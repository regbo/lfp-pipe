//! Optional cross-platform desktop tray for the tunnel client.

use std::{
    env,
    path::{Path, PathBuf},
    process::Command,
    thread,
};

use anyhow::{Context, anyhow};
use shared::{cli::DesktopMode, config::ClientConfig};
use tiny_skia::{FillRule, Paint, PathBuilder, Pixmap, Transform};
use tray_icon::{
    Icon, TrayIcon, TrayIconBuilder,
    menu::{Menu, MenuEvent, MenuId, MenuItem, PredefinedMenuItem},
};
use winit::{
    application::ApplicationHandler,
    event::WindowEvent,
    event_loop::{ActiveEventLoop, EventLoop},
    window::WindowId,
};

const OPEN_CONFIG_ID: &str = "open-config";
const OPEN_FOLDER_ID: &str = "open-config-folder";
const RELOAD_ID: &str = "reload-config";
const EXIT_ID: &str = "exit";

#[derive(Debug)]
enum UserEvent {
    Menu(MenuEvent),
    RuntimeStopped(String),
}

/// Return whether the selected desktop mode should start a tray event loop.
///
/// Automatic mode is conservative on Linux, where a display socket is
/// required, and avoids GUI initialization in Windows service sessions and
/// macOS SSH-only sessions. `always` remains available for unusual desktops.
pub fn should_run(mode: DesktopMode) -> bool {
    match mode {
        DesktopMode::Always => true,
        DesktopMode::Never => false,
        DesktopMode::Auto => desktop_session_available(),
    }
}

fn desktop_session_available() -> bool {
    #[cfg(target_os = "linux")]
    {
        env::var_os("DISPLAY").is_some() || env::var_os("WAYLAND_DISPLAY").is_some()
    }
    #[cfg(target_os = "windows")]
    {
        env::var("SESSIONNAME")
            .map(|name| !name.eq_ignore_ascii_case("services"))
            .unwrap_or(true)
    }
    #[cfg(target_os = "macos")]
    {
        env::var_os("SSH_CONNECTION").is_none() || env::var_os("TERM_PROGRAM").is_some()
    }
}

/// Run the tray event loop on the main thread and the tunnel on a worker.
///
/// # Errors
///
/// Returns an error when the desktop event loop or tray icon cannot be
/// initialized. Runtime failures remain visible in the tray for inspection.
pub fn run(configs: Vec<ClientConfig>, config_path: PathBuf) -> anyhow::Result<()> {
    let route_count = configs.len();
    let event_loop = EventLoop::<UserEvent>::with_user_event()
        .build()
        .context("initialize desktop event loop")?;
    let proxy = event_loop.create_proxy();
    MenuEvent::set_event_handler(Some(move |event| {
        let _ = proxy.send_event(UserEvent::Menu(event));
    }));

    let runtime_proxy = event_loop.create_proxy();
    thread::Builder::new()
        .name("lfp-pipe-runtime".into())
        .spawn(move || {
            let result = tokio::runtime::Runtime::new()
                .context("initialize async runtime")
                .and_then(|runtime| runtime.block_on(crate::run_all(configs)));
            let message = match result {
                Ok(()) => "Tunnel runtime stopped".to_string(),
                Err(error) => format!("Tunnel stopped: {error:#}"),
            };
            let _ = runtime_proxy.send_event(UserEvent::RuntimeStopped(message));
        })
        .context("start tunnel runtime thread")?;

    let mut app = TrayApplication::new(config_path, route_count)?;
    event_loop
        .run_app(&mut app)
        .context("run desktop event loop")
}

struct TrayApplication {
    config_path: PathBuf,
    status: MenuItem,
    tray: Option<TrayIcon>,
    menu: Menu,
}

impl TrayApplication {
    fn new(config_path: PathBuf, route_count: usize) -> anyhow::Result<Self> {
        let status = MenuItem::with_id(
            "status",
            format!("Running · {route_count} route(s)"),
            false,
            None,
        );
        let open_config = MenuItem::with_id(OPEN_CONFIG_ID, "Open Config", true, None);
        let open_folder = MenuItem::with_id(OPEN_FOLDER_ID, "Open Config Folder", true, None);
        let reload = MenuItem::with_id(RELOAD_ID, "Reload Config", true, None);
        let exit = MenuItem::with_id(EXIT_ID, "Exit lfp-pipe", true, None);
        let separator_before_actions = PredefinedMenuItem::separator();
        let separator_before_exit = PredefinedMenuItem::separator();
        let menu = Menu::with_items(&[
            &status,
            &separator_before_actions,
            &open_config,
            &open_folder,
            &reload,
            &separator_before_exit,
            &exit,
        ])
        .context("create tray menu")?;
        Ok(Self {
            config_path,
            status,
            tray: None,
            menu,
        })
    }

    fn handle_menu(&mut self, event_loop: &ActiveEventLoop, id: &MenuId) {
        match id.as_ref() {
            OPEN_CONFIG_ID => self.open_path(self.config_path.clone()),
            OPEN_FOLDER_ID => {
                let folder = self
                    .config_path
                    .parent()
                    .unwrap_or_else(|| Path::new("."))
                    .to_path_buf();
                self.open_path(folder);
            }
            RELOAD_ID => match restart_current_process(&self.config_path) {
                Ok(()) => event_loop.exit(),
                Err(error) => self.set_error(format!("Reload failed: {error:#}")),
            },
            EXIT_ID => event_loop.exit(),
            _ => {}
        }
    }

    fn open_path(&mut self, path: PathBuf) {
        if let Err(error) = open::that_detached(&path) {
            self.set_error(format!("Open failed: {error}"));
        }
    }

    fn set_error(&mut self, message: String) {
        self.status.set_text(&message);
        if let Some(tray) = &self.tray {
            let _ = tray.set_tooltip(Some(&message));
        }
    }
}

impl ApplicationHandler<UserEvent> for TrayApplication {
    fn resumed(&mut self, _event_loop: &ActiveEventLoop) {
        if self.tray.is_some() {
            return;
        }
        match make_icon().and_then(|icon| {
            TrayIconBuilder::new()
                .with_menu(Box::new(self.menu.clone()))
                .with_icon(icon)
                .with_tooltip("lfp-pipe client · running")
                .build()
                .map_err(Into::into)
        }) {
            Ok(tray) => self.tray = Some(tray),
            Err(error) => self.set_error(format!("Tray failed: {error:#}")),
        }
    }

    fn user_event(&mut self, event_loop: &ActiveEventLoop, event: UserEvent) {
        match event {
            UserEvent::Menu(event) => self.handle_menu(event_loop, &event.id),
            UserEvent::RuntimeStopped(message) => self.set_error(message),
        }
    }

    fn window_event(
        &mut self,
        _event_loop: &ActiveEventLoop,
        _window_id: WindowId,
        _event: WindowEvent,
    ) {
    }
}

fn restart_current_process(config_path: &Path) -> anyhow::Result<()> {
    // Validate the source file before replacing a healthy process. CLI and
    // environment overrides are applied again by the replacement process.
    shared::config::load_client_configs(config_path).context("validate config before reload")?;
    let executable = env::current_exe().context("locate current executable")?;
    Command::new(executable)
        .args(env::args_os().skip(1))
        .spawn()
        .context("start replacement process")?;
    Ok(())
}

fn make_icon() -> anyhow::Result<Icon> {
    const SIZE: u32 = 32;
    let mut pixmap = Pixmap::new(SIZE, SIZE).ok_or_else(|| anyhow!("create tray icon pixmap"))?;
    let mut paint = Paint::default();
    paint.set_color_rgba8(255, 111, 97, 255);
    paint.anti_alias = true;

    // Compact version of the coral lowercase LFP monogram used by the web UI.
    // The geometry is drawn at 140px source scale and fitted into a square so
    // the same recognizable mark remains crisp in 16px and 32px system trays.
    let transform = Transform::from_scale(0.16, 0.16).post_translate(1.0, 4.5);
    for path in [brand_l_path(), brand_f_path(), brand_p_path()] {
        pixmap.fill_path(&path, &paint, FillRule::Winding, transform, None);
    }

    let mut rgba = pixmap.take();
    // tiny-skia stores premultiplied RGBA while tray-icon accepts straight
    // RGBA. Undo premultiplication so anti-aliased coral edges retain hue.
    for pixel in rgba.chunks_exact_mut(4) {
        let alpha = u16::from(pixel[3]);
        if alpha > 0 && alpha < 255 {
            for channel in &mut pixel[..3] {
                *channel = ((u16::from(*channel) * 255 / alpha).min(255)) as u8;
            }
        }
    }
    Icon::from_rgba(rgba, SIZE, SIZE).map_err(|error| anyhow!(error))
}

fn brand_l_path() -> tiny_skia::Path {
    let mut path = PathBuilder::new();
    path.move_to(12.0, 8.0);
    path.line_to(38.0, 8.0);
    path.line_to(38.0, 99.0);
    path.cubic_to(38.0, 108.0, 43.0, 113.0, 53.0, 113.0);
    path.line_to(58.0, 113.0);
    path.line_to(58.0, 136.0);
    path.line_to(46.0, 136.0);
    path.cubic_to(24.0, 136.0, 12.0, 123.0, 12.0, 101.0);
    path.close();
    path.finish().expect("valid brand L path")
}

fn brand_f_path() -> tiny_skia::Path {
    let mut path = PathBuilder::new();
    path.move_to(61.0, 136.0);
    path.line_to(61.0, 61.0);
    path.line_to(49.0, 61.0);
    path.line_to(49.0, 39.0);
    path.line_to(61.0, 39.0);
    path.line_to(61.0, 34.0);
    path.cubic_to(61.0, 13.0, 73.0, 2.0, 95.0, 2.0);
    path.line_to(115.0, 2.0);
    path.line_to(115.0, 25.0);
    path.line_to(98.0, 25.0);
    path.cubic_to(90.0, 25.0, 87.0, 29.0, 87.0, 36.0);
    path.line_to(87.0, 39.0);
    path.line_to(115.0, 39.0);
    path.line_to(115.0, 61.0);
    path.line_to(87.0, 61.0);
    path.line_to(87.0, 136.0);
    path.close();
    path.finish().expect("valid brand F path")
}

fn brand_p_path() -> tiny_skia::Path {
    let mut path = PathBuilder::new();
    path.move_to(94.0, 39.0);
    path.line_to(119.0, 39.0);
    path.line_to(119.0, 48.0);
    path.cubic_to(127.0, 40.0, 137.0, 36.0, 148.0, 36.0);
    path.cubic_to(175.0, 36.0, 190.0, 57.0, 190.0, 86.0);
    path.cubic_to(190.0, 115.0, 175.0, 136.0, 148.0, 136.0);
    path.cubic_to(137.0, 136.0, 128.0, 132.0, 120.0, 125.0);
    path.line_to(120.0, 140.0);
    path.line_to(94.0, 140.0);
    path.close();
    path.move_to(142.0, 113.0);
    path.cubic_to(156.0, 113.0, 164.0, 102.0, 164.0, 86.0);
    path.cubic_to(164.0, 70.0, 156.0, 59.0, 142.0, 59.0);
    path.cubic_to(128.0, 59.0, 119.0, 70.0, 119.0, 86.0);
    path.cubic_to(119.0, 102.0, 128.0, 113.0, 142.0, 113.0);
    path.close();
    path.finish().expect("valid brand P path")
}
