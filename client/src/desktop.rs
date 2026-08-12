//! Optional cross-platform desktop tray for the tunnel client.

use std::{
    env,
    path::{Path, PathBuf},
    process::Command,
    thread,
};

use anyhow::{Context, anyhow};
use shared::{cli::DesktopMode, config::ClientConfig};
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
    let mut rgba = vec![0_u8; (SIZE * SIZE * 4) as usize];
    for y in 0..SIZE {
        for x in 0..SIZE {
            let dx = x as f32 - 15.5;
            let dy = y as f32 - 15.5;
            let distance = (dx * dx + dy * dy).sqrt();
            let ring = (8.0..=13.5).contains(&distance);
            let stem = (14..=18).contains(&x) && (5..=17).contains(&y);
            if ring || stem {
                let offset = ((y * SIZE + x) * 4) as usize;
                rgba[offset..offset + 4].copy_from_slice(&[38, 166, 154, 255]);
            }
        }
    }
    Icon::from_rgba(rgba, SIZE, SIZE).map_err(|error| anyhow!(error))
}
