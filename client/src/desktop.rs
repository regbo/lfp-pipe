//! Optional cross-platform desktop tray for the tunnel client.

use std::{
    env,
    path::{Path, PathBuf},
    process::Command,
    sync::Arc,
    thread,
    time::Duration,
};

use anyhow::{Context, anyhow};
use notify::{RecursiveMode, Watcher};
use shared::{
    cli::DesktopMode,
    config::{CentralClientBootstrap, ClientConfig},
};
use tiny_skia::{FillRule, Paint, PathBuilder, Pixmap, Transform};
use tray_icon::{
    Icon, TrayIcon, TrayIconBuilder,
    menu::{CheckMenuItem, Menu, MenuEvent, MenuId, MenuItem, PredefinedMenuItem},
};
use winit::{
    application::ApplicationHandler,
    event::WindowEvent,
    event_loop::{ActiveEventLoop, EventLoop},
    window::WindowId,
};

const OPEN_CONFIG_ID: &str = "open-config";
const OPEN_FOLDER_ID: &str = "open-config-folder";
const START_BOOT_ID: &str = "start-at-boot";
const REMOTE_MANAGED_ID: &str = "remote-managed";
const MANAGE_ID: &str = "manage";
const MANAGEMENT_URL_ID: &str = "management-url";
const EXIT_ID: &str = "exit";
const DEFAULT_TRAY_ICON_RGBA: [u8; 4] = [255, 111, 97, 255];

#[derive(Debug)]
enum UserEvent {
    Menu(MenuEvent),
    RuntimeStopped(String),
    ConfigStatus(Option<String>),
    ConfigChanged,
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
pub fn run(
    configs: Vec<ClientConfig>,
    config_path: PathBuf,
    central: Option<CentralClientBootstrap>,
) -> anyhow::Result<()> {
    let route_count = configs.len();
    let event_loop = EventLoop::<UserEvent>::with_user_event()
        .build()
        .context("initialize desktop event loop")?;
    let proxy = event_loop.create_proxy();
    MenuEvent::set_event_handler(Some(move |event| {
        let _ = proxy.send_event(UserEvent::Menu(event));
    }));

    let runtime_proxy = event_loop.create_proxy();
    let desktop_settings = crate::desktop_settings::load_or_create()?;
    let managed_central =
        central.is_some() || (configs.is_empty() && desktop_settings.remote_managed);
    thread::Builder::new()
        .name("lfp-pipe-runtime".into())
        .spawn(move || {
            let result = tokio::runtime::Runtime::new()
                .context("initialize async runtime")
                .and_then(|runtime| {
                    let bootstrap = if let Some(bootstrap) = central {
                        Some(bootstrap)
                    } else if configs.is_empty()
                        && crate::desktop_settings::load_or_create()?.remote_managed
                    {
                        let mut settings = crate::desktop_settings::load_or_create()?;
                        if crate::desktop_settings::central_bootstrap(&settings).is_none() {
                            let _ = runtime_proxy.send_event(UserEvent::ConfigStatus(Some(
                                "Enrollment required · approve in browser".into(),
                            )));
                            runtime.block_on(crate::desktop_settings::enroll(&mut settings))?;
                        }
                        crate::desktop_settings::central_bootstrap(&settings)
                    } else if configs.is_empty() {
                        return Ok(());
                    } else {
                        None
                    };
                    if let Some(bootstrap) = bootstrap {
                        let proxy = runtime_proxy.clone();
                        let reporter = Arc::new(move |message: Option<String>| {
                            let _ = proxy.send_event(UserEvent::ConfigStatus(message));
                        });
                        runtime.block_on(crate::config_source::run_central_with_reporter(
                            bootstrap,
                            Some(reporter),
                        ))
                    } else {
                        runtime.block_on(run_local_forever(configs, runtime_proxy.clone()))
                    }
                });
            let message = match result {
                Ok(()) => "No local routes configured".to_string(),
                Err(error) => {
                    tracing::error!(?error, "desktop tunnel runtime stopped");
                    "Tunnel unavailable".to_string()
                }
            };
            let _ = runtime_proxy.send_event(UserEvent::RuntimeStopped(message));
        })
        .context("start tunnel runtime thread")?;

    let watch_proxy = event_loop.create_proxy();
    let mut watcher = if managed_central {
        None
    } else {
        let watched_path = absolute_path(&config_path);
        let watched_directory = watched_path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf();
        let mut watcher =
            notify::recommended_watcher(move |event: notify::Result<notify::Event>| {
                if event.is_ok_and(|event| {
                    event
                        .paths
                        .iter()
                        .any(|path| absolute_path(path) == watched_path)
                }) {
                    let _ = watch_proxy.send_event(UserEvent::ConfigChanged);
                }
            })
            .context("initialize config watcher")?;
        watcher
            .watch(&watched_directory, RecursiveMode::NonRecursive)
            .context("watch client config")?;
        Some(watcher)
    };
    let mut app = TrayApplication::new(config_path, route_count, managed_central)?;
    event_loop
        .run_app(&mut app)
        .context("run desktop event loop")?;
    drop(watcher.take());
    Ok(())
}

async fn run_local_forever(
    configs: Vec<ClientConfig>,
    proxy: winit::event_loop::EventLoopProxy<UserEvent>,
) -> anyhow::Result<()> {
    if configs.is_empty() {
        return Ok(());
    }
    let mut retry_delay = Duration::from_secs(1);
    loop {
        match crate::run_all(configs.clone()).await {
            Ok(()) => tracing::warn!(?retry_delay, "local tunnel runtime stopped; reconnecting"),
            Err(error) => tracing::warn!(
                ?error,
                ?retry_delay,
                "local tunnel connection stopped; reconnecting"
            ),
        }
        let _ = proxy.send_event(UserEvent::ConfigStatus(Some("Reconnecting…".into())));
        tokio::time::sleep(retry_delay).await;
        retry_delay = retry_delay.saturating_mul(2).min(Duration::from_secs(30));
    }
}

struct TrayApplication {
    config_path: PathBuf,
    status: MenuItem,
    tray: Option<TrayIcon>,
    menu: Menu,
    start_at_boot: CheckMenuItem,
    remote_managed: CheckMenuItem,
    managed_central: bool,
    route_count: usize,
    last_change: Option<std::time::Instant>,
}

impl TrayApplication {
    fn new(
        config_path: PathBuf,
        route_count: usize,
        managed_central: bool,
    ) -> anyhow::Result<Self> {
        let initial_status = if managed_central {
            "Running · centrally managed".to_string()
        } else {
            format!("Running · {route_count} route(s)")
        };
        let status = MenuItem::with_id("status", initial_status, false, None);
        let open_config = MenuItem::with_id(OPEN_CONFIG_ID, "Open local config", true, None);
        let open_folder = MenuItem::with_id(OPEN_FOLDER_ID, "Open local config folder", true, None);
        let auto_launch = crate::desktop_settings::auto_launch()?;
        let start_at_boot = CheckMenuItem::with_id(
            START_BOOT_ID,
            "Start at boot",
            true,
            auto_launch.is_enabled().unwrap_or(false),
            None,
        );
        let remote_managed = CheckMenuItem::with_id(
            REMOTE_MANAGED_ID,
            "Remote managed",
            true,
            managed_central,
            None,
        );
        let manage = MenuItem::with_id(MANAGE_ID, "Manage", true, None);
        let management_url =
            MenuItem::with_id(MANAGEMENT_URL_ID, "Change management server", true, None);
        let exit = MenuItem::with_id(EXIT_ID, "Exit lfp-pipe", true, None);
        let separator_before_actions = PredefinedMenuItem::separator();
        let separator_before_exit = PredefinedMenuItem::separator();
        let mut items: Vec<&dyn tray_icon::menu::IsMenuItem> = vec![
            &status,
            &separator_before_actions,
            &start_at_boot,
            &remote_managed,
            &manage,
            &management_url,
        ];
        if !managed_central {
            items.push(&open_config);
            items.push(&open_folder);
        }
        items.push(&separator_before_exit);
        items.push(&exit);
        let menu = Menu::with_items(&items).context("create tray menu")?;
        Ok(Self {
            config_path,
            status,
            tray: None,
            menu,
            start_at_boot,
            remote_managed,
            managed_central,
            route_count,
            last_change: None,
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
            START_BOOT_ID => {
                let result = crate::desktop_settings::auto_launch().and_then(|auto| {
                    if self.start_at_boot.is_checked() {
                        auto.enable()?;
                    } else {
                        auto.disable()?;
                    }
                    Ok(())
                });
                match result {
                    Ok(()) => {}
                    Err(error) => {
                        self.start_at_boot
                            .set_checked(!self.start_at_boot.is_checked());
                        self.set_error(format!("Start at boot failed: {error:#}"));
                    }
                }
            }
            REMOTE_MANAGED_ID => {
                match crate::desktop_settings::load_or_create()
                    .and_then(|mut settings| {
                        settings.remote_managed = self.remote_managed.is_checked();
                        crate::desktop_settings::save(&settings)
                    })
                    .and_then(|()| restart_without_config_override())
                {
                    Ok(()) => event_loop.exit(),
                    Err(error) => {
                        self.remote_managed
                            .set_checked(!self.remote_managed.is_checked());
                        self.set_error(format!("Remote management failed: {error:#}"));
                    }
                }
            }
            MANAGE_ID => match crate::desktop_settings::load_or_create() {
                Ok(settings) => {
                    if let Err(error) = open::that_detached(settings.control_plane_url) {
                        self.set_error(format!("Open management failed: {error:#}"));
                    }
                }
                Err(error) => self.set_error(format!("Open management failed: {error:#}")),
            },
            MANAGEMENT_URL_ID => match crate::desktop_settings::load_or_create() {
                Ok(mut settings) => {
                    if let Some(value) = tinyfiledialogs::input_box(
                        "LFP Connect Pipe",
                        "Management server URL",
                        &settings.control_plane_url,
                    ) {
                        if url::Url::parse(&value).is_err() {
                            self.set_error("Management server must be a valid URL".into());
                        } else {
                            settings.control_plane_url = value;
                            if let Err(error) =
                                crate::desktop_settings::save(&settings).and_then(|()| {
                                    if self.remote_managed.is_checked() {
                                        restart_without_config_override()
                                    } else {
                                        restart_current_process()
                                    }
                                })
                            {
                                self.set_error(format!(
                                    "Management server update failed: {error:#}"
                                ));
                            } else {
                                event_loop.exit();
                            }
                        }
                    }
                }
                Err(error) => self.set_error(format!("Management server update failed: {error:#}")),
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
        tracing::warn!(detail = %message, "desktop status warning");
        let message = compact_status(&message);
        self.status.set_text(&message);
        if let Some(tray) = &self.tray {
            let _ = tray.set_tooltip(Some(&message));
        }
    }

    fn clear_config_warning(&mut self) {
        let message = if self.managed_central {
            "Running · centrally managed".to_string()
        } else {
            format!("Running · {} route(s)", self.route_count)
        };
        self.status.set_text(&message);
        if let Some(tray) = &self.tray {
            let _ = tray.set_tooltip(Some("lfp-pipe client · running"));
        }
    }

    fn config_changed(&mut self, event_loop: &ActiveEventLoop) {
        if self.managed_central {
            return;
        }
        let now = std::time::Instant::now();
        if self
            .last_change
            .is_some_and(|last| now.duration_since(last) < Duration::from_millis(300))
        {
            return;
        }
        self.last_change = Some(now);
        match shared::config::load_client_configs(&self.config_path) {
            Ok(_) => match restart_current_process() {
                Ok(()) => event_loop.exit(),
                Err(error) => self.set_error(format!("Config warning: {error:#}")),
            },
            Err(error) => self.set_error(format!("Config warning: {error:#}")),
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
            UserEvent::ConfigStatus(Some(message)) => self.set_error(message),
            UserEvent::ConfigStatus(None) => self.clear_config_warning(),
            UserEvent::ConfigChanged => self.config_changed(event_loop),
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

fn absolute_path(path: &Path) -> PathBuf {
    path.canonicalize().unwrap_or_else(|_| {
        if path.is_absolute() {
            path.to_path_buf()
        } else {
            env::current_dir()
                .unwrap_or_else(|_| PathBuf::from("."))
                .join(path)
        }
    })
}

fn restart_current_process() -> anyhow::Result<()> {
    let executable = env::current_exe().context("locate current executable")?;
    Command::new(executable)
        .args(env::args_os().skip(1))
        .spawn()
        .context("start replacement process")?;
    Ok(())
}

fn restart_without_config_override() -> anyhow::Result<()> {
    let executable = env::current_exe().context("locate current executable")?;
    let mut args = env::args_os().skip(1).peekable();
    let mut filtered = Vec::new();
    while let Some(arg) = args.next() {
        if arg == "--config" {
            let _ = args.next();
            continue;
        }
        if !arg.to_string_lossy().starts_with("--config=") {
            filtered.push(arg);
        }
    }
    Command::new(executable)
        .args(filtered)
        .env_remove("LFP_PIPE_CONFIG")
        .spawn()
        .context("start remotely managed replacement")?;
    Ok(())
}

fn compact_status(message: &str) -> String {
    const MAX_CHARS: usize = 64;
    let first_line = message
        .lines()
        .next()
        .unwrap_or("Status unavailable")
        .trim();
    if first_line.chars().count() <= MAX_CHARS {
        return first_line.to_string();
    }
    format!(
        "{}…",
        first_line.chars().take(MAX_CHARS - 1).collect::<String>()
    )
}

fn make_icon() -> anyhow::Result<Icon> {
    const SIZE: u32 = 32;
    let mut pixmap = Pixmap::new(SIZE, SIZE).ok_or_else(|| anyhow!("create tray icon pixmap"))?;
    let mut paint = Paint::default();
    paint.set_color_rgba8(
        DEFAULT_TRAY_ICON_RGBA[0],
        DEFAULT_TRAY_ICON_RGBA[1],
        DEFAULT_TRAY_ICON_RGBA[2],
        DEFAULT_TRAY_ICON_RGBA[3],
    );
    paint.anti_alias = true;

    // The L-shaped route follows the LFP monogram's posture while the collars
    // make the tunnel/pipe purpose readable at 16px and 32px tray sizes.
    let path = route_elbow_path();
    pixmap.fill_path(
        &path,
        &paint,
        FillRule::Winding,
        Transform::from_scale(0.25, 0.25),
        None,
    );

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

fn route_elbow_path() -> tiny_skia::Path {
    let mut path = PathBuilder::new();
    path.move_to(18.0, 8.0);
    path.line_to(50.0, 8.0);
    path.line_to(50.0, 20.0);
    path.line_to(45.0, 20.0);
    path.line_to(45.0, 75.0);
    path.cubic_to(45.0, 81.0, 48.0, 84.0, 54.0, 84.0);
    path.line_to(108.0, 84.0);
    path.line_to(108.0, 79.0);
    path.line_to(120.0, 79.0);
    path.line_to(120.0, 111.0);
    path.line_to(108.0, 111.0);
    path.line_to(108.0, 106.0);
    path.line_to(52.0, 106.0);
    path.cubic_to(33.0, 106.0, 23.0, 96.0, 23.0, 77.0);
    path.line_to(23.0, 20.0);
    path.line_to(18.0, 20.0);
    path.close();

    // Coupling collars at each end of the route.
    path.move_to(13.0, 20.0);
    path.line_to(55.0, 20.0);
    path.line_to(55.0, 31.0);
    path.line_to(13.0, 31.0);
    path.close();
    path.move_to(97.0, 74.0);
    path.line_to(108.0, 74.0);
    path.line_to(108.0, 116.0);
    path.line_to(97.0, 116.0);
    path.close();
    path.finish().expect("valid route elbow path")
}

#[cfg(test)]
mod tests {
    use super::{compact_status, route_elbow_path};

    #[test]
    fn tray_icon_geometry_fits_source_view_box() {
        let bounds = route_elbow_path().bounds();
        assert_eq!((bounds.left(), bounds.top()), (13.0, 8.0));
        assert_eq!((bounds.right(), bounds.bottom()), (120.0, 116.0));
    }

    #[test]
    fn tray_status_is_single_line_and_bounded() {
        let status = compact_status(&format!("{}\nmore details", "x".repeat(100)));
        assert_eq!(status.chars().count(), 64);
        assert!(!status.contains('\n'));
    }
}
