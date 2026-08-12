fn main() -> anyhow::Result<()> {
    let runtime = shared::cli::parse_client_runtime()?;
    shared::logging::init(&runtime.log_filter)?;

    #[cfg(any(target_os = "windows", target_os = "macos", target_os = "linux"))]
    if client::desktop::should_run(runtime.desktop_mode) {
        return client::desktop::run(runtime.config, runtime.config_path);
    }

    tokio::runtime::Runtime::new()?.block_on(client::run_all(runtime.config))
}
