fn main() -> anyhow::Result<()> {
    let runtime = shared::cli::parse_client_runtime()?;
    shared::logging::init(&runtime.log_filter)?;

    #[cfg(any(target_os = "windows", target_os = "macos", target_os = "linux"))]
    if client::desktop::should_run(runtime.desktop_mode) {
        return client::desktop::run(runtime.config, runtime.config_path, runtime.central);
    }

    anyhow::ensure!(
        runtime.central.is_some() || !runtime.config.is_empty(),
        "headless mode requires --config/LFP_PIPE_CONFIG"
    );

    let async_runtime = tokio::runtime::Runtime::new()?;
    if let Some(central) = runtime.central {
        async_runtime.block_on(client::config_source::run_central(central))
    } else {
        async_runtime.block_on(client::run_all(runtime.config))
    }
}
