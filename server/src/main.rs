#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let runtime = shared::cli::parse_server_runtime()?;
    shared::logging::init(&runtime.log_filter)?;
    server::run(runtime.config).await
}
