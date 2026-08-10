#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let runtime = shared::cli::parse_client_runtime()?;
    shared::logging::init(&runtime.log_filter)?;
    client::run(runtime.config).await
}
