#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let runtime = shared::cli::parse_ingress_runtime()?;
    shared::logging::init(&runtime.log_filter)?;
    ingress::run(runtime.config).await
}
