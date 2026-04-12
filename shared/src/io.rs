use anyhow::Context;
use tokio::net::TcpStream;

#[cfg(target_os = "linux")]
pub async fn copy_bidirectional(
    left: &mut TcpStream,
    right: &mut TcpStream,
) -> anyhow::Result<(u64, u64)> {
    let traffic = tokio_splice2::copy_bidirectional(left, right)
        .await
        .context("tokio-splice2 copy_bidirectional failed")?;
    let tx = traffic.tx as u64;
    let rx = traffic.rx as u64;
    traffic
        .into_result()
        .context("tokio-splice2 copy_bidirectional failed")?;
    Ok((tx, rx))
}

#[cfg(not(target_os = "linux"))]
pub async fn copy_bidirectional(
    left: &mut TcpStream,
    right: &mut TcpStream,
) -> anyhow::Result<(u64, u64)> {
    tokio::io::copy_bidirectional(left, right)
        .await
        .context("tokio copy_bidirectional failed")
}
