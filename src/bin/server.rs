#[tokio::main]
async fn main() -> anyhow::Result<()> {
    foldfin::cli::server().await
}
