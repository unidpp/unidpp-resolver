//! Entrypoint: environment-driven configuration, then serve forever.

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let config = unidpp_resolver::Config::from_env();
    unidpp_resolver::run(config).await
}
