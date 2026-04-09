#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("prefire — solana governance attack detection");

    let ws_url = std::env::var("SOLANA_WS_URL")?;
    let mut receiver = prefire_monitor::rpc::subscribe_squads_events(&ws_url).await?;

    while let Some(event) = receiver.recv().await {
        println!("{:?}", event);
    }
    Ok(())
}
