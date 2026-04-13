#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let mode = args.get(1).map(|s| s.as_str()).unwrap_or("live");

    match mode {
        "live" => run_live().await,
        other => {
            eprintln!("unknown mode: {}", other);
            eprintln!("usage: prefire live");
            eprintln!("       prefire replay <sig>  (use the replay binary)");
            std::process::exit(1);
        }
    }
}

async fn run_live() -> Result<(), Box<dyn std::error::Error>> {
    println!("prefire — solana governance attack detection (live mode)");

    let ws_url = std::env::var("SOLANA_WS_URL")?;
    let mut receiver = prefire_monitor::rpc::subscribe_squads_events(&ws_url).await?;

    while let Some(event) = receiver.recv().await {
        println!("[slot {}] {:?} — sig: {}", event.slot, event.event, event.signature);
    }
    Ok(())
}
