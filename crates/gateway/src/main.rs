#![forbid(unsafe_code)]

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use clap::Parser;
use tokio::net::TcpListener;
use weft_home::Home;
use weft_resolve::Resolver;

#[derive(Parser, Debug)]
#[command(name = "weft-gateway", version, about = "Serve signed records over plain HTTP")]
struct Cli {
    #[arg(long, env = "WEFT_HOME")]
    home: Option<PathBuf>,
    #[arg(long, env = "WEFT_GATEWAY_BIND", default_value = "127.0.0.1:8080")]
    bind: SocketAddr,
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    let home = Home::new(cli.home.unwrap_or_else(Home::default_dir));
    let resolver = Arc::new(Resolver::new(home));
    let listener = match TcpListener::bind(cli.bind).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("error: bind {}: {e}", cli.bind);
            return ExitCode::FAILURE;
        }
    };
    println!("listening on http://{}", cli.bind);
    match weft_gateway::serve(listener, resolver).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}
