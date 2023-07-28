mod codec;
mod puf;
mod uav_auth_comm;
mod uav_reg;
use crate::uav_reg::register;
use clap::Parser;
use lazy_static::lazy_static;
use puf::Puf;
use tokio::sync::OnceCell;
use tracing_subscriber::EnvFilter;

use self::uav_auth_comm::auth_comm;

#[derive(Debug, Parser)]
struct CliArgs {
    #[arg(short, long)]
    pub register: bool,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Uav {
    pub uid: Vec<u8>,
    pub ruid: Vec<u8>,
}

lazy_static! {
    static ref PUF: Puf = Puf::new(([127, 0, 0, 1], 12345));
}
static UAV: OnceCell<Uav> = OnceCell::const_new();

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // tracing logger
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or("debug".parse().unwrap()))
        .init();
    let args = CliArgs::parse();
    let ta_addr = "127.0.0.1:8090";
    let gs_addr = "127.0.0.1:8091";

    if args.register {
        let _uav = register(ta_addr).await?;
        tracing::debug!("uav: {:?}", UAV.get());
        let f = std::fs::File::create("uav.json")?;
        serde_json::to_writer(f, &_uav)?;
        return Ok(());
    }
    let f = std::fs::File::open("uav.json").expect("not found uav.json, please register.");
    let uav = serde_json::from_reader::<_, Uav>(f)?;

    // insert uav ruid and uid to local database
    UAV.get_or_init(|| futures::future::ready(uav)).await;
    auth_comm(gs_addr).await?;
    Ok(())
}
