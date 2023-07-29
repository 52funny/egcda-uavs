mod codec;
mod puf;
mod uav_auth_comm;
mod uav_reg;
use crate::uav_reg::register;
use clap::Parser;
use dashmap::DashMap;
use futures::StreamExt;
use lazy_static::lazy_static;
use puf::Puf;
use rug::Integer;
use std::io::stdin;
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

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct UavRuid {
    pub ruid: String,
    pub ip_addr: String,
}

lazy_static! {
    static ref PUF: Puf = Puf::new(([127, 0, 0, 1], 12345));
    static ref UAV_RUID_LIST: DashMap<String, UavRuid> = DashMap::new();
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

    // A list of drone pseudonyms used to send GS that need to communicate
    let (anonym_tx, anonym_rx) = futures::channel::mpsc::unbounded::<Vec<String>>();

    // used to return the parameters given by GS
    let (param_tx, param_rx) = futures::channel::mpsc::unbounded::<(Vec<u8>, Vec<String>)>();

    // insert uav ruid and uid to local database
    UAV.get_or_init(|| futures::future::ready(uav)).await;
    tokio::spawn(async {
        let res = auth_comm(gs_addr, anonym_rx, param_tx).await;
        match res {
            Ok(_) => {}
            Err(e) => tracing::error!("auth failed: {:?}", e),
        }
    });

    let mut param_rx = param_rx;
    loop {
        println!("please input uav index:");
        let mut input = String::new();
        stdin().read_line(&mut input)?;
        if input == "exit" {
            break;
        }
        let uav_number = input.trim().parse::<usize>()?;

        let mut uav_ruid = vec![hex::encode(&UAV.get().unwrap().ruid)];
        for (idx, item) in UAV_RUID_LIST.iter().enumerate() {
            if idx == uav_number {
                uav_ruid.push(item.key().clone());
            }
        }
        tracing::info!("uav_ruid: {:?}", uav_ruid);
        anonym_tx.unbounded_send(uav_ruid).unwrap();

        let (ssk, c_list) = param_rx.next().await.unwrap();
        tracing::info!("ssk    : {}", hex::encode(&ssk));
        tracing::info!("c_list : {:?}", c_list);

        let c = c_list.first().unwrap();
        let r = PUF.calculate(c).await?;
        let n = Integer::from_digits(&hex::decode(r)?, rug::integer::Order::MsfBe).next_prime();
        let ssk = Integer::from_digits(&ssk, rug::integer::Order::MsfBe);
        let kd = ssk % &n;
        tracing::info!("kd     : {}", kd.to_string_radix(16));
    }

    Ok(())
}
