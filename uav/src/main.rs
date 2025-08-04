mod auth;
mod comm;
mod puf;
mod register;
mod uav_cfg;
use crate::{auth::auth, comm::comm_with_uavs};
use clap::Parser;
use lazy_static::lazy_static;
use puf::Puf;
use register::register;
use rpc::{GsRpcClient, TaRpcClient};
use tarpc::{client, context, tokio_serde::formats::Json};
use tokio::sync::OnceCell;
use tracing::info;
use tracing_subscriber::EnvFilter;
use uav_cfg::UavConfig;

#[derive(Debug, Parser)]
struct CliArgs {
    #[arg(short, long)]
    pub register: bool,

    #[arg(short, long, help = "Register number", default_value = "10")]
    pub num: usize,

    #[arg(short, long, help = "Number of authentication attempts", default_value = "1")]
    pub all_auth_num: usize,

    #[arg(short, long, default_value = "127.0.0.1")]
    pub ta_ip: String,

    #[arg(long, default_value = "8090")]
    pub ta_port: u16,

    #[arg(short, long, default_value = "127.0.0.1")]
    pub gs_ip: String,

    #[arg(long, default_value = "8091")]
    pub gs_port: u16,
}

const TAG: &[u8] = b"BLS_SIG_BLS12381G1_XMD:BLAKE2b-512_SSWU_RO_NUL_";

lazy_static! {
    // static ref PUF: Puf = Puf::new(([127, 0, 0, 1], 12345));
    static ref UAV_AUTH_LIST: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(vec![]);
}
static UAV_CONFIG: OnceCell<UavConfig> = OnceCell::const_new();

static PUF: OnceCell<Puf> = OnceCell::const_new();

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // tracing logger
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or("uav=info".parse().unwrap()))
        .init();
    let args = CliArgs::parse();

    let ta_addr = format!("{}:{}", args.ta_ip, args.ta_port);
    let gs_addr = format!("{}:{}", args.gs_ip, args.gs_port);

    PUF.get_or_init(|| async {
        let puf = Puf::new(([127, 0, 0, 1], 12345)).await.expect("Failed to initialize PUF");
        puf
    })
    .await;

    if args.register || !std::fs::exists("uav.json")? {
        let mut transport = tarpc::serde_transport::tcp::connect(&ta_addr, Json::default);
        transport.config_mut().max_frame_length(usize::MAX);
        let client = TaRpcClient::new(client::Config::default(), transport.await?).spawn();
        info!("Connected to TA at {}", ta_addr);

        let results: Vec<Result<UavConfig, anyhow::Error>> = futures::future::join_all((0..args.num).map(|_| call_register(&client))).await;
        let mut good_cfgs = Vec::new();
        for res in results {
            match res {
                Ok(cfg) => good_cfgs.push(cfg),
                Err(e) => tracing::error!("register failed: {e}"),
            }
        }

        let uav_cfg = good_cfgs
            .last()
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("no successful UAV configs"))?;

        UAV_CONFIG.set(uav_cfg.clone()).ok();
        tracing::debug!("uav: {:?}", UAV_CONFIG.get());
        let f = std::fs::File::create("uav.json")?;
        serde_json::to_writer(f, &uav_cfg)?;
        return Ok(());
    }

    let f = std::fs::File::open("uav.json").expect("not found uav.json, please register.");
    let uav = serde_json::from_reader::<_, UavConfig>(f)?;
    UAV_CONFIG.set(uav).expect("UAV_CONFIG already set");

    let mut transport = tarpc::serde_transport::tcp::connect(&gs_addr, Json::default);
    transport.config_mut().max_frame_length(usize::MAX);

    let client = GsRpcClient::new(client::Config::default(), transport.await?).spawn();
    info!("Connected to GS at {}", &gs_addr);

    let t = std::time::Instant::now();
    for _ in 0..args.all_auth_num {
        // auth if self
        auth(&client).await?;
    }
    info!("Auth {} time elapsed: {:?}", args.all_auth_num, t.elapsed());

    // parallel optimization
    // let t = std::time::Instant::now();
    // futures::future::join_all((0..args.all_auth_num).map(|_| call_auth(&client))).await;
    // info!("Auth {} time elapsed: {:?}", args.all_auth_num, t.elapsed());

    let ids = client
        .get_all_uav_id(context::current(), UAV_CONFIG.get().unwrap().uid.clone())
        .await?;
    UAV_AUTH_LIST.lock().unwrap().extend_from_slice(&ids);

    // communicate with other uavs
    let t = std::time::Instant::now();
    comm_with_uavs(&client).await?;
    info!("Communicate group size: {}", ids.len());
    info!("Communicate group key time elapsed: {:?}", t.elapsed());
    Ok(())
}

async fn call_register(client: &TaRpcClient) -> anyhow::Result<UavConfig> {
    // Register multiple UAVs and use the last config
    let cfg = register(client).await?;
    Ok(cfg)
}

#[allow(dead_code)]
async fn call_auth(client: &GsRpcClient) -> anyhow::Result<()> {
    // Authenticate with the group server
    auth(client).await?;
    Ok(())
}
