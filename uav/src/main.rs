mod codec;
mod puf;
mod uav_auth_comm;
mod uav_reg;
use crate::uav_reg::register;
use clap::Parser;
use dashmap::DashMap;
use futures::{SinkExt, StreamExt};
use hex_literal::hex;
use lazy_static::lazy_static;
use pb::communicate_uav_uav::{uav_uav_communicate_request, UavUavCommunicateRequest};
use pbc_rust::Pairing;
use puf::Puf;
use rug::Integer;
use serde::de::{self, Unexpected, Visitor};
use serde::ser::SerializeStruct;
use std::io::stdin;
use std::net::SocketAddr;
use tokio::net::TcpStream;
use tokio::sync::OnceCell;
use tokio_util::codec::Framed;
use tracing_subscriber::EnvFilter;

use self::codec::uav_uav_communicate_codec::{
    UavUavCommunicateClientCodec, UavUavCommunicateServerCodec,
};
use self::uav_auth_comm::auth_comm;

#[derive(Debug, Parser)]
struct CliArgs {
    #[arg(short, long)]
    pub register: bool,

    #[arg(short, long)]
    /// TA server address
    pub ta: String,

    #[arg(short, long)]
    /// GS server address
    pub gs: String,
}

#[derive(Debug, Clone)]
pub struct Uav {
    pub uid: Vec<u8>,
    pub ruid: Vec<u8>,
}

impl serde::Serialize for Uav {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut uav = serializer.serialize_struct("Uav", 2)?;
        uav.serialize_field("uid", &hex::encode(&self.uid))?;
        uav.serialize_field("ruid", &hex::encode(&self.ruid))?;
        uav.end()
    }
}

impl<'de> serde::Deserialize<'de> for Uav {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] = &["uid", "ruid"];
        #[allow(non_camel_case_types)]
        enum Field {
            uid,
            ruid,
        }
        impl<'de> serde::Deserialize<'de> for Field {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                struct FieldVisitor;
                impl<'de> Visitor<'de> for FieldVisitor {
                    type Value = Field;
                    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                        formatter.write_str("`uid` or `ruid`")
                    }
                    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
                    where
                        E: de::Error,
                    {
                        match v {
                            "uid" => Ok(Field::uid),
                            "ruid" => Ok(Field::ruid),
                            _ => Err(de::Error::unknown_field(v, FIELDS)),
                        }
                    }
                }
                deserializer.deserialize_identifier(FieldVisitor)
            }
        }

        struct UavVisitor;
        impl<'de> Visitor<'de> for UavVisitor {
            type Value = Uav;
            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("struct Uav")
            }
            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let uid: String = seq
                    .next_element()?
                    .ok_or_else(|| de::Error::invalid_length(0, &self))?;

                let ruid: String = seq
                    .next_element()?
                    .ok_or_else(|| de::Error::invalid_length(1, &self))?;
                let uid = hex::decode(uid).map_err(|_| {
                    de::Error::invalid_value(Unexpected::Str("invalid uid str"), &self)
                })?;
                let ruid = hex::decode(ruid).map_err(|_| {
                    de::Error::invalid_value(Unexpected::Str("invalid ruid str"), &self)
                })?;
                Ok(Uav { uid, ruid })
            }
            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: de::MapAccess<'de>,
            {
                let mut uid = None;
                let mut ruid = None;
                while let Some(key) = map.next_key()? {
                    match key {
                        Field::uid => {
                            if uid.is_some() {
                                return Err(de::Error::duplicate_field("uid"));
                            }
                            let v: String = map.next_value()?;
                            uid = Some(hex::decode(v).map_err(|_| {
                                de::Error::invalid_value(Unexpected::Str("invalid uid str"), &self)
                            })?);
                        }
                        Field::ruid => {
                            if ruid.is_some() {
                                return Err(de::Error::duplicate_field("ruid"));
                            }
                            let v: String = map.next_value()?;
                            ruid = Some(hex::decode(v).map_err(|_| {
                                de::Error::invalid_value(Unexpected::Str("invalid ruid str"), &self)
                            })?);
                        }
                    }
                }
                let uid = uid.ok_or_else(|| de::Error::missing_field("uid"))?;
                let ruid = ruid.ok_or_else(|| de::Error::missing_field("uid"))?;
                Ok(Uav { uid, ruid })
            }
        }
        deserializer.deserialize_struct("Uav", &["uid", "ruid"], UavVisitor)
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct UavRuid {
    pub ruid: String,
    pub ip_addr: String,
}

lazy_static! {
    static ref PUF: Puf = Puf::new(([127, 0, 0, 1], 12345));
    static ref UAV_RUID_LIST: DashMap<String, UavRuid> = DashMap::new();
    static ref P: Pairing = Pairing::new(TYPE_A);
}

static UAV: OnceCell<Uav> = OnceCell::const_new();

const TYPE_A: &str = "
type a
q 6269501190990595151250674934240647994559640542560528061719627332415708950243708672053776563123743544851675214786949400131452747984830937087887946632632599
h 8579533584978239287913221933865556817094441585921961055557100258639027708646644638908786275391553267066600
r 730750818665452757176057050065048642452048576511
exp2 159
exp1 110
sign1 1
sign0 -1
";

const GENERATION: [u8; 128] = hex!("221e95f6082142d33b1f78bc467bc3d16b8bfff7f1847a481b36b3581aa546798773b20edf1fac46d4f200c5c6296151bd3e835e1325b5bfb474d1c9257314113b1e1201243c6c8257f34a6a24c351ad4968ec9c9c1b3ec1bf23108f643c1a42ebb7137a5a255c845149f76535585a39ef5f96830a10556478ee066a4db57676");

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // tracing logger
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or("debug".parse().unwrap()))
        .init();
    let args = CliArgs::parse();
    let ta_addr = args.ta.clone();
    let gs_addr = args.gs.clone();

    if args.register {
        let _uav = register(&ta_addr).await?;
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
    tokio::spawn(async move {
        let res = auth_comm(&gs_addr, anonym_rx, param_tx).await;
        match res {
            Ok(_) => {}
            Err(e) => tracing::error!("auth failed: {:?}", e),
        }
    });

    tokio::spawn(receive_uav_message_tcp());

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
        anonym_tx.unbounded_send(uav_ruid.clone()).unwrap();

        let (ssk, c_list) = param_rx.next().await.unwrap();
        tracing::info!("ssk    : {}", hex::encode(&ssk));
        tracing::info!("c_list : {:?}", c_list);

        let c = c_list.first().unwrap();
        let r = PUF.calculate(c).await?;
        let n = Integer::from_digits(&hex::decode(r)?, rug::integer::Order::MsfBe).next_prime();
        let ssk = Integer::from_digits(&ssk, rug::integer::Order::MsfBe);
        let kd = ssk.clone() % &n;
        tracing::info!("kd     : {}", kd.to_string_radix(16));
        let kd_bytes = kd.to_digits::<u8>(rug::integer::Order::MsfBe);

        let ssk_bytes = ssk.to_digits::<u8>(rug::integer::Order::MsfBe);

        let other_ruid = uav_ruid.last().unwrap();
        let other_c = c_list.last().unwrap();

        let other_addr = UAV_RUID_LIST.get(other_ruid).unwrap().ip_addr.clone() + ":8092";
        send_uav_message_tcp(&other_addr, kd_bytes, other_c.to_owned(), ssk_bytes).await?;
    }

    Ok(())
}

async fn send_uav_message_tcp(
    addr: &str,
    _kd: Vec<u8>,
    c: String,
    ssk: Vec<u8>,
) -> anyhow::Result<()> {
    let stream = TcpStream::connect(addr).await?;
    let mut framed = Framed::new(stream, UavUavCommunicateClientCodec);
    // fake encrypted data
    let data = vec![];
    framed
        .send(UavUavCommunicateRequest::new_uav_uav_communicate_prev_message(data, c, ssk))
        .await?;
    Ok(())
}

async fn receive_uav_message_tcp() -> anyhow::Result<()> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:8092").await?;
    loop {
        let (socket, _addr) = listener.accept().await?;
        tokio::spawn(async move {
            let res = receive_uav_message(socket, _addr).await;
            match res {
                Ok(_) => {}
                Err(e) => {
                    tracing::error!("receive uav message failed: {:?}", e)
                }
            }
        });
    }
}

async fn receive_uav_message(stream: TcpStream, _addr: SocketAddr) -> anyhow::Result<()> {
    let mut framed = Framed::new(stream, UavUavCommunicateServerCodec);
    let prev = if let Some(Ok(res)) = framed.next().await {
        if let Some(uav_uav_communicate_request::Request::UavUavCommunicatePrevMessage(prev_msg)) =
            res.request
        {
            prev_msg
        } else {
            anyhow::bail!("receive uav uav message failed");
        }
    } else {
        anyhow::bail!("receive uav uav message prev failed");
    };
    tracing::debug!("prev: {:?}", prev);
    let ssk = Integer::from_digits(&prev.ssk, rug::integer::Order::MsfBe);
    let r = PUF.calculate(&prev.c).await?;
    let n = Integer::from_digits(&hex::decode(r)?, rug::integer::Order::MsfBe).next_prime();
    let kd = ssk % &n;
    tracing::info!("kd   : {}", kd.to_string_radix(16));
    Ok(())
}
