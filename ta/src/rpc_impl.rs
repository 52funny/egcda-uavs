use crate::{GsInfo, TAConfig, UavInfo, GS_LIST, GS_SSK_LIST, PUF_INPUT_SIZE, TAG, T_MAX, UAV_LIST};
use blake2::{Blake2b512, Digest};
use blstrs_plus::{
    elliptic_curve::hash2curve::ExpandMsgXmd, group::prime::PrimeCurveAffine, pairing, G1Affine, G1Projective, G2Affine, Scalar,
};
use dashmap::DashMap;
use hex::ToHex;
use lazy_static::lazy_static;
use rpc::*;
use rug::Integer;
use tracing::{debug, info, warn};
use utils::{abbreviate_key_default, encrypt_aes128_gcm, hash_to_prime};

lazy_static! {
    static ref state: DashMap<String, UavInfo> = DashMap::new();
}

#[derive(Clone)]
pub struct TA {
    cfg: TAConfig,
}

impl TA {
    pub fn new(cfg: TAConfig) -> Self {
        TA { cfg }
    }
}

impl TaRpc for TA {
    async fn get_ta_pubkey(self, _context: tarpc::context::Context) -> String {
        hex::encode(self.cfg.pk.to_compressed())
    }

    async fn register_gs(self, _context: tarpc::context::Context, req: rpc::GsRegisterRequest) -> () {
        let (gid, pk_str) = (req.gid, req.gs_pubkey);
        let pk_bytes = hex::decode(pk_str).expect("Failed to decode hex");
        let pk_array: [u8; 96] = pk_bytes.try_into().expect("Public key bytes length mismatch");
        let pk = G2Affine::from_compressed(&pk_array).expect("Failed to create G2Affine from bytes");
        info!("GS registered: {}", abbreviate_key_default(&gid));
        GS_LIST.insert(gid.clone(), GsInfo { gid, pk });
    }

    #[allow(clippy::missing_transmute_annotations)]
    async fn authenticate_gs(self, _context: tarpc::context::Context, req: rpc::GsAuthRequest) -> Option<rpc::GsAuthResponse> {
        let (gid, t_g, sig) = (req.gid, req.t_g, req.sigma);
        let gs_info = GS_LIST.get(&gid).expect("GS not found");

        let t_now = chrono::Utc::now().timestamp();
        let t = hex::decode(&t_g).expect("Failed to decode hex");
        let t: [u8; 8] = t[0..8].try_into().expect("T_g bytes length mismatch");
        let t = i64::from_be_bytes(t);
        if (t_now - t) > T_MAX as i64 {
            warn!("GS authentication failed: T_g is too old");
            return None;
        }

        let mut buf = Vec::with_capacity(gid.len() + t_g.len());
        buf.extend_from_slice(gid.as_bytes());
        buf.extend_from_slice(t_g.as_bytes());

        let sig = G1Affine::from_compressed_hex(&sig).expect("Failed to decode G1Affine from hex");
        let tau = G1Projective::hash::<ExpandMsgXmd<Blake2b512>>(&buf, TAG);

        let lhs = pairing(&sig, &G2Affine::generator());
        let rhs = pairing(&tau.into(), &gs_info.pk);

        if lhs != rhs {
            warn!("GS authentication failed for gid : {}", gid);
            return None;
        }

        info!("GS authentication successful for gid: {}", abbreviate_key_default(&gid));

        let mut hasher = Blake2b512::new();
        hasher.update(tau.to_compressed());
        let x = hasher.finalize();
        let x = Scalar::from_bytes_wide(unsafe { &std::mem::transmute::<_, [u8; 64]>(x) });

        let ssk = gs_info.pk * x * self.cfg.sk;
        let ssk_hex = ssk.to_compressed().encode_hex::<String>();

        debug!("Generated shared secret key for GS: {}", abbreviate_key_default(&ssk_hex));

        // insert ssk into GS_SSK_LIST
        GS_SSK_LIST.insert(gid.clone(), ssk_hex);

        Some(GsAuthResponse {})
    }

    async fn get_uav_list(self, _context: tarpc::context::Context, gid: String) -> Option<Vec<u8>> {
        let ssk_hex_ref = GS_SSK_LIST.get(&gid)?;
        let ssk_hex = ssk_hex_ref.value();
        let ssk_bytes = hex::decode(ssk_hex).expect("Failed to decode shared secret key from hex");

        let data = UAV_LIST
            .0
            .iter()
            .map(|entry| transmute_uav_info(entry.value(), &self.cfg))
            .collect::<Vec<_>>();
        let data_json = serde_json::to_string(&data).unwrap();

        let ciphertext = encrypt_aes128_gcm(
            &ssk_bytes[0..16].try_into().expect("Shared secret key length mismatch"),
            data_json.as_bytes(),
        )
        .expect("AES-GCM encryption failed");
        Some(ciphertext)
    }

    async fn register_uav_phase1(
        self,
        _context: tarpc::context::Context,
        _req: rpc::UavRegisterRequest1,
    ) -> Option<rpc::UavRegisterResponse1> {
        let uid = rand::random::<[u8; 32]>();
        let uid = uid.encode_hex::<String>();

        let sk = rand::random::<[u64; 4]>();
        let sk = Scalar::from_raw_unchecked(sk);

        let pk = G2Affine::generator() * sk;

        let puf_challenge = rand::random::<[u8; PUF_INPUT_SIZE]>().encode_hex::<String>();

        let uav_info = UavInfo {
            uid: uid.clone(),
            sk,
            pk: pk.into(),
            c: puf_challenge.clone(),
            r: String::default(),
            p: Integer::default(),
        };
        debug!("uav info: {:?}", uav_info);

        let sk_hex = sk.to_be_bytes().encode_hex::<String>();
        let pk_hex = pk.to_compressed().encode_hex::<String>();

        if state.contains_key(&uid) {
            warn!("UAV with uid {} already exists, generating a new one", uid);
            return None;
        }

        state.insert(uid.clone(), uav_info);
        let resp = rpc::UavRegisterResponse1 {
            uid,
            puf_challenge,
            uav_sk: sk_hex,
            uav_pubkey: pk_hex,
        };
        Some(resp)
    }

    async fn register_uav_phase2(
        self,
        _context: tarpc::context::Context,
        req: rpc::UavRegisterRequest2,
    ) -> Option<rpc::UavRegisterResponse2> {
        let uid = req.uid;
        let puf_response = req.puf_response;

        let p = hash_to_prime(puf_response.clone() + &uid);

        let Some((_, mut uav_info)) = state.remove(&uid) else {
            warn!("UAV with uid {} not found", uid);
            return None;
        };

        uav_info.p = p;
        uav_info.r = puf_response;

        UAV_LIST.0.insert(uid.clone(), uav_info);
        info!("UAV registered with uid: {}", abbreviate_key_default(&uid));

        Some(rpc::UavRegisterResponse2 {})
    }
}

fn transmute_uav_info(uav: &UavInfo, cfg: &TAConfig) -> GsAuthResponseStruct {
    let r = hex::decode(&uav.r).unwrap();
    let mut r_buf = [0u8; 64];
    r_buf[..r.len()].copy_from_slice(&r);
    let r_scalr = Scalar::from_bytes_wide(&r_buf);

    let sk = cfg.sk;

    let g1 = G1Affine::generator();
    let z = (g1 * sk * r_scalr).to_compressed();

    GsAuthResponseStruct {
        uid: uav.uid.clone(),
        pk_u: uav.pk.to_compressed().encode_hex::<String>(),
        c: uav.c.clone(),
        z: z.encode_hex::<String>(),
        p: uav.p.clone(),
    }
}
