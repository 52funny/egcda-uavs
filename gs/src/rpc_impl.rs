use crate::{GSConfig, TAG, T_MAX, UAV_LIST};
use blake2::Blake2b512;
use blstrs_plus::{elliptic_curve::hash2curve::ExpandMsgXmd, group::prime::PrimeCurveAffine, pairing, G1Affine, G1Projective, G2Affine};
use hex::ToHex;
use rpc::*;
use rug::integer::Order;
use tracing::info;
use utils::build_crt;

#[derive(Debug, Clone)]
pub struct GS {
    pub cfg: GSConfig,
    pub pk_t: G2Affine,
}

impl GS {
    pub fn new(cfg: GSConfig, pk_t: G2Affine) -> Self {
        Self { cfg, pk_t }
    }
}

impl GsRpc for GS {
    async fn get_gs_pubkey(self, _context: ::tarpc::context::Context) -> String {
        self.cfg.pk.to_compressed().encode_hex::<String>()
    }

    async fn authenticate_uav_phase1(self, _context: ::tarpc::context::Context, req: UavAuthRequest1) -> Option<UavAuthResponse1> {
        let uid = req.uid;
        let uav_info = UAV_LIST.0.get(&uid)?;
        Some(UavAuthResponse1 {
            puf_challenge: uav_info.c.clone(),
        })
    }

    async fn authenticate_uav_phase2(self, _context: ::tarpc::context::Context, req: UavAuthRequest2) -> Option<UavAuthResponse2> {
        let uid = req.uid;
        let uav_info = UAV_LIST.0.get(&uid)?;

        let pk_u = uav_info.pk;
        let z = G1Affine::from_compressed_hex(&uav_info.z).expect("Failed to decode UAV z value");
        let x = G1Affine::from_compressed_hex(&req.x).expect("Failed to decode x value");

        let t_now = chrono::Utc::now().timestamp();
        if (t_now - req.t_u).abs() > T_MAX {
            tracing::warn!("UAV authentication request too old: {}", t_now - req.t_u);
            return None;
        }
        let mut buf = Vec::with_capacity(uav_info.c.len() + req.x.len() + uid.len() + 8);
        buf.extend_from_slice(uav_info.c.as_bytes());
        buf.extend_from_slice(req.x.as_bytes());
        buf.extend_from_slice(uid.as_bytes());
        buf.extend_from_slice(&req.t_u.to_be_bytes());

        let sigma = req.sigma;
        let sig = G1Affine::from_compressed_hex(&sigma).expect("Failed to decode UAV signature");

        let h_i = G1Projective::hash::<ExpandMsgXmd<Blake2b512>>(&buf, TAG);

        let tmp: G1Affine = (sig + G1Projective::from(z)).into();
        let lhs = pairing(&tmp, &G2Affine::generator());

        let rhs1 = pairing(&h_i.into(), &pk_u);
        let rhs2 = pairing(&x, &self.pk_t);

        let rhs = rhs1 * rhs2;
        if lhs == rhs {
            info!("UAV authentication successful for uid: {}", uid);
        } else {
            tracing::warn!("UAV authentication failed for uid: {}", uid);
            return None;
        }
        Some(UavAuthResponse2 {})
    }

    async fn get_all_uav_id(self, _context: ::tarpc::context::Context, id: String) -> Vec<String> {
        let uid_list = UAV_LIST
            .0
            .iter()
            .filter(|x| x.key() != &id)
            .map(|x| x.key().clone())
            .collect::<Vec<_>>();

        let mut list = Vec::with_capacity(uid_list.len() + 1);
        list.push(id);
        list.extend_from_slice(&uid_list);
        list
    }

    async fn communicate_uavs(self, _context: ::tarpc::context::Context, req: UavCommRequest) -> Option<UavCommResponse> {
        let uid_k = req.uid_k;
        let c_p = uid_k
            .iter()
            .map(|uid| {
                let uav_opt = UAV_LIST.0.get(uid);
                if uav_opt.is_none() {
                    tracing::warn!("UAV with uid {} not found", uid);
                    return None;
                }
                let uav = uav_opt.unwrap();
                Some((uid, uav.c.clone(), uav.p.clone()))
            })
            .collect::<Option<Vec<_>>>()?;

        let c = c_p.iter().map(|(_, c, _)| c.clone()).collect::<Vec<_>>();
        let p = c_p.iter().map(|(_, _, p)| p.clone()).collect::<Vec<_>>();

        let bytes = rand::random::<[u8; 16]>();
        let kd = rug::Integer::from_digits(&bytes, Order::MsfBe);
        info!("Generated key for uav group communication: {}", kd.to_string_radix(16));

        let eta = build_crt(p);
        let mu = kd.clone() * eta;

        Some(UavCommResponse {
            mu: mu.to_string_radix(16),
            c_m: c,
        })
    }
}
