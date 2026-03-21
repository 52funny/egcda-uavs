use crate::{GSConfig, UavInfo, TAG, T_MAX, UAV_LIST, UAV_SESSION_KEYS};
use ::pairing::MillerLoopResult as _;
use blstrs_plus::{
    elliptic_curve::hash2curve::ExpandMsgXmd,
    group::{prime::PrimeCurveAffine, Group},
    multi_miller_loop, pairing, G1Affine, G1Projective, G2Affine, G2Prepared, Scalar,
};
use dashmap::DashMap;
use hex::ToHex;
use lazy_static::lazy_static;
use rayon::iter::{IndexedParallelIterator, IntoParallelRefIterator, ParallelIterator};
use rpc::*;
use rug::integer::Order;
use tracing::info;
use utils::{abbreviate_key_default, build_crt, derive_session_key_from_g1, hash_to_scalar};

#[derive(Debug, Clone)]
struct AuthSession {
    challenge: String,
    x: Scalar,
}

lazy_static! {
    static ref AUTH_SESSIONS: DashMap<String, AuthSession> = DashMap::new();
}

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
        let t_g = chrono::Utc::now().timestamp();
        let x = rand::random::<[u64; 4]>();
        let x = Scalar::from_raw_unchecked(x);
        let x_point = G1Affine::generator() * x;
        let z_point = G1Affine::from_compressed_hex(&uav_info.z).expect("Failed to decode UAV z value");

        let mut buf = Vec::with_capacity(
            uav_info.c.len()
                + uid.len()
                + 8
                + self.cfg.pk_g1.to_compressed().len()
                + x_point.to_compressed().len()
                + z_point.to_compressed().len(),
        );
        buf.extend_from_slice(uav_info.c.as_bytes());
        buf.extend_from_slice(uid.as_bytes());
        buf.extend_from_slice(&t_g.to_be_bytes());
        buf.extend_from_slice(&self.cfg.pk_g1.to_compressed());
        buf.extend_from_slice(&x_point.to_compressed());
        buf.extend_from_slice(&z_point.to_compressed());
        let e = hash_to_scalar(&buf);
        let sigma_g = x + e * self.cfg.sk;

        AUTH_SESSIONS.insert(
            uid.clone(),
            AuthSession {
                challenge: uav_info.c.clone(),
                x,
            },
        );

        Some(UavAuthResponse1 {
            puf_challenge: uav_info.c.clone(),
            x: x_point.to_compressed().encode_hex::<String>(),
            sigma_g: sigma_g.to_be_bytes().encode_hex::<String>(),
            gs_pubkey: self.cfg.pk_g1.to_compressed().encode_hex::<String>(),
            t_g,
        })
    }

    async fn authenticate_uav_phase2(self, _context: ::tarpc::context::Context, req: UavAuthRequest2) -> Option<UavAuthResponse2> {
        let uid = req.uid;
        let (_, session) = AUTH_SESSIONS.remove(&uid)?;
        let uav_info = UAV_LIST.0.get(&uid)?;

        let pk_u = uav_info.pk;
        let z = G1Affine::from_compressed_hex(&uav_info.z).expect("Failed to decode UAV z value");
        let g_r = G1Affine::from_compressed_hex(&req.g_r).expect("Failed to decode g_r value");

        let t_now = chrono::Utc::now().timestamp();
        if (t_now - req.t_u).abs() > T_MAX {
            tracing::warn!("UAV authentication request too old: {}", t_now - req.t_u);
            return None;
        }
        let mut buf = Vec::with_capacity(session.challenge.len() + g_r.to_compressed().len() + uid.len() + 8);
        buf.extend_from_slice(session.challenge.as_bytes());
        buf.extend_from_slice(&g_r.to_compressed());
        buf.extend_from_slice(uid.as_bytes());
        buf.extend_from_slice(&req.t_u.to_be_bytes());

        let sigma = req.sigma;
        let sig = G1Affine::from_compressed_hex(&sigma).expect("Failed to decode UAV signature");

        let h_i = G1Projective::hash::<ExpandMsgXmd<blake2::Blake2b512>>(&buf, TAG);

        let tmp: G1Affine = (sig + G1Projective::from(z)).into();
        let lhs = pairing(&tmp, &G2Affine::generator());

        let rhs1 = pairing(&h_i.into(), &pk_u);
        let rhs2 = pairing(&g_r, &self.pk_t);

        let rhs = rhs1 * rhs2;
        if lhs == rhs {
            let shared = G1Affine::from(G1Projective::from(g_r) * session.x);
            let ssk_g_u = derive_session_key_from_g1(&shared);
            UAV_SESSION_KEYS.insert(uid.clone(), hex::encode(ssk_g_u));
            info!("UAV authenticate successful {}", abbreviate_key_default(&uid));
        } else {
            tracing::warn!("UAV authenticate failed for uid: {}", abbreviate_key_default(&uid));
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
                    tracing::warn!("UAV with uid {} not found", abbreviate_key_default(&uid));
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
        info!("UAV group key: {}", abbreviate_key_default(&kd.to_string_radix(16)));

        let eta = build_crt(p);
        let mu = kd.clone() * eta;

        Some(UavCommResponse {
            mu: mu.to_string_radix(16),
            c_m: c,
        })
    }

    async fn batch_authenticate_uavs_phase1(self, _context: tarpc::context::Context, reqs: Vec<String>) -> Option<Vec<String>> {
        let uids = reqs;
        let responses = uids
            .iter()
            .map(|uid| {
                let uav_info = UAV_LIST.0.get(uid)?;
                let t_g = chrono::Utc::now().timestamp();
                let x = rand::random::<[u64; 4]>();
                let x = Scalar::from_raw_unchecked(x);
                let x_point = G1Affine::generator() * x;
                let z_point = G1Affine::from_compressed_hex(&uav_info.z).expect("Failed to decode UAV z value");
                let mut buf = Vec::with_capacity(
                    uav_info.c.len()
                        + uid.len()
                        + 8
                        + self.cfg.pk_g1.to_compressed().len()
                        + x_point.to_compressed().len()
                        + z_point.to_compressed().len(),
                );
                buf.extend_from_slice(uav_info.c.as_bytes());
                buf.extend_from_slice(uid.as_bytes());
                buf.extend_from_slice(&t_g.to_be_bytes());
                buf.extend_from_slice(&self.cfg.pk_g1.to_compressed());
                buf.extend_from_slice(&x_point.to_compressed());
                buf.extend_from_slice(&z_point.to_compressed());
                let e = hash_to_scalar(&buf);
                let sigma_g = x + e * self.cfg.sk;

                AUTH_SESSIONS.insert(
                    uid.clone(),
                    AuthSession {
                        challenge: uav_info.c.clone(),
                        x,
                    },
                );

                let response = UavAuthResponse1 {
                    puf_challenge: uav_info.c.clone(),
                    x: x_point.to_compressed().encode_hex::<String>(),
                    sigma_g: sigma_g.to_be_bytes().encode_hex::<String>(),
                    gs_pubkey: self.cfg.pk_g1.to_compressed().encode_hex::<String>(),
                    t_g,
                };
                Some(serde_json::to_string(&response).expect("Failed to encode auth response"))
            })
            .collect::<Option<Vec<_>>>()?;
        Some(responses)
    }
    async fn batch_authenticate_uavs_phase2(
        self,
        _context: tarpc::context::Context,
        reqs: Vec<UavAuthRequest2>,
    ) -> Option<UavAuthResponse2> {
        let uav_infos = reqs
            .par_iter()
            .map(|req| -> Option<(UavInfo, AuthSession)> {
                let uid = &req.uid;
                let uav_info = UAV_LIST.0.get(uid)?.clone();
                let (_, session) = AUTH_SESSIONS.remove(uid)?;
                Some((uav_info, session))
            })
            .collect::<Option<Vec<_>>>()?;

        let pk_us = uav_infos.par_iter().map(|(uav_info, _)| uav_info.pk).collect::<Vec<_>>();
        let z = uav_infos
            .par_iter()
            .map(|(uav_info, _)| G1Affine::from_compressed_hex(&uav_info.z).expect("Failed to decode UAV z value"))
            .map(G1Projective::from)
            .reduce(G1Projective::identity, |acc, z| acc + z);

        let g_rs = reqs
            .par_iter()
            .map(|req| G1Affine::from_compressed_hex(&req.g_r).expect("Failed to decode g_r value"))
            .collect::<Vec<_>>();

        let t_now = chrono::Utc::now().timestamp();
        // check if the request is too old
        reqs.par_iter()
            .map(|req| {
                if (t_now - req.t_u).abs() > T_MAX {
                    tracing::warn!("UAV authentication request too old: {}", t_now - req.t_u);
                    return None;
                }
                Some(())
            })
            .collect::<Option<Vec<_>>>()?;

        let sigma = reqs
            .par_iter()
            .map(|req| G1Affine::from_compressed_hex(&req.sigma).expect("Failed to decode UAV signature"))
            .map(G1Projective::from)
            .reduce(G1Projective::identity, |acc, sig| acc + sig);

        let h_is = reqs
            .par_iter()
            .zip(uav_infos.par_iter())
            .map(|(req, (_uav_info, session))| {
                let uid = &req.uid;
                let g_r = G1Affine::from_compressed_hex(&req.g_r).expect("Failed to decode g_r value");
                let mut buf = Vec::with_capacity(session.challenge.len() + g_r.to_compressed().len() + uid.len() + 8);
                buf.extend_from_slice(session.challenge.as_bytes());
                buf.extend_from_slice(&g_r.to_compressed());
                buf.extend_from_slice(uid.as_bytes());
                buf.extend_from_slice(&req.t_u.to_be_bytes());
                G1Projective::hash::<ExpandMsgXmd<blake2::Blake2b512>>(&buf, TAG)
            })
            .map(G1Affine::from)
            .collect::<Vec<_>>();

        let tmp: G1Affine = (sigma + z).into();
        let lhs = pairing(&tmp, &G2Affine::generator());

        let pk_t_prepared = G2Prepared::from(self.pk_t);
        let pk_us_prepared = pk_us.par_iter().map(|pk_u| G2Prepared::from(*pk_u)).collect::<Vec<_>>();
        let g_r_terms = g_rs.iter().map(|g_r| (g_r, &pk_t_prepared));
        let h_i_terms = h_is.iter().zip(pk_us_prepared.iter());
        let terms = h_i_terms.chain(g_r_terms).collect::<Vec<_>>();
        let rhs = multi_miller_loop(&terms).final_exponentiation();

        if lhs == rhs {
            reqs.par_iter().zip(g_rs.par_iter()).zip(uav_infos.par_iter()).for_each(|((req, g_r), (_, session))| {
                let shared = G1Affine::from(G1Projective::from(*g_r) * session.x);
                let ssk_g_u = derive_session_key_from_g1(&shared);
                UAV_SESSION_KEYS.insert(req.uid.clone(), hex::encode(ssk_g_u));
            });
            info!("UAV batch authentication successful");
            return Some(UavAuthResponse2 {});
        }
        tracing::warn!("UAV batch authentication failed");
        None
    }
}
