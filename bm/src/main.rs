mod puf;
use blake2::{Blake2b512, Digest};
use blstrs_plus::{
    G1Affine, G1Projective, G2Affine, Scalar, elliptic_curve::hash2curve::ExpandMsgXmd, group::prime::PrimeCurveAffine, pairing,
};
use puf::Puf;
use rand::RngCore;

const TAG: &[u8] = b"BLS_SIG_BLS12381G1_XMD:BLAKE2b-512_SSWU_RO_NUL_";

#[tokio::main]
async fn main() {
    let puf = Puf::new(([127, 0, 0, 1], 12345)).await.unwrap();
    test_scalar_mul_point1();
    test_scalar_mul_point2();
    test_add_g1();
    test_add_g2();
    test_pairing();
    test_gt_exp();
    test_gt_mul();
    test_hash_to_zq();
    test_hash_to_g1();
    test_hash_to_prime();
    test_large_integer_add();
    test_large_integer_mul();
    test_large_integer_div();
    test_aes_encrypt();
    test_aes_decrypt();
    test_puf(&puf).await;
}

fn test_add_g1() {
    let g1 = G1Affine::generator();
    let p1 = g1 * Scalar::from_raw_unchecked(rand::random::<[u64; 4]>());
    let p2 = g1 * Scalar::from_raw_unchecked(rand::random::<[u64; 4]>());
    let t = std::time::Instant::now();
    let _p = p1 + p2;
    println!("G1 addition took: {:?}", t.elapsed());
}

fn test_add_g2() {
    let g2 = G2Affine::generator();
    let p1 = g2 * Scalar::from_raw_unchecked(rand::random::<[u64; 4]>());
    let p2 = g2 * Scalar::from_raw_unchecked(rand::random::<[u64; 4]>());
    let t = std::time::Instant::now();
    let _p = p1 + p2;
    println!("G2 addition took: {:?}", t.elapsed());
}

fn test_scalar_mul_point1() {
    let sk = rand::random::<[u64; 4]>();
    let scalar = Scalar::from_raw_unchecked(sk);
    let g1 = G1Affine::generator();
    let t = std::time::Instant::now();
    let _p = g1 * scalar;
    println!("Scalar multiplication on g1 took: {:?}", t.elapsed());
}

fn test_scalar_mul_point2() {
    let sk = rand::random::<[u64; 4]>();
    let scalar = Scalar::from_raw_unchecked(sk);
    let g2 = G2Affine::generator();
    let t = std::time::Instant::now();
    let _p = g2 * scalar;
    println!("Scalar multiplication on g2 took: {:?}", t.elapsed());
}

fn test_pairing() {
    let sk1 = rand::random::<[u64; 4]>();
    let sk2 = rand::random::<[u64; 4]>();
    let sk1 = Scalar::from_raw_unchecked(sk1);
    let sk2 = Scalar::from_raw_unchecked(sk2);

    let g1 = G1Affine::generator();
    let g2 = G2Affine::generator();

    let p = g1 * sk1;
    let q = g2 * sk2;

    let t = std::time::Instant::now();
    pairing(&p.into(), &q.into());
    println!("Pairing took: {:?}", t.elapsed());
}

fn test_gt_exp() {
    let sk1 = rand::random::<[u64; 4]>();
    let sk2 = rand::random::<[u64; 4]>();
    let sk1 = Scalar::from_raw_unchecked(sk1);
    let sk2 = Scalar::from_raw_unchecked(sk2);

    let e = Scalar::from_raw_unchecked(rand::random::<[u64; 4]>());

    let g1 = G1Affine::generator();
    let g2 = G2Affine::generator();

    let p = g1 * sk1;
    let q = g2 * sk2;

    let gt = pairing(&p.into(), &q.into());
    let t = std::time::Instant::now();
    let _ = gt * e;
    println!("Pairing exponentiation took: {:?}", t.elapsed());
}

fn test_gt_mul() {
    let sk1 = rand::random::<[u64; 4]>();
    let sk2 = rand::random::<[u64; 4]>();
    let sk1 = Scalar::from_raw_unchecked(sk1);
    let sk2 = Scalar::from_raw_unchecked(sk2);

    let g1 = G1Affine::generator();
    let g2 = G2Affine::generator();

    let p = g1 * sk1;
    let q = g2 * sk2;

    let gt = pairing(&p.into(), &q.into());
    let t = std::time::Instant::now();
    let _ = gt * gt;
    println!("GT multiplication took: {:?}", t.elapsed());
}

fn test_hash_to_g1() {
    let input = b"test input";
    let t = std::time::Instant::now();
    let _g1 = G1Projective::hash::<ExpandMsgXmd<Blake2b512>>(input, TAG);
    println!("Hash to G1 took: {:?}", t.elapsed());
}

fn test_hash_to_prime() {
    let data = "test data";
    let t = std::time::Instant::now();
    let _p = utils::hash_to_prime(data.into());
    println!("Hash to prime took: {:?}", t.elapsed());
}

fn test_hash_to_zq() {
    let data = "test data";
    let mut hasher = Blake2b512::new();
    let t = std::time::Instant::now();
    hasher.update(data);
    let _fin = hasher.finalize();
    println!("Hash to Z_q took: {:?}", t.elapsed());
}

fn test_large_integer_add() {
    let a_bytes = rand::random::<[u8; 32]>();
    let b_bytes = rand::random::<[u8; 32]>();
    let a = rug::Integer::from_digits(&a_bytes, rug::integer::Order::MsfBe);
    let b = rug::Integer::from_digits(&b_bytes, rug::integer::Order::MsfBe);
    let t = std::time::Instant::now();
    let _c = a + b;
    println!("Large integer addition took: {:?}", t.elapsed());
}

fn test_large_integer_mul() {
    let a_bytes = rand::random::<[u8; 32]>();
    let b_bytes = rand::random::<[u8; 32]>();
    let a = rug::Integer::from_digits(&a_bytes, rug::integer::Order::MsfBe);
    let b = rug::Integer::from_digits(&b_bytes, rug::integer::Order::MsfBe);
    let t = std::time::Instant::now();
    let _c = a * b;
    println!("Large integer multiplication took: {:?}", t.elapsed());
}

fn test_large_integer_div() {
    let a_bytes = rand::random::<[u8; 32]>();
    let b_bytes = rand::random::<[u8; 32]>();
    let a = rug::Integer::from_digits(&a_bytes, rug::integer::Order::MsfBe);
    let b = rug::Integer::from_digits(&b_bytes, rug::integer::Order::MsfBe);
    let t = std::time::Instant::now();
    let _c = a / b;
    println!("Large integer division took: {:?}", t.elapsed());
}

fn test_aes_encrypt() {
    let key = rand::random::<[u8; 16]>();
    let mut data = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut data);
    let t = std::time::Instant::now();
    let _ciphertext = utils::encrypt_aes128_gcm(&key, &data);
    println!("AES encryption took: {:?}", t.elapsed());
}

fn test_aes_decrypt() {
    let key = rand::random::<[u8; 16]>();
    let mut data = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut data);
    let ciphertext = utils::encrypt_aes128_gcm(&key, &data).unwrap();
    let t = std::time::Instant::now();
    let _plaintext = utils::decrypt_aes128_gcm(&key, &ciphertext).unwrap();
    println!("AES decryption took: {:?}", t.elapsed());
}

async fn test_puf(puf: &Puf) {
    let c = rand::random::<[u8; 12]>();
    let c_hex = hex::encode(c);
    let t = std::time::Instant::now();
    let _r = puf.calculate(c_hex).await.unwrap();
    println!("PUF calculation took: {:?}", t.elapsed());
}
