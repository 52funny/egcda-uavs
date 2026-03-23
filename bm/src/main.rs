mod puf;
use blake2::{Blake2b512, Blake2bMac512, Digest};
use blstrs_plus::{
    ff::Field,
    G1Affine, G1Projective, G2Affine, Scalar, elliptic_curve::hash2curve::ExpandMsgXmd, group::prime::PrimeCurveAffine, pairing,
};
use hmac::Mac;
use puf::Puf;
use rand::RngCore;
use rug::{Integer, integer::Order};
use sha2::Sha256;

const TAG: &[u8] = b"BLS_SIG_BLS12381G1_XMD:BLAKE2b-512_SSWU_RO_NUL_";
type HmacBlake2b = Blake2bMac512;

#[tokio::main]
async fn main() {
    let puf = Puf::new_with_pool_size(([127, 0, 0, 1], 12345), 8).await.unwrap();
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
    test_large_integer_modulo();
    test_aes_encrypt();
    test_aes_decrypt();
    test_hmac();
    test_xor();
    test_chaotic_map();
    test_fuzzy_extractor();
    for n in [128usize, 256, 512] {
        test_secret_sharing_recovery(n);
    }
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
    let b = random_nonzero_integer_256();
    let a = Integer::from_digits(&a_bytes, Order::MsfBe);
    let t = std::time::Instant::now();
    let _c = a / b;
    println!("Large integer division took: {:?}", t.elapsed());
}

fn test_large_integer_modulo() {
    let a_bytes = rand::random::<[u8; 32]>();
    let a = Integer::from_digits(&a_bytes, Order::MsfBe);
    let b = random_nonzero_integer_256();
    let t = std::time::Instant::now();
    let _r = a.modulo(&b);
    println!("Large integer modulo took: {:?}", t.elapsed());
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

fn test_hmac() {
    let key = rand::random::<[u8; 32]>();
    let mut data = [0u8; 128];
    rand::thread_rng().fill_bytes(&mut data);
    let t = std::time::Instant::now();
    let mut mac = HmacBlake2b::new_from_slice(&key).expect("HMAC key length is valid");
    mac.update(&data);
    let _tag = mac.finalize().into_bytes();
    println!("HMAC-BLAKE2b took: {:?}", t.elapsed());
}

fn test_xor() {
    let lhs = rand::random::<[u8; 32]>();
    let rhs = rand::random::<[u8; 32]>();
    let t = std::time::Instant::now();
    let _out = xor_bytes(&lhs, &rhs);
    println!("XOR took: {:?}", t.elapsed());
}

fn test_chaotic_map() {
    let seed = 0.618_033_988_749_894_9_f64;
    let degree = 5_u32;
    let iterations = 1_000;
    let t = std::time::Instant::now();
    let _value = chebyshev_map(seed, degree, iterations);
    println!("Chebyshev chaotic map iteration took: {:?}", t.elapsed());
}

fn test_fuzzy_extractor() {
    let extractor = FuzzyExtractor::new(32, 2, 0.001);
    let value = b"AABBCCDDEEFFGGHHAABBCCDDEEFFGGHH";
    let noisy_value = b"AABBCCDDEEFFGGKHAABBCCDDEEFFGGHH";

    let t = std::time::Instant::now();
    let (_key, helper) = extractor.generate(value).expect("fuzzy extractor generate failed");
    let _reproduced = extractor
        .reproduce(noisy_value, &helper)
        .expect("fuzzy extractor reproduce failed");
    println!("Fuzzy extractor generate+reproduce took: {:?}", t.elapsed());
}

fn test_secret_sharing_recovery(n: usize) {
    let threshold = n;
    let secret = random_scalar();
    let shares = generate_shamir_shares(secret, threshold, n);
    let t = std::time::Instant::now();
    let recovered = recover_shamir_secret(&shares[..threshold]);
    let _secret_bigint = Integer::from_digits(&recovered.to_be_bytes(), Order::MsfBe);
    println!("Secret sharing recovery over BLS scalar field with n={n} took: {:?}", t.elapsed());
}

async fn test_puf(puf: &Puf) {
    let c = rand::random::<[u8; 12]>();
    let c_hex = hex::encode(c);
    let t = std::time::Instant::now();
    let _r = puf.calculate(c_hex).await.unwrap();
    println!("PUF calculation took: {:?}", t.elapsed());
}

fn random_nonzero_integer_256() -> Integer {
    loop {
        let bytes = rand::random::<[u8; 32]>();
        let value = Integer::from_digits(&bytes, Order::MsfBe);
        if value != 0 {
            return value;
        }
    }
}

fn random_scalar() -> Scalar {
    let mut wide = [0u8; 64];
    rand::thread_rng().fill_bytes(&mut wide);
    Scalar::from_bytes_wide(&wide)
}

fn generate_shamir_shares(secret: Scalar, threshold: usize, n: usize) -> Vec<(Scalar, Scalar)> {
    let mut coeffs = Vec::with_capacity(threshold);
    coeffs.push(secret);
    coeffs.extend((1..threshold).map(|_| random_scalar()));

    (1..=n)
        .map(|i| {
            let x = Scalar::from(i as u64);
            let y = coeffs
                .iter()
                .rev()
                .copied()
                .fold(Scalar::ZERO, |acc, coeff| acc * x + coeff);
            (x, y)
        })
        .collect()
}

fn recover_shamir_secret(shares: &[(Scalar, Scalar)]) -> Scalar {
    shares
        .iter()
        .enumerate()
        .fold(Scalar::ZERO, |acc, (i, (x_i, y_i))| {
            let (numerator, denominator) = shares.iter().enumerate().filter(|(j, _)| *j != i).fold(
                (Scalar::ONE, Scalar::ONE),
                |(num, den), (_, (x_j, _))| (num * -*x_j, den * (*x_i - *x_j)),
            );

            let inv = Option::<Scalar>::from(denominator.invert()).expect("distinct x coordinates required");
            acc + *y_i * numerator * inv
        })
}

fn xor_bytes<const N: usize>(lhs: &[u8; N], rhs: &[u8; N]) -> [u8; N] {
    let mut out = [0u8; N];
    for (dst, (a, b)) in out.iter_mut().zip(lhs.iter().zip(rhs.iter())) {
        *dst = *a ^ *b;
    }
    out
}

fn chebyshev_map(mut x: f64, degree: u32, iterations: usize) -> f64 {
    for _ in 0..iterations {
        x = ((degree as f64) * x.acos()).cos();
    }
    x
}

#[derive(Debug, Clone)]
struct Helper {
    helper_len: usize,
    nonces: Vec<Vec<u8>>,
    masks: Vec<Vec<u8>>,
    ciphers: Vec<Vec<u8>>,
}

impl Helper {
    fn new(length: usize, cipher_len: usize, helper_len: usize) -> Self {
        let mut nonces = vec![vec![0u8; 16]; helper_len];
        let mut masks = vec![vec![0u8; length]; helper_len];
        let ciphers = vec![vec![0u8; cipher_len]; helper_len];
        for i in 0..helper_len {
            rand::thread_rng().fill_bytes(&mut nonces[i]);
            rand::thread_rng().fill_bytes(&mut masks[i]);
        }
        Self {
            helper_len,
            nonces,
            masks,
            ciphers,
        }
    }
}

#[derive(Debug)]
struct FuzzyExtractor {
    length: usize,
    ham_err: usize,
    rep_err: f64,
    sec_len: usize,
    cipher_len: usize,
    helper_len: usize,
}

impl FuzzyExtractor {
    fn new(length: usize, ham_err: usize, rep_err: f64) -> Self {
        let bits = (length * 8) as f64;
        let exp = ham_err as f64 / bits.ln();
        let num_helpers = (bits.powf(exp) * (2.0 / rep_err).log2()) as usize;
        let sec_len = 2;

        Self {
            length,
            ham_err,
            rep_err,
            sec_len,
            cipher_len: sec_len + length,
            helper_len: num_helpers.max(1),
        }
    }

    fn generate(&self, value: impl AsRef<[u8]>) -> anyhow::Result<(Vec<u8>, Helper)> {
        let value = value.as_ref();
        if self.length != value.len() {
            anyhow::bail!("value length does not match extractor length");
        }

        let mut key = vec![0u8; self.length];
        let mut key_padded = vec![0u8; self.sec_len + self.length];
        rand::thread_rng().fill_bytes(&mut key);
        key_padded[..self.length].copy_from_slice(&key);

        let mut vector = vec![0u8; self.length];
        let mut helper = Helper::new(self.length, self.cipher_len, self.helper_len);

        for i in 0..helper.helper_len {
            for j in 0..self.length {
                vector[j] = value[j] & helper.masks[i][j];
            }

            pbkdf2::pbkdf2_hmac::<Sha256>(&vector, &helper.nonces[i], 1, &mut helper.ciphers[i]);

            for j in 0..self.cipher_len {
                helper.ciphers[i][j] ^= key_padded[j];
            }
        }

        Ok((key, helper))
    }

    fn reproduce(&self, value: impl AsRef<[u8]>, helper: &Helper) -> anyhow::Result<Vec<u8>> {
        let value = value.as_ref();
        if self.length != value.len() {
            anyhow::bail!("value length does not match extractor length");
        }

        let mut vector = vec![0u8; self.length];
        let mut digest = vec![0u8; self.cipher_len];
        let mut plain = vec![0u8; self.cipher_len];

        for i in 0..helper.helper_len {
            for j in 0..self.length {
                vector[j] = value[j] & helper.masks[i][j];
            }

            pbkdf2::pbkdf2_hmac::<Sha256>(&vector, &helper.nonces[i], 1, &mut digest);

            for j in 0..self.cipher_len {
                plain[j] = helper.ciphers[i][j] ^ digest[j];
            }

            if plain[self.length..self.cipher_len].iter().all(|byte| *byte == 0) {
                return Ok(plain[..self.length].to_vec());
            }
        }

        anyhow::bail!(
            "no match found for fuzzy extractor with ham_err={} and rep_err={}",
            self.ham_err,
            self.rep_err
        );
    }
}
