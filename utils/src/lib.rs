use blake2::{Blake2b512, Digest};
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use rayon::prelude::*;
use rug::{
    Integer,
    integer::{IsPrime, Order},
};

const BIT_LENGTH: usize = 256;

pub fn hash_to_prime(data: String) -> Integer {
    let mut hasher = Blake2b512::new();
    hasher.update(&data);
    let hash_bytes = hasher.finalize();

    let mut seed = [0u8; 32];
    seed.copy_from_slice(&hash_bytes[..32]);
    let mut rng = ChaCha20Rng::from_seed(seed);

    // Draw a random number of BIT_LENGTH bits from rng
    let byte_len = BIT_LENGTH.div_ceil(8);
    let mut buf = vec![0u8; byte_len];

    loop {
        rng.fill_bytes(&mut buf);

        // Clear the extra high bits to ensure it strictly does not exceed BIT_LENGTH bits
        let extra_bits = byte_len * 8 - BIT_LENGTH;
        buf[0] &= 0xFF >> extra_bits;

        // Ensure it is odd
        buf[byte_len - 1] |= 1;

        // Convert to a big integer (big-endian)
        let candidate = Integer::from_digits(&buf, Order::MsfBe);

        // Primality test (Miller–Rabin, 25 rounds)
        if candidate.is_probably_prime(25) != IsPrime::No {
            return candidate;
        }
        // Otherwise, continue the loop
    }
}

pub fn encrypt_aes128_gcm(key: &[u8; 16], data: &[u8]) -> anyhow::Result<Vec<u8>> {
    use aes_gcm::{
        Aes128Gcm, Nonce,
        aead::{Aead, KeyInit},
    };

    let cipher = Aes128Gcm::new_from_slice(key)?;
    let nonce = Nonce::from_slice(&[0u8; 12]);

    cipher
        .encrypt(nonce, data)
        .map_err(|e| anyhow::anyhow!("AES-GCM encryption failed: {:?}", e))
}

pub fn decrypt_aes128_gcm(key: &[u8; 16], ciphertext: &[u8]) -> anyhow::Result<Vec<u8>> {
    use aes_gcm::{
        Aes128Gcm, Nonce,
        aead::{Aead, KeyInit},
    };

    let cipher = Aes128Gcm::new_from_slice(key)?;
    let nonce = Nonce::from_slice(&[0u8; 12]);

    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| anyhow::anyhow!("AES-GCM decryption failed: {:?}", e))
}

pub fn build_crt(p: Vec<Integer>) -> Integer {
    let m = p.par_iter().product::<Integer>();
    let mi = p.par_iter().map(|x| m.clone() / x).collect::<Vec<_>>();
    let mi_inv = mi
        .par_iter()
        .zip(p)
        .map(|(m_i, p)| m_i.clone().invert(&p).expect("Failed to invert"))
        .collect::<Vec<_>>();

    mi.par_iter()
        .zip(mi_inv)
        .map(|(m_i, m_i_inv)| m_i.clone() * m_i_inv)
        .sum::<Integer>()
}

/// Abbreviate a string like: aa9f0...34865
///
/// Keeps the first `head` characters and last `tail` characters, inserting
/// `placeholder` in between if truncation is needed.
pub fn abbreviate_key(s: &str, head: usize, tail: usize, placeholder: &str) -> String {
    let chars: Vec<char> = s.chars().collect();
    let total_len = chars.len();
    let placeholder_len = placeholder.chars().count();

    if total_len <= head + tail + placeholder_len {
        return s.to_string();
    }

    let head_part: String = chars.iter().take(head).collect();
    let tail_part: String = chars.iter().rev().take(tail).collect::<Vec<_>>().into_iter().rev().collect();

    format!("{head_part}{placeholder}{tail_part}")
}

/// Convenience with defaults: keep 5 head, 5 tail, use "..." as placeholder.
pub fn abbreviate_key_default(s: &str) -> String {
    abbreviate_key(s, 5, 5, "...")
}

#[cfg(test)]
mod tests {
    use super::*;
    use rug::integer::Order;

    #[test]
    fn test_hash_to_prime() {
        let data = "test data!".to_string();
        let t = std::time::Instant::now();
        let prime = hash_to_prime(data);
        println!("Time taken: {:?}", t.elapsed());
        println!("Generated prime: {prime}");

        assert!(prime.is_probably_prime(10) != IsPrime::No);
    }

    #[test]
    fn test_crt() {
        let mut p = Vec::new();
        for _ in 1..10 {
            let bytes = rand::random::<[u8; 16]>();
            p.push(Integer::from_digits(&bytes, Order::MsfBe).next_prime());
        }
        let v = build_crt(p.clone());
        for x in p.iter() {
            assert_eq!(v.clone() % x, Integer::from(1));
        }
    }
}
