use rug::{Integer, integer::Order};
use std::time::Instant;

fn main() {
    for n in [4usize, 8, 16, 32, 64, 128, 256, 512] {
        let primes = generate_primes(n, 128);
        let t = Instant::now();
        let crt = utils::build_crt(primes.clone());
        let elapsed = t.elapsed();
        let modulus = primes.iter().product::<Integer>();
        let quotient: Integer = (crt.clone() - 1) / &modulus;

        println!(
            "n={n:>3} | crt_bits={:>6} | crt_bytes={:>5} | M_bits={:>6} | q_bits={:>2} | elapsed={elapsed:?}",
            crt.significant_bits(),
            crt.significant_digits::<u8>(),
            modulus.significant_bits(),
            quotient.significant_bits(),
        );
    }
}

fn generate_primes(n: usize, bits: usize) -> Vec<Integer> {
    let byte_len = bits.div_ceil(8);
    let mut primes = Vec::with_capacity(n);
    for i in 0..n {
        let mut candidate = {
            let mut bytes = vec![0u8; byte_len];
            for (j, b) in bytes.iter_mut().enumerate() {
                *b = (((i / 8) * 131 + i * 17 + j * 29 + 31) & 0xff) as u8;
            }
            bytes[0] |= 0x80;
            bytes[byte_len - 1] |= 1;
            Integer::from_digits(&bytes, Order::MsfBe).next_prime()
        };

        while primes.iter().any(|p| p == &candidate) {
            candidate += 2;
            candidate = candidate.next_prime();
        }
        primes.push(candidate);
    }
    primes
}
