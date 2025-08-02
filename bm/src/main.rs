use blstrs_plus::{G1Affine, G2Affine, Scalar, group::prime::PrimeCurveAffine, pairing};

fn main() {
    test_scalar_mul_point1();
    test_scalar_mul_point2();
    test_add_g1();
    test_add_g2();
    test_pairing();
    test_pairing_exp();
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

fn test_pairing_exp() {
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
