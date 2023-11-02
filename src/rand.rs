use crate::conversion::ByteConvertible;
use curve25519_dalek::RistrettoPoint;
use curve25519_dalek::Scalar;
use num_bigint::BigUint;
use rand::RngCore;

pub trait RandomGenerator<T> {
    fn generate_random() -> Result<T, Box<dyn std::error::Error>>;
}

impl RandomGenerator<BigUint> for BigUint {
    fn generate_random() -> Result<BigUint, Box<dyn std::error::Error>> {
        let mut rng = rand::thread_rng();
        let mut bytes = vec![0u8; 32];
        rng.fill_bytes(&mut bytes);
        BigUint::from_bytes(&bytes)
    }
}

impl RandomGenerator<Scalar> for Scalar {
    fn generate_random() -> Result<Scalar, Box<dyn std::error::Error>> {
        let mut rng = rand::thread_rng();
        let mut bytes = vec![0u8; 32];
        rng.fill_bytes(&mut bytes);
        Scalar::from_bytes(&bytes)
    }
}

impl RandomGenerator<RistrettoPoint> for RistrettoPoint {
    fn generate_random() -> Result<RistrettoPoint, Box<dyn std::error::Error>> {
        let mut rng = rand::thread_rng();
        let mut bytes = vec![0u8; 32];
        rng.fill_bytes(&mut bytes);
        RistrettoPoint::from_bytes(&bytes)
    }
}
