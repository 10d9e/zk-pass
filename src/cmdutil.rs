/// An enumeration representing the types of RFC MODP groups.
///
/// These types correspond to the different MODP groups defined in RFC 5114. They are used
/// to specify the particular parameters of the finite cyclic groups used in cryptographic
/// protocols. These groups are often used in key exchange protocols like Diffie-Hellman.
///
/// # Variants
/// - `Rfc5114Modp_1024_160`: Represents the 1024-bit MODP group with a 160-bit prime order subgroup.
/// - `Rfc5114Modp_2048_224`: Represents the 2048-bit MODP group with a 224-bit prime order subgroup.
/// - `Rfc5114Modp_2048_256`: Represents the 2048-bit MODP group with a 256-bit prime order subgroup.
#[derive(PartialEq, Debug, strum::EnumString, strum::EnumVariantNames, strum::Display)]
#[strum(serialize_all = "snake_case")]
#[allow(non_camel_case_types)]
pub enum RfcModpType {
    Rfc5114Modp_1024_160,
    Rfc5114Modp_2048_224,
    Rfc5114Modp_2048_256,
}

/// An enumeration representing the types of Chaum-Pedersen protocols.
///
/// The Chaum-Pedersen protocol is a cryptographic protocol used for proving knowledge
/// of a discrete logarithm without revealing its value. This enumeration specifies
/// the underlying mathematical structure used in the protocol.
///
/// # Variants
/// - `DiscreteLog`: Indicates that the protocol is based on discrete logarithms.
/// - `EllipticCurve`: Indicates that the protocol is based on elliptic curves.
#[derive(PartialEq, Debug, strum::EnumString, strum::EnumVariantNames, strum::Display)]
#[strum(serialize_all = "snake_case")]
pub enum ChaumPedersenType {
    DiscreteLog,
    EllipticCurve,
}

/// An enumeration representing the types of elliptic curves.
///
/// Elliptic curves are used in various cryptographic protocols, and this enumeration
/// provides a way to specify which type of elliptic curve is being used.
///
/// # Variants
/// - `Ec25519`: Represents the Curve25519 elliptic curve, commonly used in cryptographic
///   protocols for key exchange and digital signatures.
#[derive(PartialEq, Debug, strum::EnumString, strum::EnumVariantNames, strum::Display)]
#[strum(serialize_all = "snake_case")]
pub enum EllipticCurveType {
    Ec25519,
    Pallas,
}
