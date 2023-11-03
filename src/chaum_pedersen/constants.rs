use crate::{chaum_pedersen::GroupParams, conversion::ByteConvertible};
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::RistrettoPoint;
use lazy_static::lazy_static;
use num_bigint::BigUint;
use pasta_curves::pallas::Point;
use std::str::FromStr;

// RFC5114_GROUP_PARAMETERS are constant Prime Order Subgroups as defined in RFC5114
// Reference: https://www.rfc-editor.org/rfc/rfc5114.html#section-2
lazy_static! {

    // Group parameters for 1024-bit MODP group with 160-bit Prime Order Subgroup
    pub static ref RFC5114_MODP_1024_160_BIT_PARAMS: GroupParams<BigUint> = {
        GroupParams {
            p: BigUint::from_bytes_be(&hex::decode("B10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C69A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C013ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD7098488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708DF1FB2BC2E4A4371").unwrap()),
            q: BigUint::from_bytes_be(
                &hex::decode("F518AA8781A8DF278ABA4E7D64B7CB9D49462353").unwrap(),
            ),
            g: BigUint::from_bytes_be(&hex::decode("A4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507FD6406CFF14266D31266FEA1E5C41564B777E690F5504F213160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28AD662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24855E6EEB22B3B2E5").unwrap()),
            h: BigUint::from_bytes_be(&hex::decode("4BFE69CCAB1878A8B2DD9B4F83FFAC8D659EFA94698852F75A47EA4F7545230AD20FFB306DE1C24B5856E0D2C4798B3CC65A0307538B6E431CB94EB62892B0296B281D31EA58A9CC9D5917BF4BAD70AE5B1363F63A9164A1442DA843FCFC3752B366BC3DE27819C41C44426C80203AB8BB511D93AEA55AD70CC31A5A989FC413").unwrap()),
        }
    };

    // Similarly, defining RFC5114_MODP_2048_224_BIT_PARAMS as a lazy static variable, which contains group parameters for a 2048-bit MODP group with 224-bit Prime Order Subgroup.
    // Reference: https://www.rfc-editor.org/rfc/rfc5114.html#section-3
    pub static ref RFC5114_MODP_2048_224_BIT_PARAMS: GroupParams<BigUint> = {
        GroupParams {
            p: BigUint::from_bytes_be(&hex::decode("AD107E1E9123A9D0D660FAA79559C51FA20D64E5683B9FD1B54B1597B61D0A75E6FA141DF95A56DBAF9A3C407BA1DF15EB3D688A309C180E1DE6B85A1274A0A66D3F8152AD6AC2129037C9EDEFDA4DF8D91E8FEF55B7394B7AD5B7D0B6C12207C9F98D11ED34DBF6C6BA0B2C8BBC27BE6A00E0A0B9C49708B3BF8A317091883681286130BC8985DB1602E714415D9330278273C7DE31EFDC7310F7121FD5A07415987D9ADC0A486DCDF93ACC44328387315D75E198C641A480CD86A1B9E587E8BE60E69CC928B2B9C52172E413042E9B23F10B0E16E79763C9B53DCF4BA80A29E3FB73C16B8E75B97EF363E2FFA31F71CF9DE5384E71B81C0AC4DFFE0C10E64F").unwrap()),
            q: BigUint::from_bytes_be(
                &hex::decode("801C0D34C58D93FE997177101F80535A4738CEBCBF389A99B36371EB").unwrap(),
            ),
            g: BigUint::from_bytes_be(&hex::decode("AC4032EF4F2D9AE39DF30B5C8FFDAC506CDEBE7B89998CAF74866A08CFE4FFE3A6824A4E10B9A6F0DD921F01A70C4AFAAB739D7700C29F52C57DB17C620A8652BE5E9001A8D66AD7C17669101999024AF4D027275AC1348BB8A762D0521BC98AE247150422EA1ED409939D54DA7460CDB5F6C6B250717CBEF180EB34118E98D119529A45D6F834566E3025E316A330EFBB77A86F0C1AB15B051AE3D428C8F8ACB70A8137150B8EEB10E183EDD19963DDD9E263E4770589EF6AA21E7F5F2FF381B539CCE3409D13CD566AFBB48D6C019181E1BCFE94B30269EDFE72FE9B6AA4BD7B5A0F1C71CFFF4C19C418E1F6EC017981BC087F2A7065B384B890D3191F2BFA").unwrap()),
            h: BigUint::from_bytes_be(&hex::decode("2B08F613407C962D9625F571A9D42CBB9076B11751076EA2EC11B8A88F331BEB20020E310AAF2BC1B4AD60718367E684C488826E1853202A7F51A706A0C524C748D87B70B8AE6796FD36278412E01E55583C9C59D333DD6D5FC9A46724043165EFFB5C5F2A02E0FFC436E475B600B0B32C8657697CB56235BA2EA0570859FEAB405BA17ECA75F9FDFCF64FBE3F81C6228D8454B7B96B92815C44C140B7FB92A32E970DB6379D50079591A1C812DCD554F3DA6EF4079381EDAEBC5DF78BC882FAF701B2DF6CBA88601746B3AF0CFEBFEFEE3E723B47D20B6F828DBC40221CD979915811BB43FD087CB9416CB1279B852697544CCF5B404E587563E9A76F52AE8A").unwrap()),
        }
    };

    // Similarly, defining RFC5114_MODP_2048_256_BIT_PARAMS as a lazy static variable, which contains group parameters for a 2048-bit MODP group with 256-bit Prime Order Subgroup.
    // Reference: https://www.rfc-editor.org/rfc/rfc5114.html#section-3
    pub static ref RFC5114_MODP_2048_256_BIT_PARAMS: GroupParams<BigUint> = {
        GroupParams {
            p: BigUint::from_bytes_be(&hex::decode("87A8E61DB4B6663CFFBBD19C651959998CEEF608660DD0F25D2CEED4435E3B00E00DF8F1D61957D4FAF7DF4561B2AA3016C3D91134096FAA3BF4296D830E9A7C209E0C6497517ABD5A8A9D306BCF67ED91F9E6725B4758C022E0B1EF4275BF7B6C5BFC11D45F9088B941F54EB1E59BB8BC39A0BF12307F5C4FDB70C581B23F76B63ACAE1CAA6B7902D52526735488A0EF13C6D9A51BFA4AB3AD8347796524D8EF6A167B5A41825D967E144E5140564251CCACB83E6B486F6B3CA3F7971506026C0B857F689962856DED4010ABD0BE621C3A3960A54E710C375F26375D7014103A4B54330C198AF126116D2276E11715F693877FAD7EF09CADB094AE91E1A1597").unwrap()),
            q: BigUint::from_bytes_be(
                &hex::decode("8CF83642A709A097B447997640129DA299B1A47D1EB3750BA308B0FE64F5FBD3").unwrap(),
            ),
            g: BigUint::from_bytes_be(&hex::decode("3FB32C9B73134D0B2E77506660EDBD484CA7B18F21EF205407F4793A1A0BA12510DBC15077BE463FFF4FED4AAC0BB555BE3A6C1B0C6B47B1BC3773BF7E8C6F62901228F8C28CBB18A55AE31341000A650196F931C77A57F2DDF463E5E9EC144B777DE62AAAB8A8628AC376D282D6ED3864E67982428EBC831D14348F6F2F9193B5045AF2767164E1DFC967C1FB3F2E55A4BD1BFFE83B9C80D052B985D182EA0ADB2A3B7313D3FE14C8484B1E052588B9B7D2BBD2DF016199ECD06E1557CD0915B3353BBB64E0EC377FD028370DF92B52C7891428CDC67EB6184B523D1DB246C32F63078490F00EF8D647D148D47954515E2327CFEF98C582664B4C0F6CC41659").unwrap()),
            h: BigUint::from_bytes_be(&hex::decode("5AAD0D96AC4DDE50F71307E4F9FF1E1FC0CC2DA0B81402FCCDB6DC541F3693B82499073C613C922F7275EE228B5426FBB6D6290411BA8FA5315F340DBC3D08A18A0644118C280DB17E33B9E7996D4920F911648DB55E242183ABAB41C1F0E0F9BE3DC0A10728E8B3A0D1E2F2C671013D0787B727E5B4C565FBA7F1F3E7274D565B701D2BB0A3936D70D81806FAE9453541684AFE105BADA312424CEF301B6D4FB7B04BF768A71F56AA3C19C51504EDC70DE7E43676B01EFA618DFDE2B9C00018285E0E7E2FFF3EC3FDAC8CC496D48750603CDD59B784B110F85271C2CE3D604FF7644A96B1FB32C12D3DD3B237E81A9997D6A79D738E64080957E2AB0EBA8B61").unwrap()),
        }
    };

    // Defining `EC25519_GROUP_PARAMS` as a lazy static variable. This variable represents the group parameters for the elliptic curve Curve25519, specifically for the Ristretto group.
    pub static ref EC25519_GROUP_PARAMS: GroupParams<RistrettoPoint> = {
        GroupParams::<RistrettoPoint> {
            g: RistrettoPoint::convert_from(
                &hex::decode("2aea1fc8034016ac0e9be8c357421a6a3afba883fd10d0f842f4ef6df6fb347a").unwrap()
            )
            .unwrap().to_owned(),
            h: RistrettoPoint::convert_from(
                &hex::decode("ae0855e254e43f00ad816c82b3a801f9995fe0717c826eb776b7a29f13e04c78").unwrap()
            )
            .unwrap().to_owned(),
            p: RISTRETTO_BASEPOINT_POINT.to_owned(),
            q: RISTRETTO_BASEPOINT_POINT.to_owned(),
        }
    };

    pub static ref PALLAS_GROUP_PARAMS: GroupParams<Point> = {
        //use pasta_curves::group::GroupEncoding;
        GroupParams::<Point> {
            g: Point::convert_from(
                convert(&hex::decode("f9abd1b1a37af310baa363ed031ef5613fb474f1780dc8fc767c2b1480da582b").unwrap()).unwrap()
            ).unwrap(),
            h: Point::convert_from(
                convert(&hex::decode("8f1339a6e025db7854f67838a42764b870e85e991e7b2e6570c5e5fee6e5c30c").unwrap()).unwrap()
            ).unwrap(),
            p: Point::convert_from(
                convert(&hex::decode("00000000ed302d991bf94c09fc98462200000000000000000000000000000040").unwrap()).unwrap()
            ).unwrap(),
            q: Point::convert_from(
                convert(&hex::decode("00000000ed302d991bf94c09fc98462200000000000000000000000000000040").unwrap()).unwrap()
            ).unwrap(),
        }
    };

}

fn convert(vec: &Vec<u8>) -> Result<&[u8; 32], &'static str> {
    if vec.len() == 32 {
        let slice: &[u8; 32] = vec
            .as_slice()
            .try_into()
            .expect("Slice with incorrect length");
        Ok(slice)
    } else {
        Err("Vector does not have exactly 32 elements")
    }
}
// Implementing the FromStr trait for GroupParams<BigUint>. This allows for creating GroupParams<BigUint> instances from string slices.
impl FromStr for GroupParams<BigUint> {
    type Err = (); // Defining the error type as a unit type.

    // Implementing the from_str method which takes a string slice and returns a Result.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            // Matching specific strings and returning corresponding predefined group parameters.
            "rfc5114_modp_1024_160" => Ok(RFC5114_MODP_1024_160_BIT_PARAMS.to_owned()),
            "rfc5114_modp_2048_224" => Ok(RFC5114_MODP_2048_224_BIT_PARAMS.to_owned()),
            "rfc5114_modp_2048_256" => Ok(RFC5114_MODP_2048_256_BIT_PARAMS.to_owned()),
            _ => Err(()), // Returning an error for unrecognized strings.
        }
    }
}

// Implementing the FromStr trait for GroupParams<RistrettoPoint>. This allows for creating GroupParams<RistrettoPoint> instances from string slices.
impl FromStr for GroupParams<RistrettoPoint> {
    type Err = (); // Defining the error type as a unit type.

    // Implementing the from_str method which takes a string slice and returns a Result.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            // Matching the string "ec25519" and returning the corresponding group parameters.
            "ec25519" => Ok(EC25519_GROUP_PARAMS.to_owned()),
            _ => Err(()), // Returning an error for unrecognized strings.
        }
    }
}

//
impl FromStr for GroupParams<Point> {
    type Err = (); // Defining the error type as a unit type.

    // Implementing the from_str method which takes a string slice and returns a Result.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            // Matching the string "ec25519" and returning the corresponding group parameters.
            "pallas" => Ok(PALLAS_GROUP_PARAMS.to_owned()),
            _ => Err(()), // Returning an error for unrecognized strings.
        }
    }
}
