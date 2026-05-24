use base64::Engine;
use der::{Any, Choice, Decode, Length, Sequence, asn1::{BitString, OctetString}};
use elliptic_curve::Error;
use hex_literal::hex;

#[cfg(feature="rustcrypto-ml-kem")]
use ml_kem::{EncodedSizeUser, kem::Decapsulate};

// ML-KEM-PrivateKey ::= CHOICE {
//   seed [0] IMPLICIT OCTET STRING (SIZE (64)),
//   expandedKey OCTET STRING (SIZE (1632 | 2400 | 3168)),
//   both SEQUENCE {
//     seed OCTET STRING (SIZE (64)),
//     expandedKey OCTET STRING (SIZE (1632 | 2400 | 3168)) } }
#[derive(Clone, Debug, Eq, PartialEq, Choice)]
enum MlKeyPrivateKeyChoice {
    #[asn1(context_specific = "0", tag_mode = "IMPLICIT")]
    Seed(OctetString),
    ExpandedKey(OctetString),
    Both(SeedAndExpandedKey), //both(Any),
}

// #[derive(Clone, Debug, Eq, PartialEq, Sequence)]
// struct MlKeyPrivateKeyChoice2 {
//     one: Any,
//     // #[asn1(context_specific = "0", tag_mode = "IMPLICIT")]
//     // Seed(OctetString),
//     // ExpandedKey(OctetString),
//     // Both(SeedAndExpandedKey), //both(Any),
// }

// impl DecodeOwned for MlKeyPrivateKeyChoice {
    
// }
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
struct SeedAndExpandedKey 
{
    seed: OctetString,
    expanded_key: OctetString,
}

// #[derive(Clone, Debug, Eq, PartialEq, Sequence)]
// pub struct PrivateKeyInfo
// {
//     pub version: rsa::pkcs1::Version,

// ///         privateKeyAlgorithm       PrivateKeyAlgorithmIdentifier,
// ///         privateKey                PrivateKey,
// ///         attributes           [0]  IMPLICIT Attributes OPTIONAL }
// /// 
//     /// X.509 `AlgorithmIdentifier` for the private key type.
//     pub algorithm: AlgorithmIdentifier<Any>, //<Params>,

//     /// Private key data. Exact content format is different between algorithms.
//     pub private_key: Any,

//     // Public key data, optionally available if version is V2.
//     pub public_key: Option<Any>,
// }


//
// openssl genpkey -algorithm ML-KEM-512 -out ml-kem-private-key.pem
// openssl pkey -in ml-kem-private-key.pem -pubout -out ml-kem-public-key.pem
// openssl pkeyutl -encap -pubin -inkey ml-kem-public-key.pem -secret ss1.dat -out ctext.dat
//
#[cfg(feature="rustcrypto-rsa")]
#[test]
fn test_ml_kem_512 () -> Result<(), Error>{
    use der::DecodePem;


    let private_key = "-----BEGIN PRIVATE KEY-----\n\
        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\n\
        ORM=\n\
        -----END PRIVATE KEY-----";

    let public_key = "-----BEGIN PUBLIC KEY-----\n\
        MIIDMjALBglghkgBZQMEBAEDggMhAFF7Sa6kMQuhLr1CcIJaDORUBQ5qE+6WExLV\n\
        lIAAjlmqZ5ibav2Ht64GWYVwI2CxS8WBJq1AIz5qwuzIHi/QJRnGL132SJ/EI+lI\n\
        x3lluVKKdawgO+vyzqYynbADIrGMmRvqkt/3bqZYycZHUTrAQuMJicBKIXhkvi3U\n\
        pRRoPlNZiy5mlsLDgChnrZ+0FoojfUyntQA4ND4xPEApWiU3QATjQ+0nGTCrcta4\n\
        kxzCKIIIYZ8Ii5Rcd+ULJ9A5sf3VFA3cexmSltFhsf9qwqysKXMZUpYCWu5ArFZk\n\
        Ewt4vCF8vpFJu0j6E0dgB8xCel65hSsFGJ77IcM0uBTrBIOUvFwGSAomB89Ux5g0\n\
        UdCWxLlUTNsiaMrFpIRnJLIZfmiTwCTFvEDpgFVRw4uocQN2Zi7RrCVHDpfWgokQ\n\
        gHYHYu4BU1kgyf1Vkyh7XBykbGwVoThCEXG6J3kHoZ9xVfVUYmigvbwarN9JI0C4\n\
        KEexU7X6IkhWxFVXP6/UYgOBuABBWcFHJYNLm820va+FrBZRlxJxPngyUzilXHKY\n\
        moQrRN01Rbl1fmd0anrhKDFLCULRJmuFeJtzYiOLzRlGBP90LhGQVe+goBoSfRz1\n\
        chGhI0rXUCYXGBKhob3TLnsTGswpqfuGQD8hLeDaIp/kC7VZU47gJAv4cAvpQuM3\n\
        C2rYlHtgsAaJE8d0ppAgcdx1vi0ykVGBSCH7nFkrpLpxDxdlLCQjAq3gE8HWJOpC\n\
        a2Cohmtlr81CKiDipGsxqj0rR5golWlZg1oEOvDjz7+bye2QV0x7eV/5AUHXV9IF\n\
        K4AkAQ+5CRzzU2O2lH8bI4LoUS+Ihn7QxOsWABrorsdAp8Q2jsRQsjMFXooSUdJx\n\
        z/yGdVkBiD8GX0EJSGmpz7ypvFeKjMwaxWaymsdDUEKDH9bbNhiomHS3BGHwnnQk\n\
        B+dlxHZpZRNCvQYCKA74f3OzOcvLUi+yNgzjbkugANr7oiVzsSR8KEhAS7gcfVi8\n\
        PYJDgf2KFrurnwvFQ2knOoAgQC2IsaoZI2qZ4YtGYt5TaJgmT/1qU1w9gHW5eyPL\n\
        8JgKEeRV\n\
        -----END PUBLIC KEY-----";

    let ct = "pkBk4rtVACl9VYzXaw5zQjiAdSNFW8szeqbX6qMbFfVhGnaTiSyaByFTVGQrcmqveJ8TuaQ+bNmjAGIdZlT66Xd1OOmC+JpvoVp+Wwb9/S7eHLg9/WPScTXl2DT6JPnqlff+YAfvfUGv/VEFT+I/jwRw35VOIGri9EvZhnWLWvyVjIySKJJ/oOb7US5hwts8tp97tGyy/diQ6FHKbglsMPku0tOgMCWyQVWyU0Rcm4w6zceVWoAAvZSdKGV/mDbWsbT9bIrvtInlEiCxAgTlp51uPc8Ypmb0wBsVbA7PbcYT2k2L2JE7k671vIeuzFsorkPq18piPWpj0m5+BLTV2OLfL8cC/1hoG9ERvxKYrQ6fI5QUoq4EdFnFip8WCNroXmW5mYWUFpPOLTXCSdB4UOXEZSSOYDdr1xgR7bGIDt4dvlIOb+5VCebovalUQRT2I+qE6aDP76wUf2D7VTUNO4G3/3cNkhydE/zC3EajERxsygCGLhjR1vrGC7vRMiPcPMDUZO3CiX0AhEw9Sb55X8jjcEs+RKDdKVnLEaR5v7OrL+m4qzQT81+qUpNskSvQzXdOrUbWIAc59YbLibHj3NrU5LOR4/kgxmMpy6bb1fz7kXRNXnvbqkxQg7GsagUHyzpOtEHezKCaYsYUji3+7sdmvhX4H43A8L12qRjWU3rXHXGFJvO5wBI3G5IeZM84ASgl1hpPoF8DRRWOtqsV7YwLmPp53+XAjkkvJcsd8sDAPVHQo+lAm4mWioIkty8/jl/UKZSq8Qz4DdimHNn35tO9BTUlvak83UscDx7s91GRIW6I35sPVtwgIrxf/WnRzL0ZC93aMFs8qfSTJKaJOQxnoL629LJykbQvZ70RX4X3rsmLvwhXnldHoEj1Fow2mOuqO1hqyTNUAGxpJwgBm+VSXlohtWi0Wmp5OSePRQpowKDGFSf+VSvjtJ+ffiOg7xUo7EgzVPycK7YXLimhrsWKlVcyosvx+Jr40aF++6jBJVmB7ZmS+kIiqEFoHv0c";
    let ss = hex! ( "72ff 5a7f fde5 bfe1 91c7 6a64 038e f8ab 6a39 f8c6 ef73 6d42 690c 87a7 5782 1500");
    
    let priv_key_3 = rsa::pkcs8::PrivateKeyInfo::<Any, OctetString, BitString>::from_pem(private_key).unwrap();
    
    let mlkem_private_key_choice = MlKeyPrivateKeyChoice::from_der(priv_key_3.private_key.as_bytes()).unwrap();

    let MlKeyPrivateKeyChoice::Both(seed_and_expanded_key) = mlkem_private_key_choice else { panic!("bb") };
    assert_eq! (seed_and_expanded_key.seed.len(), Length::new(64));
    assert_eq! (seed_and_expanded_key.expanded_key.len(), Length::new(1632));
    
    let public_key2 = rsa::pkcs8::SubjectPublicKeyInfo::<Any, BitString>::from_pem(public_key).unwrap();
    assert_eq! ( public_key2.subject_public_key.as_bytes().unwrap().len(), 800);

    let ct = base64::engine::general_purpose::STANDARD.decode(ct).unwrap();
    assert_eq! ( ct.len(), 768);

    let decapsulator = <ml_kem::kem::Kem<ml_kem::MlKem512Params> as ml_kem::KemCore>::DecapsulationKey::from_bytes(&seed_and_expanded_key.expanded_key.as_bytes().try_into().unwrap());

    
    let ss2 = decapsulator.decapsulate(&ct.as_slice().try_into().unwrap()).unwrap();

    assert_eq! ( ss2, ss);

    Ok(())

}


// openssl genpkey -algorithm X25519MLKEM768 -out hybrid_key.pem
