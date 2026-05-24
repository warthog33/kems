use elliptic_curve::PrimeField;
use hex_literal::hex;
use kdfs::ansi_x9_63::X963Kdf;
use kems::{Capsulator, EncapsulateDeterministic2, Decapsulate, eckem::{EcRawEncoder, EcdhKem}, kem_with_kdf::{CombinerNoKeys, KemWithKdf}};
use kems::generic_array::{GenericArray, typenum::consts::U32};

#[cfg(feature="rustcrypto-p521")]
use p521::NistP521;
#[cfg(feature="rustcrypto-sha2")]
use sha2::Sha512;


//mod common;
//use common::PredictableRng;

#[cfg(feature="rustcrypto-p521")]
#[test]
/// Test from Nexo Card Security Spec 4.0
fn test_ecdh () 
{

    let static_d = "4054254801738479901853562403503006018363132444973935480756155609729444288428596934864100012430463475006671101545803516444395424250329488194978695722509565146";

    let ephem_d = hex!("00003E50B1DCCF6A7BF43BD02FA8019753D5B62BDE85DDEDF16ABC28F308EDF153842719C7E2518692A86391204E5CB72B5C34E0FEC8C7C3F85831A2B9D993BCF325");

    let ephem_pub = hex!("0066276B9FE9086A9B824A26AE8050AFD581CCCB8D7515102A849B9FF3B2B3311560FB5E23EAF18A601EA3E7A98C47228CD2F3B3391DA035C41C54EFC1CB56F21F1E"
                                    "015980343BDA76D762CE6A875994CB677821125F1CCA943A58A828BF1A8A3DF8CD1C451FB529DF7C4E363407ED66922B6A9FB7262B210732989A1D487CB21D8D2894");

    let key = hex!("D0CD1EC88A646ED9AE24CB58EAB618BB85CAFF500BE1B641A35C44B1CCF57923");

                                    let st = p521::Scalar::from_str_vartime(static_d).unwrap();
    let d = p521::SecretKey::from_scalar(st).unwrap();

    //let ephem_key = p521::SecretKey::from_bytes(&ephem_d.into()).unwrap();

    let encapsulator = KemWithKdf::<EcdhKem<NistP521, EcRawEncoder<NistP521>>, CombinerNoKeys, X963Kdf<Sha512>, U32>::new_encapsulator(d.public_key());
    //let mut pred_rng = PredictableRng::new(&ephem_d);
    //let (ephem_pub2, key3) = encapsulator.encapsulate(&mut pred_rng ).unwrap();
    let (ephem_pub2, key3) = encapsulator.encapsulate_deterministic(&ephem_d ).unwrap();

    assert_eq!(ephem_pub2.as_slice(), &ephem_pub);
    assert_eq!(key3, key);

    let decapsulator = KemWithKdf::<EcdhKem<NistP521, EcRawEncoder<NistP521>>, CombinerNoKeys, X963Kdf<Sha512>, U32>::new_decapsulator(d);

    let key2 = decapsulator.decapsulate(&GenericArray::from_slice(&ephem_pub)).unwrap();

    assert_eq!(key2, key)


}

