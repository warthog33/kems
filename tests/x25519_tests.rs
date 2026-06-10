use cipher::typenum::consts::U16;
use kdfs::iso18033_2::Kdf1;
use kdfs::hybrid_array::Array;
use kems::{Capsulator,Encapsulate, Decapsulate};
use kems::generic_array::{GenericArray, typenum::{U32}};
use kems::eckem::SeedAsScalar;
use kems::kem_with_kdf::{KemWithKdf, CombinerAllPubKeys};
use kems::x25519kem::X25519Capsulator;
use kems::x448kem::X448Capsulator;
use rand_core::OsRng;
use sha2::Sha256;
use x25519_dalek::{StaticSecret, PublicKey};
use kems::{kem_with_kdf::KemAuthWithKdf, x25519kem::X25519AuthCapsulator};
use kems::x448kem::X448AuthCapsulator;


#[test]
fn simple_x25519_kem () 
{
    let recipient_secret_key = StaticSecret::random_from_rng(&mut OsRng);
    let recipient_public_key = PublicKey::from(&recipient_secret_key);

    let encapsulator = KemWithKdf::<X25519Capsulator::<SeedAsScalar>, CombinerAllPubKeys, Kdf1::<Sha256>,U16>::from_public_key(recipient_public_key);
    
    let (c0_send, k_send) = encapsulator.encapsulate(&mut OsRng).unwrap();
    
    let decapsulator = KemWithKdf::<X25519Capsulator<SeedAsScalar>, CombinerAllPubKeys, Kdf1::<Sha256>, U16>::from_private_key(recipient_secret_key);
    let k_recv: Array<u8, U16> = decapsulator.decapsulate(&c0_send).unwrap();

    assert_eq! ( k_send.as_slice(), k_recv.as_slice());
}


#[test]
fn auth_x25519_kem () {
    let recipient_secret_key = StaticSecret::random_from_rng(&mut OsRng);
    let recipient_public_key = PublicKey::from(&recipient_secret_key);
    let sender_secret_key = StaticSecret::random_from_rng(&mut OsRng);
    let sender_public_key = PublicKey::from(&sender_secret_key);

    type X25519Kdf1Sha256 = KemAuthWithKdf::<X25519AuthCapsulator<SeedAsScalar>, CombinerAllPubKeys, Kdf1::<Sha256>,U16>;
    let encapsulator = X25519Kdf1Sha256::encap_from_keys(recipient_public_key, sender_secret_key);
    let (c0_send, k_send) = encapsulator.encapsulate(&mut OsRng).unwrap();

    let decapsulator = X25519Kdf1Sha256::decap_from_keys(sender_public_key, recipient_secret_key );
    let k_recv: Array<u8, U16> = decapsulator.decapsulate(&c0_send).unwrap();

    assert_eq! ( k_send.as_slice(), k_recv.as_slice());
}


// Using KEM traits from ML-KEM
#[test]
fn x25519_test_new_kem_traits () {
    
    //let (encapsulator, decapsulator) = X25519Capsulator::<EcCombinerAllPubKeys::<Kdf1::<Sha256>>,U16, SeedAsScalar>::generate(&mut OsRng);
    let (encapsulator, decapsulator) = KemWithKdf::<X25519Capsulator::<SeedAsScalar>, CombinerAllPubKeys, Kdf1::<Sha256>, U16>::generate(&mut OsRng);
    let (ek, ss1): (GenericArray<_,_>, _) = encapsulator.encapsulate(&mut OsRng).unwrap();    
    let ss2 = decapsulator.decapsulate(&ek).unwrap();
    assert_eq!(ss1, ss2);
}


#[test]
fn x448_test_new_kem_traits () {
    let (encapsulator, decapsulator) = KemWithKdf::<X448Capsulator::<SeedAsScalar>, CombinerAllPubKeys, Kdf1::<Sha256>, U16>::generate(&mut OsRng);
    let (ek, ss1) = encapsulator.encapsulate(&mut OsRng).unwrap();    
    let ss2 = decapsulator.decapsulate(&ek).unwrap();

    assert_eq!(ss1, ss2);
}



#[test]
fn x448_test_5 () {
    let sender_secret_key = x448::StaticSecret::from([2u8; 56]); //::random_from_rng(&mut rand_core3::OsRng);
    let sender_public_key = x448::PublicKey::from(&sender_secret_key);
    let recipient_secret_key = x448::StaticSecret::from([3u8; 56]); //new(&mut rand_core3::OsRng);
    let recipient_public_key = x448::PublicKey::from(&recipient_secret_key);

    let auth_encapsulator = KemAuthWithKdf::<X448AuthCapsulator, CombinerAllPubKeys, Kdf1::<Sha256>,U32>::encap_from_keys(recipient_public_key, sender_secret_key);
    let (ct, k_send) = auth_encapsulator.encapsulate(&mut rand_core::OsRng).unwrap();

    let auth_decapsulator = KemAuthWithKdf::<X448AuthCapsulator, CombinerAllPubKeys, Kdf1::<Sha256>, U32>::decap_from_keys(sender_public_key, recipient_secret_key);
    let k_recv = auth_decapsulator.decapsulate(&ct).unwrap();

    assert_eq!(k_send, k_recv);
}