use cipher::typenum::consts::U16;
use kdfs::iso18033_2::Kdf1;
use kdfs::hybrid_array::Array;
use kem::{Decapsulate, Encapsulate, Kem};
use kems::{KemExtensions};
use kems::FromKey;
use kems::kem_with_kdf::{KemWithKdf, CombinerAllPubKeys, KemAuthWithKdf};
use kems::x25519kem::{X25519Kem,X25519AuthKem};
use kems::x448kem::{X448AuthKem,X448Kem};
use p256::U32;
use sha2::Sha256;
use x25519_dalek::{StaticSecret, PublicKey};


#[test]
fn simple_x25519_kem () 
{
    let recipient_secret_key = StaticSecret::random();
    let recipient_public_key = PublicKey::from(&recipient_secret_key);

    //let encapsulator = X25519Capsulator::<SeedAsScalar>::from_public_key(recipient_public_key);
    let encapsulator = <KemWithKdf::<X25519Kem, CombinerAllPubKeys, Kdf1::<Sha256>,U16> as Kem>::EncapsulationKey::from_key(recipient_public_key);
    
    let (c0_send, k_send) = encapsulator.encapsulate();
    
    let decapsulator = <KemWithKdf::<X25519Kem, CombinerAllPubKeys, Kdf1::<Sha256>, U16> as Kem>::DecapsulationKey::from_key(recipient_secret_key);
    let k_recv: Array<u8, U16> = Decapsulate::decapsulate(&decapsulator, &c0_send);

    assert_eq! ( k_send.as_slice(), k_recv.as_slice());
}
#[test]
fn simple_x25519_kem2 () 
{
    let recipient_secret_key = StaticSecret::random();
    let recipient_public_key = PublicKey::from(&recipient_secret_key);

    let encapsulator = <X25519Kem as Kem>::EncapsulationKey::from_key(recipient_public_key);
    
    let (c0_send, k_send) = kem::Encapsulate::encapsulate(&encapsulator);
            
    let decapsulator = <X25519Kem as KemExtensions>::from_private_key(recipient_secret_key);

    //let k_recv = ml_kem::Decapsulate::decapsulate(&decapsulator, &c0_send);
    let k_recv = kem::TryDecapsulate::try_decapsulate(&decapsulator, &c0_send).unwrap();

    assert_eq! ( k_send.as_slice(), k_recv.as_slice());
}
#[test]
fn simple_x25519_kem3 () 
{
    let recipient_secret_key = StaticSecret::random();
    let recipient_public_key = PublicKey::from(&recipient_secret_key);

    let encapsulator = <KemWithKdf::<X25519Kem, CombinerAllPubKeys, Kdf1::<Sha256>,U16> as Kem>::EncapsulationKey::from_key(recipient_public_key);
    
    // Use traits from rustcrypto kem 0.3.0
    let (c0_send, k_send) = kem::Encapsulate::encapsulate(&encapsulator);
            
    let decapsulator = <KemWithKdf::<X25519Kem, CombinerAllPubKeys, Kdf1::<Sha256>,U16> as Kem>::DecapsulationKey::from_key(recipient_secret_key);

    //let k_recv = ml_kem::Decapsulate::decapsulate(&decapsulator, &c0_send);
    let k_recv = Decapsulate::decapsulate(&decapsulator, &c0_send.0.into());
    assert_eq! ( k_send.as_slice(), k_recv.as_slice());

    let k_recv2 = ml_kem::kem::TryDecapsulate::try_decapsulate(&decapsulator, &c0_send).unwrap();
    assert_eq! ( k_send.as_slice(), k_recv2.as_slice());
    
}


#[test]
fn auth_x25519_kem () {
    let recipient_secret_key = StaticSecret::random();
    let recipient_public_key = PublicKey::from(&recipient_secret_key);
    let sender_secret_key = StaticSecret::random();
    let sender_public_key = PublicKey::from(&sender_secret_key);

    type X25519Kdf1Sha256 = KemAuthWithKdf::<X25519AuthKem, CombinerAllPubKeys, Kdf1::<Sha256>,U16>;
    let encapsulator = X25519Kdf1Sha256::encap_from_keys(recipient_public_key, sender_secret_key);
    let (c0_send, k_send) = encapsulator.encapsulate();

    let decapsulator = X25519Kdf1Sha256::decap_from_keys(sender_public_key, recipient_secret_key );
    let k_recv: Array<u8, U16> = decapsulator.decapsulate(&c0_send);

    assert_eq! ( k_send.as_slice(), k_recv.as_slice());
}


// Using KEM traits from ML-KEM
#[test]
fn x25519_test_new_kem_traits () {
    
    //let (encapsulator, decapsulator) = X25519Capsulator::<EcCombinerAllPubKeys::<Kdf1::<Sha256>>,U16, SeedAsScalar>::generate(&mut OsRng);
    let (decapsulator,encapsulator ) = KemWithKdf::<X25519Kem, CombinerAllPubKeys, Kdf1::<Sha256>, U16>::generate_keypair();
    let (ek, ss1)  = encapsulator.encapsulate();
    let ss2 = decapsulator.decapsulate(&ek);
    assert_eq!(ss1, ss2);
}


#[test]
fn x448_test_new_kem_traits () {
    let (decapsulator, encapsulator) = KemWithKdf::<X448Kem, CombinerAllPubKeys, Kdf1::<Sha256>, U16>::generate_keypair();
    let (ek, ss1) = encapsulator.encapsulate(); 
    let ss2 = decapsulator.decapsulate(&ek);

    assert_eq!(ss1, ss2);
}



#[test]
fn x448_test_5 () {
    let sender_secret_key = x448::StaticSecret::from([2u8; 56]); //::random_from_rng(&mut rand_core3::OsRng);
    let sender_public_key = x448::PublicKey::from(&sender_secret_key);
    let recipient_secret_key = x448::StaticSecret::from([3u8; 56]); //new(&mut rand_core3::OsRng);
    let recipient_public_key = x448::PublicKey::from(&recipient_secret_key);

    let auth_encapsulator = KemAuthWithKdf::<X448AuthKem, CombinerAllPubKeys, Kdf1::<Sha256>,U32>::encap_from_keys(recipient_public_key, sender_secret_key);
    let (ct, k_send) = auth_encapsulator.encapsulate();

    let auth_decapsulator = KemAuthWithKdf::<X448AuthKem, CombinerAllPubKeys, Kdf1::<Sha256>, U32>::decap_from_keys(sender_public_key, recipient_secret_key);
    let k_recv = auth_decapsulator.decapsulate(&ct);

    assert_eq!(k_send, k_recv);
}