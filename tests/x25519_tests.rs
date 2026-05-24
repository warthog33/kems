use cipher::typenum::consts::U16;
use kdfs::iso18033_2::Kdf1;
use kdfs::hybrid_array::Array;
use kems::{Capsulator,Encapsulate, Decapsulate};
use kems::generic_array::{GenericArray, typenum::{U32}};
use kems::{eckem::{SeedAsScalar}, kem_with_kdf::{KemWithKdf, CombinerAllPubKeys}};
use rand_core::OsRng;
#[cfg(feature="rustcrypto-x25519")]
use kems::x25519kem::X25519Capsulator;
#[cfg(feature="rustcrypto-x448")]
use kems::x448kem::X448Capsulator;
#[cfg(feature="rustcrypto-sha2")]
use sha2::Sha256;
#[cfg(feature="rustcrypto-x25519")]
use x25519_dalek::{StaticSecret, PublicKey};


#[test]
#[cfg(all(feature="rustcrypto-sha2", feature="rustcrypto-x25519"))]
fn simple_x25519_kem () 
{
    let recipient_secret_key = StaticSecret::random_from_rng(&mut OsRng);
    let recipient_public_key = PublicKey::from(&recipient_secret_key);

    //let encapsulator = X25519Encapsulator::<EcCombinerAllPubKeys::<Kdf1::<Sha256>>,U16>::from_bytes(recipient_public_key.as_bytes().into());
    let encapsulator = KemWithKdf::<X25519Capsulator::<SeedAsScalar>, CombinerAllPubKeys, Kdf1::<Sha256>,U16>::new_encapsulator(recipient_public_key);
    

    let (c0_send, k_send) : (GenericArray<_,_>, _) = encapsulator.encapsulate(&mut OsRng).unwrap();
    //let c0 = c0_send.as_slice();
    //let c0_recv = GenericArray::from_slice(c0);
    //let decapsulator = X25519Decapsulator::<EcCombinerAllPubKeys::<Kdf1::<Sha256>>>::from_bytes(recipient_secret_key.as_bytes().into());
    let decapsulator = KemWithKdf::<X25519Capsulator<SeedAsScalar>, CombinerAllPubKeys, Kdf1::<Sha256>, U16>::new_decapsulator(recipient_secret_key);
    let k_recv: Array<u8, U16> = decapsulator.decapsulate(&c0_send).unwrap();

    assert_eq! ( k_send.as_slice(), k_recv.as_slice());
}


#[test]
#[cfg(all(feature="rustcrypto-sha2", feature="rustcrypto-x25519"))]
fn auth_x25519_kem () {
    use kems::{kem_with_kdf::KemAuthWithKdf, x25519kem::X25519AuthCapsulator};

    
    let recipient_secret_key = StaticSecret::random_from_rng(&mut OsRng);
    let recipient_public_key = PublicKey::from(&recipient_secret_key);
    let sender_secret_key = StaticSecret::random_from_rng(&mut OsRng);
    let sender_public_key = PublicKey::from(&sender_secret_key);

    //let encapsulator = X25519AuthEncapsulator::<EcCombinerAllPubKeys::<Kdf1::<Sha256>>,U16>::from_keys(recipient_public_key, sender_secret_key);
    type X25519Kdf1Sha256 = KemAuthWithKdf::<X25519AuthCapsulator, CombinerAllPubKeys, Kdf1::<Sha256>,U16>;
    let encapsulator = X25519Kdf1Sha256::encap_from_keys(recipient_public_key, sender_secret_key);
    let (c0_send, k_send) = encapsulator.encapsulate(&mut OsRng).unwrap();

    let decapsulator = X25519Kdf1Sha256::decap_from_keys(sender_public_key, recipient_secret_key );
    let k_recv: Array<u8, U16> = decapsulator.decapsulate(&c0_send).unwrap();

    assert_eq! ( k_send.as_slice(), k_recv.as_slice());
}




// Using KEM traits from ML-KEM
#[test]
#[cfg(all(feature="rustcrypto-sha2", feature="rustcrypto-x25519"))]
fn x25519_test_new_kem_traits () {
    
    //let (encapsulator, decapsulator) = X25519Capsulator::<EcCombinerAllPubKeys::<Kdf1::<Sha256>>,U16, SeedAsScalar>::generate(&mut OsRng);
    let (encapsulator, decapsulator) = KemWithKdf::<X25519Capsulator::<SeedAsScalar>, CombinerAllPubKeys, Kdf1::<Sha256>, U16>::generate(&mut OsRng);
    let (ek, ss1): (GenericArray<_,_>, _) = encapsulator.encapsulate(&mut OsRng).unwrap();    
    let ss2 = decapsulator.decapsulate(&ek).unwrap();

    assert_eq!(ss1, ss2);
}


#[test]
#[cfg(all(feature="rustcrypto-sha2", feature="rustcrypto-x448"))]
fn x448_test_new_kem_traits () {
    
    //let (encapsulator, decapsulator) = X448Capsulator::<EcCombinerAllPubKeys::<Kdf1::<Sha256>>,U16>::generate(&mut OsRng);

    let (encapsulator, decapsulator) = KemWithKdf::<X448Capsulator::<SeedAsScalar>, CombinerAllPubKeys, Kdf1::<Sha256>, U16>::generate(&mut OsRng);
    let (ek, ss1) = encapsulator.encapsulate(&mut OsRng).unwrap();    
    let ss2 = decapsulator.decapsulate(&ek).unwrap();

    assert_eq!(ss1, ss2);
}



#[test]
#[cfg(all(feature="rustcrypto-sha2", feature="rustcrypto-x448"))]
fn x448_test_5 () {
    use kems::{kem_with_kdf::KemAuthWithKdf, x448kem::X448AuthCapsulator};
    use x448::{StaticSecret, PublicKey};

    
    let sender_secret_key = StaticSecret::from([2u8; 56]); //::random_from_rng(&mut rand_core3::OsRng);
    //let sender_secret_key = StaticSecret::random_from_rng(thread_rng());
    let sender_public_key = PublicKey::from(&sender_secret_key);
    let recipient_secret_key = StaticSecret::from([3u8; 56]); //new(&mut rand_core3::OsRng);
    let recipient_public_key = PublicKey::from(&recipient_secret_key);

    let auth_encapsulator = KemAuthWithKdf::<X448AuthCapsulator, CombinerAllPubKeys, Kdf1::<Sha256>,U32>::encap_from_keys(recipient_public_key, sender_secret_key);
    //let auth_encapsulator = <KemWithKdfWithCiphertextAndPublicKey::<X448AuthEncapsulator<EcCombinerNoPubKeys<PassThroughKdf>, U32>, Kdf1::<Sha256>, U32> as Capsulator>::Encapsulator::from_keys(recipient_public_key, sender_secret_key);
    let (ct, k_send) = auth_encapsulator.encapsulate(&mut rand_core::OsRng).unwrap();

    let auth_decapsulator = KemAuthWithKdf::<X448AuthCapsulator, CombinerAllPubKeys, Kdf1::<Sha256>, U32>::decap_from_keys(sender_public_key, recipient_secret_key);
    let k_recv = auth_decapsulator.decapsulate(&ct).unwrap();

    assert_eq!(k_send, k_recv);
 
}