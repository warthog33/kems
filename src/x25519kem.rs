//!
//! Implementation of a Key Encapsulation Mechanism using x25519 (pure rust implementation, x25519_dalek)
//! This module implements the KEM traits from the rustcrypto project
//! 
//! ```
//! use cipher::typenum::consts::U32;
//! use sha2::Sha256;
//! use rand_core::OsRng;
//! use kems::x25519kem::{X25519Encapsulator, X25519Decapsulator, X25519Capsulator};
//! use kems::eckem::{SeedAsScalar};
//! use kems::{Capsulator,FromKey, Encapsulate, Decapsulate, kem_with_kdf::{CombinerAllPubKeys, KemWithKdf}};
//! use kdfs::iso18033_2::Kdf1;
//! use x25519_dalek::{StaticSecret, PublicKey};
//! 
//! let recipient_secret_key = StaticSecret::random_from_rng(&mut OsRng);
//! let recipient_public_key = PublicKey::from(&recipient_secret_key);
//! 
//! let (encapsulator, decapsulator) = KemWithKdf::<X25519Capsulator<SeedAsScalar>, CombinerAllPubKeys, Kdf1::<Sha256>, U32>::generate_from_rng(&mut OsRng);
//! 
//! let (c0_send, k_send) = encapsulator.encapsulate(&mut OsRng).unwrap();
//!  
//! let (k_recv) = decapsulator.decapsulate(&c0_send).unwrap();
//! assert! ( k_send == k_recv);
//! ```
//! 
//! The example below shows the authenticated mode which uses two diffie hellman operations and concatenates the outptus
//! 
//! ```
//! use cipher::typenum::consts::U32;
//! use kems::x25519kem::X25519AuthCapsulator;
//! use rand_core::OsRng;
//! use kems::{Encapsulate, Decapsulate, FromKey, FromKeys, kem_with_kdf::{KemAuthWithKdf, CombinerAllPubKeys}};
//! use kdfs::iso18033_2::Kdf1;
//! use sha2::Sha256;
//! use x25519_dalek::{StaticSecret, PublicKey};
//! 
//! let sender_secret_key = StaticSecret::random_from_rng(&mut OsRng);
//! let sender_public_key = PublicKey::from(&sender_secret_key);
//! let recipient_secret_key = StaticSecret::random_from_rng(&mut OsRng);
//! let recipient_public_key = PublicKey::from(&recipient_secret_key);
//! 
//! let auth_encapsulator = KemAuthWithKdf::<X25519AuthCapsulator, CombinerAllPubKeys, Kdf1::<Sha256>,U32>::encap_from_keys(recipient_public_key, sender_secret_key);
//! let (c0, k_send) = auth_encapsulator.encapsulate(&mut OsRng).unwrap();
//!
//! let auth_decapsulator = KemAuthWithKdf::<X25519AuthCapsulator, CombinerAllPubKeys, Kdf1::<Sha256>, U32>::decap_from_keys(sender_public_key, recipient_secret_key);
//! let k_recv = auth_decapsulator.decapsulate(&c0).unwrap();
//! assert!( k_send == k_recv);
//! ```

use std::borrow::Cow;
use std::convert::Infallible;
use std::marker::PhantomData;
use crate::{Capsulator, CryptoRngCore, Decapsulate, Encapsulate, EncapsulateDeterministic2, FromKey, FromKeys, GenerateDeterministic2, GenerateDeterministic3, GenerateDeterministic4, GetEncapsulator, GetRecipientPublicKeyBytes, GetSenderPublicKeyBytes};
use crate::eckem::{SeedAsScalar};
use generic_array::{GenericArray};
use generic_array::typenum::Unsigned;
use cipher::KeySizeUser;
use cipher::common::KeyExport;
use cipher::typenum::consts::*;
use ml_kem::{Kem, TryKeyInit};
use std::array::TryFromSliceError;
use hmac::KeyInit;
use kdfs::hybrid_array::Array;
use x25519_dalek::{PublicKey, StaticSecret};


impl GenerateDeterministic2<StaticSecret> for SeedAsScalar 
{
    type SeedSize = U32;
    //type PublicKey = PublicKey;
    //type Private = StaticSecret;
    type Error = std::array::TryFromSliceError;
    
    //fn generate_deterministic2( seed: &[u8]) -> Result<(StaticSecret, PublicKey), Self::Error> {
    fn generate_deterministic2( seed: &[u8]) -> Result<StaticSecret, Self::Error> {
        let seed_array: [u8;32] = seed.try_into()?;
        let priv_key = StaticSecret::from(seed_array);
        //let pub_key = PublicKey::from(&priv_key);
        Ok(priv_key)
    }
}


/// Factory struct used to create X25519Encapsulator and X25519Decapsulators
#[derive(PartialEq,Ord,PartialOrd,Eq,Default,Copy,Clone,Debug)]
pub struct X25519Capsulator<G> (PhantomData<G>);

impl<G> Capsulator for X25519Capsulator<G>
{
    type Encapsulator = X25519Encapsulator<G>;
    type Decapsulator = X25519Decapsulator<G>;
    type CiphertextSize = U32;
    type SharedKeySize = U32;
    
    fn generate_from_rng ( rng: &mut impl CryptoRngCore ) -> (Self::Encapsulator, Self::Decapsulator) {
        let private = StaticSecret::random_from_rng(rng);
        let public = PublicKey::from(&private);
        (X25519Encapsulator::from_key(public), X25519Decapsulator::from_key(private))
    }
}

impl<G> Kem for X25519Capsulator<G>
where G: Default + std::cmp::Ord + std::fmt::Debug + Copy + std::marker::Sync + std::marker::Send + 'static
{ 
    type DecapsulationKey = X25519Decapsulator<G>;

    type EncapsulationKey = X25519Encapsulator<G>;

    type SharedKeySize = U32;

    type CiphertextSize = U32;
}


impl<G> GenerateDeterministic3 for X25519Capsulator<G>
where G: GenerateDeterministic2<StaticSecret>
{
    type SeedSize = G::SeedSize;
    type Private = <Self as Capsulator>::Decapsulator;
    type Public = <Self as Capsulator>::Encapsulator;
    type Error = ();

    fn generate_deterministic(seed: &cipher::Array::<u8, Self::SeedSize>) -> Result<(Self::Public, Self::Private), Self::Error> {
        let Ok(private) = G::generate_deterministic2(seed) else { panic! ( "Generation failed")};
        let public = PublicKey::from(&private);
        Ok((X25519Encapsulator::from_key(public), X25519Decapsulator::from_key(private)))
    }
}




///
/// Structure used to create encapsulated keys and derive 
/// shared secrets.
/// 
#[derive(Eq, PartialEq, Debug, Clone, Copy)]
pub struct X25519Encapsulator<G>
{
    recipient_public: PublicKey,
    phantom: PhantomData<G>,
}

///
/// Encapsulation method which takes an existing ephemeral private key and returns the matching public key and shared secret
/// 
impl<G> X25519Encapsulator<G>
{
    fn encapsulate_from_key(&self, ephem_prv: StaticSecret) -> Result<(GenericArray<u8,U32>, Array<u8,U32>), ()> {
        let ephem_pub = PublicKey::from(&ephem_prv);
        
        let raw_shared_secret = ephem_prv.diffie_hellman(&self.recipient_public);
        Ok((ephem_pub.to_bytes().into(), raw_shared_secret.to_bytes().into()))
    }
}

impl<G> Encapsulate<GenericArray<u8,U32>, Array<u8,U32>> for X25519Encapsulator<G>
{
    type Error = ();
    
    fn encapsulate(&self, rng: &mut impl CryptoRngCore) -> Result<(GenericArray<u8,U32>, Array<u8,U32>), Self::Error> {
        let ephem_prv = StaticSecret::random_from_rng(rng);
        self.encapsulate_from_key(ephem_prv)
    }
}

impl<G> ml_kem::kem::Encapsulate for X25519Encapsulator<G>
where G: Default + Copy + Clone + std::fmt::Debug + std::cmp::Ord + Sync + Send + 'static
{
    type Kem = X25519Capsulator<G>;

    fn encapsulate_with_rng<R>(&self, rng: &mut R) -> (ml_kem::Ciphertext<Self::Kem>, ml_kem::kem::SharedKey<Self::Kem>)
    where
        R: rand::CryptoRng + ?Sized {
        let mut private_bytes = [0u8; 32];
        rng.fill_bytes(&mut private_bytes);
        let ephem_prv = StaticSecret::from(private_bytes);
        let ephem_pub = PublicKey::from(&ephem_prv);
        
        let raw_shared_secret = ephem_prv.diffie_hellman(&self.recipient_public);
        (ephem_pub.to_bytes().into(), raw_shared_secret.to_bytes().into())
    }
}

impl<G> EncapsulateDeterministic2<GenericArray<u8,U32>, Array<u8,U32>> for X25519Encapsulator<G>
where G: GenerateDeterministic2<StaticSecret>
{
    type Error = ();
    type SeedSize = G::SeedSize; //U32;
    
    fn encapsulate_deterministic(&self, seed: &[u8]) -> Result<(GenericArray<u8,U32>, Array<u8,U32>), Self::Error> {
        if seed.len() < Self::SeedSize::USIZE { return Err(())}
        let Ok(ephem_prv) = G::generate_deterministic2(seed) else { return Err(())};
        self.encapsulate_from_key(ephem_prv)
    }
}

impl<G> KeySizeUser for X25519Encapsulator<G>
{
    type KeySize = U32;
}
impl<G> KeyExport for X25519Encapsulator<G>
{
    fn to_bytes(&self) -> cipher::Key<Self> {
        Array::from(*self.recipient_public.as_bytes())
    }
}
impl<G> KeyInit for X25519Encapsulator<G>
{
    fn new(key: &cipher::Key<Self>) -> Self {
        let encoded_array: &[u8;32] = key.as_ref();
        Self::from_key(PublicKey::from(*encoded_array))
    }
}
impl<G> TryKeyInit for X25519Encapsulator<G>
{
    fn new(_key: &cipher::Key<Self>) -> Result<Self, ml_kem::InvalidKey> {
        todo!()
    }
}
impl<G> TryFrom<&[u8]> for X25519Encapsulator<G>
{
    type Error = TryFromSliceError;
    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Ok(<Self as KeyInit>::new(value.try_into()?))
        
    }
}
// impl<G> EncodedSizeUser2 for X25519Encapsulator<G>
// {
//     type EncodedSize = U32;
//     fn as_bytes(&self) -> crate::Encoded<Self> {
//         GenericArray::from(*self.recipient_public.as_bytes())
//     }
//     fn from_bytes(encoded_public_key: &crate::Encoded<Self>) -> Self {
//         let encoded_array: &[u8;32] = encoded_public_key.as_ref();
//         Self::from_key(PublicKey::from(*encoded_array))
//     }
// }

impl<G> FromKey for X25519Encapsulator<G>
{
    type Key = PublicKey;
    fn from_key(recipient_public: PublicKey) -> Self {
        Self{recipient_public, phantom: PhantomData}
    }
}

impl<G> GetRecipientPublicKeyBytes for X25519Encapsulator<G>
{
    type EncodedLen = U32;

    fn get_recipient_public_key_bytes<'a>(&'a self) -> Cow<'a,[u8]> { //GenericArray<u8, Self::EncodedLen> {
        self.recipient_public.as_bytes().into()
    }
}





///
/// Struct enabling receipt of a X25519EncapKey and recovery of the shared secret
/// 
/// 
#[derive(Clone)]
pub struct X25519Decapsulator<G>
{
    recipient_private: StaticSecret,
    phantom: PhantomData<G>
}

impl<G> std::fmt::Debug for X25519Decapsulator<G>
{
    fn fmt(&self, _f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        todo!()
    }
}

// impl<G> std::cmp::PartialEq for X25519Decapsulator<G>
// {
//     fn eq(&self, other: &Self) -> bool {
//         todo!()
//     }
// }
// impl<G> std::cmp::Eq for X25519Decapsulator<G>
// {
// }


impl<G> FromKey for X25519Decapsulator<G>
{
    type Key = StaticSecret;
    /// Create a new Encapsulator struct using the given key
    fn from_key(value: StaticSecret) -> Self {
        Self{recipient_private: value, phantom: PhantomData}
    }
}

impl<G> Decapsulate<GenericArray<u8, U32>, Array<u8, U32>> for X25519Decapsulator<G>
{
    type Error = ();
    fn decapsulate(&self, encapsulated_key: &GenericArray<u8, U32>) -> Result<Array<u8, U32>, Self::Error> {
        let encoded_array: &[u8; 32] = encapsulated_key.as_ref();

        let ephem_pub = PublicKey::from(*encoded_array);
        let raw_shared_secret = self.recipient_private.diffie_hellman (&ephem_pub);

        Ok(raw_shared_secret.to_bytes().into())
    }
}

impl<G> ml_kem::Generate for X25519Decapsulator<G>
{
    fn try_generate_from_rng<R: rand::TryCryptoRng + ?Sized>(_rng: &mut R) -> Result<Self, R::Error> {
        todo!()
    }
}
impl<G> ml_kem::kem::TryDecapsulate for X25519Decapsulator<G>
where G: Default + std::cmp::Ord + std::fmt::Debug + Copy + Sync + Send + 'static
{
    type Error = Infallible;

    fn try_decapsulate(
        &self,
        ct: &ml_kem::Ciphertext<Self::Kem>,
    ) -> Result<ml_kem::kem::SharedKey<Self::Kem>, Self::Error> {
        let ephem_pub = PublicKey::from(ct.0);
        let raw_shared_secret = self.recipient_private.diffie_hellman (&ephem_pub);
        Ok(raw_shared_secret.to_bytes().into())
    }
}
// impl<G> ml_kem::Decapsulate for X25519Decapsulator<G>
// where G: Default + std::cmp::Ord + std::fmt::Debug + Copy + Sync + Send + 'static
// {
//     fn decapsulate(&self, ct: &ml_kem::Ciphertext<Self::Kem>) -> ml_kem::kem::SharedKey<Self::Kem> {
//         todo!()
//     }
// }


impl<G> KeySizeUser for X25519Decapsulator<G>
{
    type KeySize = U32;
}
impl<G> KeyExport for X25519Decapsulator<G>
{
    fn to_bytes(&self) -> cipher::Key<Self> {
        Array::from(*self.recipient_private.as_bytes())
    }
}
impl<G> KeyInit for X25519Decapsulator<G>
{
    fn new(key: &cipher::Key<Self>) -> Self {
        let encoded_array: &[u8; 32] = key.as_ref();
        Self::from_key(x25519_dalek::StaticSecret::from(*encoded_array))
    }
}
impl<G> TryFrom<&[u8]> for X25519Decapsulator<G>
{
    type Error = TryFromSliceError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let encoded_array: &[u8; 32] = value.try_into()?;
        Ok(Self::from_key(x25519_dalek::StaticSecret::from(*encoded_array)))
    }
}

impl<G> GenerateDeterministic4 for X25519Decapsulator<G>
where G: GenerateDeterministic2<StaticSecret>,
{
    type SeedSize = G::SeedSize;

    type Error = ();

    fn generate_deterministic(seed: &Array::<u8, Self::SeedSize>) -> Result<Self, Self::Error> where Self: Sized {
        let Ok(private) = G::generate_deterministic2(seed) else { panic!("Unhandled ")};
        Ok(Self::from_key(private))
    }
}
// impl<G> crate::EncodedSizeUser2 for X25519Decapsulator<G>
// {
//     type EncodedSize = U32;
//     fn as_bytes(&self) -> crate::Encoded<Self> {
//         GenericArray::from(*self.recipient_private.as_bytes())
//     }
//     fn from_bytes(enc: &crate::Encoded<Self>) -> Self {
//         let encoded_array: &[u8; 32] = enc.as_ref();
//         Self::from_key(x25519_dalek::StaticSecret::from(*encoded_array))
//     }
// }

impl<G> GetEncapsulator for X25519Decapsulator<G>
{
    type Encapsulator = X25519Encapsulator<G>;
    fn encapsulation_key(&self) -> Self::Encapsulator {
        Self::Encapsulator::from_key ( PublicKey::from(&self.recipient_private))
    }
}
impl<G> ml_kem::kem::Decapsulator for X25519Decapsulator<G>
where G: Default + std::cmp::Ord + std::fmt::Debug + Copy + Clone + Send + Sync + 'static
{
    type Kem = X25519Capsulator<G>;
    
    fn encapsulation_key(&self) -> &ml_kem::kem::EncapsulationKey<Self::Kem> {
        todo!()
        //&ml_kem::kem::EncapsulationKey::<Self::Kem>::from_key ( PublicKey::from(&self.recipient_private))
    }
}

impl<G> GetRecipientPublicKeyBytes for X25519Decapsulator<G>
{
    type EncodedLen = U32;

    fn get_recipient_public_key_bytes<'a>(&'a self) -> Cow<'a, [u8]> { //GenericArray<u8, Self::EncodedLen> {
        PublicKey::from(&self.recipient_private).to_bytes().to_vec().into()
    }
}





pub struct X25519AuthCapsulator<G=SeedAsScalar> (PhantomData<G>);

impl<G> Capsulator for X25519AuthCapsulator<G>
where G: GenerateDeterministic2<StaticSecret>
{
    type Encapsulator = X25519AuthEncapsulator<G>;
    type Decapsulator = X25519AuthDecapsulator;
    type CiphertextSize = U32;
    type SharedKeySize = U64;
    
    fn generate_from_rng ( rng: &mut impl CryptoRngCore ) -> (Self::Encapsulator, Self::Decapsulator) {
        let prv_a = StaticSecret::random_from_rng(&mut *rng);
        let pub_a = PublicKey::from(&prv_a);
        let prv_b = StaticSecret::random_from_rng(rng);
        let pub_b = PublicKey::from(&prv_b);
        (X25519AuthEncapsulator::from_keys(pub_a, prv_b), X25519AuthDecapsulator::from_keys(pub_b, prv_a))
    }
}


///
/// Implementation of the AuthEncapsulator for Curve X25519 using dalek-x25519
/// 
pub struct X25519AuthEncapsulator<G>
{
    sender_private: StaticSecret,
    recipient_public: PublicKey,
    phantom: PhantomData<G>,
}


impl<G> FromKeys for X25519AuthEncapsulator<G>
{
    type PrivateKey = StaticSecret;
    type PublicKey = PublicKey;
    fn from_keys ( recipient_public: Self::PublicKey, sender_private: Self::PrivateKey ) -> Self {
        Self { sender_private, recipient_public, phantom: PhantomData}
    }
}


impl<G> Encapsulate<GenericArray<u8,U32>, Array<u8,U64>> for X25519AuthEncapsulator<G>
where G: GenerateDeterministic2<StaticSecret>
{
    type Error = ();

    fn encapsulate(&self, rng: &mut impl CryptoRngCore) -> Result<(GenericArray<u8,U32>, Array<u8,U64>), Self::Error> {
        let mut seed = Array::<u8, <Self as EncapsulateDeterministic2<GenericArray<u8,U32>, Array<u8,U64>>>::SeedSize>::default();
        rng.fill_bytes(&mut seed);
        self.encapsulate_deterministic(&seed)
    }
}

impl<G> EncapsulateDeterministic2<GenericArray<u8,U32>, Array<u8,U64>> for X25519AuthEncapsulator<G>
where G: GenerateDeterministic2<StaticSecret>
{
    type Error = ();
    type SeedSize = G::SeedSize;
    
    fn encapsulate_deterministic(&self, seed: &[u8]) -> Result<(GenericArray<u8,U32>, Array<u8,U64>), Self::Error> {
        if seed.len() < Self::SeedSize::USIZE { return Err(())}
        let Ok(ephem_prv) = G::generate_deterministic2(seed) else { return Err(())};
        let ephem_pub = PublicKey::from(&ephem_prv);
        let raw_shared_secret1 = ephem_prv.diffie_hellman(&self.recipient_public);
        let raw_shared_secret2 = self.sender_private.diffie_hellman(&self.recipient_public);

        let raw_shared_secret_1: &Array<u8, U32> = raw_shared_secret1.as_bytes().into();
        let raw_shared_secret_2: &Array<u8, U32> = raw_shared_secret2.as_bytes().into();
        let raw_shared_secret = raw_shared_secret_1.concat(*raw_shared_secret_2);

        let encapsulated_key = GenericArray::from(*ephem_pub.as_bytes());
        Ok((encapsulated_key, raw_shared_secret))
    }
}

impl<G> GetRecipientPublicKeyBytes for X25519AuthEncapsulator<G>
{
    type EncodedLen = U32;

    fn get_recipient_public_key_bytes<'a>(&'a self) -> Cow<'a,[u8]> { //GenericArray<u8, Self::EncodedLen> {
        self.recipient_public.as_bytes().into()
    }
}

impl<G> GetSenderPublicKeyBytes for X25519AuthEncapsulator<G>
{
    type EncodedLen = U32;

    fn get_sender_public_key_bytes(&self) -> GenericArray<u8, Self::EncodedLen> {
        let sender_public = PublicKey::from(&self.sender_private);
        GenericArray::from(*sender_public.as_bytes())
    }
}


///
/// Implementation of an AuthDecapsulator for X25519 using x25519-dalek
/// 
//pub struct X25519AuthDecapsulator <K: EcdhAuthCombiner>
pub struct X25519AuthDecapsulator
{
    recipient_private: StaticSecret,
    sender_public: PublicKey,
}

impl FromKeys for X25519AuthDecapsulator
{
    type PrivateKey = StaticSecret;
    type PublicKey = PublicKey;
    fn from_keys ( sender_public: Self::PublicKey, recipient_private: Self::PrivateKey ) -> Self {
        Self { recipient_private, sender_public}
        
    }
}

impl Decapsulate<GenericArray<u8,U32>, Array<u8,U64>> for X25519AuthDecapsulator
{
    type Error = ();

    fn decapsulate(&self, encapsulated_key: &GenericArray<u8,U32>) -> Result<Array<u8,U64>, Self::Error> {
        let encoded_array: &[u8; 32] = encapsulated_key.as_ref();
        let ephem_pub = PublicKey::from(*encoded_array);
        let raw_shared_secret1 = self.recipient_private.diffie_hellman(&ephem_pub);
        let raw_shared_secret2 = self.recipient_private.diffie_hellman(&self.sender_public);

        // let mut raw_shared_secret = Array::default(); //raw_shared_secret_1.concat(raw_shared_secret_2);
        // raw_shared_secret[..U32::USIZE].copy_from_slice(raw_shared_secret1.as_bytes());
        // raw_shared_secret[U32::USIZE..].copy_from_slice(raw_shared_secret2.as_bytes());
        let raw_shared_secret1 = Array::<u8,U32>::from(raw_shared_secret1.to_bytes());
        let raw_shared_secret2 = Array::<u8,U32>::from(raw_shared_secret2.to_bytes());

        Ok ( raw_shared_secret1.concat(raw_shared_secret2))
    }
}

impl GetRecipientPublicKeyBytes for X25519AuthDecapsulator
{
    type EncodedLen = U32;

    fn get_recipient_public_key_bytes<'a>(&'a self) -> Cow<'a, [u8]> { //GenericArray<u8, Self::EncodedLen> {
        let recipient_public = PublicKey::from(&self.recipient_private);
        recipient_public.as_bytes().to_vec().into()
    }
}

impl GetSenderPublicKeyBytes for X25519AuthDecapsulator
{
    type EncodedLen = U32;

    fn get_sender_public_key_bytes(&self) -> GenericArray<u8, Self::EncodedLen> {
        GenericArray::from(*self.sender_public.as_bytes())
    }
}



