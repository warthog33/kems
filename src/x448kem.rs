//!
//! Implementation of a Key Encapsulation Mechanism using x448 (pure rust implementation
//! This module implements the KEM traits from the rustcrypto project
//! 
//! ```
//! use cipher::typenum::consts::U32;
//! 
//! use rand_core::OsRng;
//! use kdfs::iso18033_2::Kdf1;
//! use kems::x448kem::{X448Encapsulator, X448Decapsulator, X448Capsulator};
//! use kems::eckem::SeedAsScalar;
//! use kems::{Capsulator, FromKeys, Decapsulate, Encapsulate};
//! use kems::kem_with_kdf::{CombinerAllPubKeys, KemWithKdf};
//! use sha2::Sha256;
//! use x448::{StaticSecret, PublicKey};
//! 
//! let recipient_secret_key = StaticSecret::random_from_rng(&mut rand::rng());
//! let recipient_public_key = PublicKey::from(&recipient_secret_key);
//! 
//! let encapsulator = KemWithKdf::<X448Capsulator<SeedAsScalar>, CombinerAllPubKeys, Kdf1::<Sha256>, U32>::from_public_key(recipient_public_key);
//! let (ct, k_send) = encapsulator.encapsulate(&mut OsRng).unwrap();
//!
//! let decapsulator = KemWithKdf::<X448Capsulator<SeedAsScalar>, CombinerAllPubKeys, Kdf1::<Sha256>, U32>::from_private_key(recipient_secret_key);
//! let (k_recv) = decapsulator.decapsulate(&ct).unwrap();
//! assert! ( k_send == k_recv);
//! ```
//! 
//! The example below shows the authenticated mode which uses two diffie hellman operations and concatenates the outptus
//! 
//! ```
//! use sha2::Sha256;
//! use rand_core::OsRng;
//! use x448::{StaticSecret, PublicKey};
//! use kems::x448kem::{X448AuthCapsulator};
//! use cipher::typenum::consts::U32;
//! use kdfs::iso18033_2::Kdf1;
//! use kems::{FromKeys, Decapsulate, Encapsulate};
//! use kems::kem_with_kdf::{KemAuthWithKdf, CombinerAllPubKeys};
//! 
//! let sender_secret_key = StaticSecret::random_from_rng(&mut rand::rng());
//! let sender_public_key = PublicKey::from(&sender_secret_key);
//! let recipient_secret_key = StaticSecret::random_from_rng(&mut rand::rng());
//! let recipient_public_key = PublicKey::from(&recipient_secret_key);
//! 
//! let auth_encapsulator = KemAuthWithKdf::<X448AuthCapsulator, CombinerAllPubKeys, Kdf1::<Sha256>, U32>::encap_from_keys(recipient_public_key, sender_secret_key);
//! let (ct, k_send) = auth_encapsulator.encapsulate(&mut OsRng).unwrap();
//! 
//! let auth_decapsulator = KemAuthWithKdf::<X448AuthCapsulator, CombinerAllPubKeys, Kdf1::<Sha256>, U32>::decap_from_keys(sender_public_key, recipient_secret_key);
//! let k_recv = auth_decapsulator.decapsulate(&ct).unwrap();
//! assert!( k_send == k_recv);
//! ```


// use std::fmt::Debug;
// use std::marker::PhantomData;

use std::array::TryFromSliceError;
use std::borrow::Cow;
use std::convert::Infallible;
use std::marker::PhantomData;

use crate::{Capsulator, CryptoRngCore, Decapsulate, Encapsulate, EncapsulateDeterministic2, FromKey, FromKeys, GenerateDeterministic2, GenerateDeterministic3, GenerateDeterministic4, GetEncapsulator, GetRecipientPublicKeyBytes, GetSenderPublicKeyBytes};
use crate::eckem::SeedAsScalar;
use cipher::KeySizeUser;
use cipher::common::KeyExport;
use cipher::typenum::{consts::*};
use hmac::KeyInit;
//use crypto_bigint::TryFromSliceError;
use kdfs::hybrid_array::Array;
use generic_array::GenericArray;
use generic_array::typenum::Unsigned;
use ml_kem::TryKeyInit;
use x448::{PublicKey, StaticSecret};

 
/// Factory struct used to create X448Encapsulator and X448Decapsulators
pub struct X448Capsulator<G> (PhantomData<G>);

impl<G> Capsulator for X448Capsulator<G>
where G: GenerateDeterministic2<x448::StaticSecret>
{
    type Encapsulator = X448Encapsulator<G>;
    type Decapsulator = X448Decapsulator<G>;
    type CiphertextSize = U56;
    type SharedKeySize = U56;
    
    fn generate_from_rng ( rng: &mut impl CryptoRngCore ) -> (Self::Encapsulator, Self::Decapsulator) 
    {
        let mut seed = Array::default();
        rng.fill_bytes(&mut seed);
        Self::generate_deterministic(&seed).unwrap()
    }
}

/// Directly uses the 56 byte seed as the raw encoded private key
impl<G> GenerateDeterministic3 for X448Capsulator<G>
where G: GenerateDeterministic2<x448::StaticSecret>
{
    type SeedSize = G::SeedSize;
    type Private = <Self as Capsulator>::Decapsulator;
    type Public = <Self as Capsulator>::Encapsulator;
    type Error = ();

    fn generate_deterministic(seed: &cipher::Array::<u8, Self::SeedSize>) -> Result<(Self::Public, Self::Private), Self::Error> {
        let Ok(private) = G::generate_deterministic2(seed) else { panic! ( "Generateion failed")};
        let public = PublicKey::from(&private);
        Ok((X448Encapsulator::from_key(public), X448Decapsulator::from_key(private)))
    }
}



impl GenerateDeterministic2<StaticSecret> for SeedAsScalar 
{
    type SeedSize = U56;
    //type PublicKey = PublicKey;
    //type Private = StaticSecret;
    type Error = ();
    //fn generate_deterministic2( seed: &[u8]) -> Result<(StaticSecret, PublicKey), Self::Error> {
    fn generate_deterministic2( seed: &[u8]) -> Result<StaticSecret, Self::Error> {
        let seed_as_array: [u8; 56] = seed.try_into().map_err(|_|())?;
        let priv_key = StaticSecret::from(seed_as_array);
        //let pub_key = PublicKey::from(&priv_key);
        Ok(priv_key)
    }
}



///
/// Structure used to create encapsulated keys and derive 
/// shared secrets.
/// 
pub struct X448Encapsulator<G> //<K: EcdhCombiner, L: ArrayLength<u8>>
{
    recipient_public: PublicKey,
    phantom: PhantomData<G>,
}

impl<G> FromKey for X448Encapsulator<G>
{
    type Key = PublicKey;
    /// Create a new Encapsulator struct using the given kdf
    fn from_key(recipient_public: PublicKey) -> Self {
        Self { recipient_public, phantom: PhantomData }
    }
}

impl<G> Encapsulate<GenericArray<u8, U56>, Array<u8, U56>> for X448Encapsulator<G>
where G: GenerateDeterministic2<x448::StaticSecret>
{
    type Error = ();
    fn encapsulate(&self, rng: &mut impl CryptoRngCore) -> Result<(GenericArray<u8,U56>, Array<u8,U56>), Self::Error> {
        let mut seed = Array::<u8, G::SeedSize>::default();
        rng.fill_bytes(&mut seed);
        self.encapsulate_deterministic(&seed)
    }
}

impl<G> EncapsulateDeterministic2<GenericArray<u8, U56>, Array<u8, U56>> for X448Encapsulator<G>
where G: GenerateDeterministic2<x448::StaticSecret>
{
    type Error = ();
    type SeedSize = G::SeedSize; //U56;
    fn encapsulate_deterministic(&self, seed: &[u8]) -> Result<(GenericArray<u8, U56>, Array<u8, U56>), Self::Error> {
        if seed.len() < Self::SeedSize::USIZE { return Err(())};
        let Ok(ephem_prv) = G::generate_deterministic2(seed) else { return Err(())};
        let ephem_pub = PublicKey::from(&ephem_prv);

        let encapsulated_key = GenericArray::from(*ephem_pub.as_bytes());
        let raw_shared_secret = ephem_prv.diffie_hellman(&self.recipient_public);
        
        Ok((encapsulated_key, (*raw_shared_secret.as_bytes()).into()))
    }
}

impl<G> KeySizeUser for X448Encapsulator<G>
{
    type KeySize = U56;
}
impl<G> KeyExport for X448Encapsulator<G>
{
    fn to_bytes(&self) -> cipher::Key<Self> {
        Array::from(*self.recipient_public.as_bytes())
    }
}
impl<G> KeyInit for X448Encapsulator<G>
{
    fn new(key: &cipher::Key<Self>) -> Self {
        let key = PublicKey::from_bytes(&key).unwrap();
        Self::from_key(key)
    }
}
impl<G> TryFrom<&[u8]> for X448Encapsulator<G>
{
    type Error = TryFromSliceError;
    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Ok(KeyInit::new(value.try_into()?))
    }
}

impl<G> GetRecipientPublicKeyBytes for X448Encapsulator<G>
{
    type EncodedLen = U56;

    fn get_recipient_public_key_bytes<'a>(&'a self) -> Cow<'a, [u8]> {
        self.recipient_public.as_bytes().into()
    }
}






///
/// Structure used to decapsulate ciphertexts and output derived 
/// shared secrets.
/// 
pub struct X448Decapsulator<G>
{
    recipient_private: StaticSecret,
    phantom: PhantomData<G>,
}

impl<G> FromKey for X448Decapsulator<G> {
    type Key = StaticSecret;
    fn from_key ( recipient_private: StaticSecret) -> Self {
        return Self{ recipient_private, phantom: PhantomData}
    }
}

impl<G> Decapsulate<GenericArray<u8, U56>, Array<u8, U56>> for X448Decapsulator<G>
{
    type Error = ();
    fn decapsulate(&self, encapsulated_key: &GenericArray<u8, U56>) -> Result<Array<u8, U56>, Self::Error> {
        let ephemeral_public = PublicKey::from_bytes(&encapsulated_key).unwrap();
        let raw_shared_secret = self.recipient_private.diffie_hellman(&ephemeral_public);
        Ok(Array::from(*raw_shared_secret.as_bytes()))
    }
}


impl<G> KeySizeUser for X448Decapsulator<G>
{
    type KeySize = U56;
}
impl<G> KeyExport for X448Decapsulator<G>
{
    fn to_bytes(&self) -> cipher::Key<Self> {
        Array::from(*self.recipient_private.as_bytes())
    }
}
impl<G> KeyInit for X448Decapsulator<G>
{
    fn new(key: &cipher::Key<Self>) -> Self {
        let recipient_private = StaticSecret::from(<[u8;56]>::from(key.clone()));
        Self::from_key(recipient_private)
    }
}
impl<G> TryFrom<&[u8]> for X448Decapsulator<G>
{
    type Error = TryFromSliceError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let recipient_private = StaticSecret::from(<[u8;56]>::try_from(value)?);
        Ok(Self::from_key(recipient_private))
    }
}

impl<G> GenerateDeterministic4 for X448Decapsulator<G>
where G: GenerateDeterministic2<StaticSecret>
{
    type SeedSize = G::SeedSize;

    type Error = ();

    fn generate_deterministic(seed: &Array::<u8, Self::SeedSize>) -> Result<Self, Self::Error> where Self: Sized {
        let Ok(private_key) = G::generate_deterministic2(seed) else { panic!("Unhandled key")};
        Ok(Self::from_key(private_key))
    }
}

// impl<G> crate::EncodedSizeUser2 for X448Decapsulator<G>
// {
//     type EncodedSize = U56;
//     fn as_bytes(&self) -> crate::Encoded<Self> {
//         GenericArray::from(*self.recipient_private.as_bytes())
//     }
//     fn from_bytes(encoded_private_key: &crate::Encoded<Self>) -> Self {
//         let recipient_private = StaticSecret::from(<[u8;56]>::from(encoded_private_key.clone()));
//         Self::from_key(recipient_private)
//     }
// }


impl<G> GetEncapsulator for X448Decapsulator<G>
{
    type Encapsulator = X448Encapsulator<G>;
    fn encapsulation_key(&self) -> Self::Encapsulator {
        let recipient_public = PublicKey::from(&self.recipient_private);
        Self::Encapsulator::from_key(recipient_public)
    }
}
impl<G> GetRecipientPublicKeyBytes for X448Decapsulator<G>
{
    type EncodedLen = U56;

    fn get_recipient_public_key_bytes<'a>(&'a self) -> Cow<'a, [u8]> {
        self.encapsulation_key().get_recipient_public_key_bytes().to_vec().into()
    }
}





///
/// Implementation of the AuthEncapsulator for Curve X448
/// 
pub struct X448AuthEncapsulator 
{
    sender_private: StaticSecret,
    recipient_public: PublicKey,
}


impl FromKeys for X448AuthEncapsulator
{
    type PrivateKey = StaticSecret;
    type PublicKey = PublicKey;
    fn from_keys ( recipient_public: Self::PublicKey, sender_private: Self::PrivateKey ) -> Self {
        Self { sender_private, recipient_public}
    }
}

impl GetRecipientPublicKeyBytes for X448AuthEncapsulator
{
    type EncodedLen = U56;

    fn get_recipient_public_key_bytes<'a>(&'a self) -> Cow<'a, [u8]> { //GenericArray<u8, Self::EncodedLen> {
        self.recipient_public.as_bytes().into()
    }
}

impl GetSenderPublicKeyBytes for X448AuthEncapsulator
{
    type EncodedLen = U56;

    fn get_sender_public_key_bytes(&self) -> GenericArray<u8, Self::EncodedLen> {
        let sender_public = PublicKey::from(&self.sender_private);
        GenericArray::from(*sender_public.as_bytes())
    }
}

///
/// Implementation of authenticated key encapsulation
/// 
impl Encapsulate<GenericArray<u8,U56>, Array<u8,U112>> for X448AuthEncapsulator
{
    type Error = ();

    fn encapsulate(&self, rng: &mut impl CryptoRngCore) -> Result<(GenericArray<u8,U56>, Array<u8,U112>), Self::Error> {
        //let ephem_prv = x448::Secret::new(&mut RngWrapper::from(rng));
        let mut seed = [0u8; 56];
        rng.fill_bytes(&mut seed);
        let ephem_prv = StaticSecret::from(seed);
        let ephem_pub = PublicKey::from(&ephem_prv);
        let encapsulated_key = GenericArray::from(*ephem_pub.as_bytes());

        let raw_shared_secret1 = ephem_prv.diffie_hellman(&self.recipient_public);
        let raw_shared_secret1 = Array::<u8, U56>::from(*raw_shared_secret1.as_bytes());

        let raw_shared_secret2 = self.sender_private.diffie_hellman(&self.recipient_public);
        let raw_shared_secret2 = Array::<u8, U56>::from(*raw_shared_secret2.as_bytes());

        Ok((encapsulated_key, raw_shared_secret1.concat(raw_shared_secret2)))
    }
}



///
/// Implementation of an AuthDecapsulator for X448 using x448-dalek
/// 
pub struct X448AuthDecapsulator
{
    recipient_private: StaticSecret,
    sender_public: PublicKey,
}

impl FromKeys for X448AuthDecapsulator
{
    type PrivateKey = StaticSecret;
    type PublicKey = PublicKey;
    fn from_keys ( pub_key: Self::PublicKey, priv_key: Self::PrivateKey ) -> Self {
        Self { recipient_private: priv_key, sender_public: pub_key}
    }
}

impl Decapsulate<GenericArray<u8,U56>, Array<u8,U112>> for X448AuthDecapsulator
{
    type Error = ();

    fn decapsulate(&self, ciphertext_ga: &GenericArray<u8,U56>) -> Result<Array<u8, U112>, Self::Error> {
        let Some(ephemeral_public) = PublicKey::from_bytes(&ciphertext_ga) else { return Err(())};
        let raw_shared_secret1 = self.recipient_private.diffie_hellman(&ephemeral_public);
        let raw_shared_secret1 = Array::<u8, U56>::from(*raw_shared_secret1.as_bytes());

        let raw_shared_secret2 = self.recipient_private.diffie_hellman(&self.sender_public);
        let raw_shared_secret2 = Array::<u8, U56>::from(*raw_shared_secret2.as_bytes());
        
        Ok(raw_shared_secret1.concat(raw_shared_secret2))
    }
}

impl GetRecipientPublicKeyBytes for X448AuthDecapsulator
{
    type EncodedLen = U56;

    fn get_recipient_public_key_bytes<'a>(&'a self) -> Cow<'a, [u8]> { //GenericArray<u8, Self::EncodedLen> {
        let recipient_public = PublicKey::from(&self.recipient_private);
        recipient_public.as_bytes().to_vec().into()
    }
}

impl GetSenderPublicKeyBytes for X448AuthDecapsulator
{
    type EncodedLen = U56;

    fn get_sender_public_key_bytes(&self) -> GenericArray<u8, Self::EncodedLen> {
        GenericArray::from(*self.sender_public.as_bytes())
    }
}




pub struct X448AuthCapsulator();

impl Capsulator for X448AuthCapsulator
{
    type Encapsulator = X448AuthEncapsulator;
    type Decapsulator = X448AuthDecapsulator;
    type CiphertextSize = U56;
    type SharedKeySize = U112;
    
    fn generate_from_rng ( _rng: &mut impl CryptoRngCore ) -> (Self::Encapsulator, Self::Decapsulator) {
        todo!()
        // let prv_a = x25519_dalek::StaticSecret::random_from_rng(&mut *rng);
        // let pub_a = x25519_dalek::PublicKey::from(&prv_a);
        // let prv_b = x25519_dalek::StaticSecret::random_from_rng(rng);
        // let pub_b = x25519_dalek::PublicKey::from(&prv_b);
        // (X25519AuthEncapsulator::from_keys(pub_a, prv_b), X25519AuthDecapsulator::from_keys(pub_b, prv_a))
    }
}








impl<G> ml_kem::Kem for X448Capsulator<G>
where G: Default + std::cmp::Ord + std::fmt::Debug + Copy + std::marker::Sync + std::marker::Send + 'static
{ 
    type DecapsulationKey = X448Decapsulator<G>;
    type EncapsulationKey = X448Encapsulator<G>;
    type SharedKeySize = U32;
    type CiphertextSize = U32;
}

impl<G> Ord for X448Capsulator<G>
where G: Default + std::cmp::Ord + std::fmt::Debug + Copy + std::marker::Sync + std::marker::Send + 'static
{
    fn cmp(&self, _other: &Self) -> std::cmp::Ordering {
        todo!()
    }
}
impl<G> PartialOrd for X448Capsulator<G>
where G: Default + std::cmp::Ord + std::fmt::Debug + Copy + std::marker::Sync + std::marker::Send + 'static
{
    fn partial_cmp(&self, _other: &Self) -> Option<std::cmp::Ordering> {
        todo!()
    }
}
impl<G> PartialEq for X448Capsulator<G>
where G: Default + std::cmp::Ord + std::fmt::Debug + Copy + std::marker::Sync + std::marker::Send + 'static
{
    fn eq(&self, _other: &Self) -> bool {
        todo!()
    }
}   
impl<G> Eq for X448Capsulator<G>
where G: Default + std::cmp::Ord + std::fmt::Debug + Copy + std::marker::Sync + std::marker::Send + 'static
{
}
impl<G> Default for X448Capsulator<G>
where G: Default + std::cmp::Ord + std::fmt::Debug + Copy + std::marker::Sync + std::marker::Send + 'static
{
    fn default() -> Self {
        todo!()
    }
}   
impl<G> std::fmt::Debug for X448Capsulator<G>
where G: Default + std::cmp::Ord + std::fmt::Debug + Copy + std::marker::Sync + std::marker::Send + 'static
{
    fn fmt(&self, _f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        todo!()
    }
}
impl<G> Copy for X448Capsulator<G>
{
}
impl<G> Clone for X448Capsulator<G>
{
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}


impl<G> ml_kem::Generate for X448Decapsulator<G>
{
    fn try_generate_from_rng<R: rand::TryCryptoRng + ?Sized>(_rng: &mut R) -> Result<Self, R::Error> {
        todo!()
    }
}
impl<G> ml_kem::kem::TryDecapsulate for X448Decapsulator<G>
where G: Default + std::cmp::Ord + std::fmt::Debug + Copy + Clone + Send + Sync + 'static
{
    type Error = Infallible;

    fn try_decapsulate(
        &self,
        _ct: &ml_kem::Ciphertext<Self::Kem>,
    ) -> Result<ml_kem::kem::SharedKey<Self::Kem>, Self::Error> {
        todo!()
    }
}   
impl<G> ml_kem::kem::Decapsulator for X448Decapsulator<G>
where G: Default + std::cmp::Ord + std::fmt::Debug + Copy + Clone + Send + Sync + 'static
{
    type Kem = X448Capsulator<G>;
    
    fn encapsulation_key(&self) -> &ml_kem::kem::EncapsulationKey<Self::Kem> {
        todo!()
        //&ml_kem::kem::EncapsulationKey::<Self::Kem>::from_key ( PublicKey::from(&self.recipient_private))
    }
}


impl<G> ml_kem::kem::Encapsulate for X448Encapsulator<G>
where G: Default + std::cmp::Ord + std::fmt::Debug + Copy + Clone + Send + Sync + 'static
{
    type Kem = X448Capsulator<G>;

    fn encapsulate_with_rng<R>(&self, _rng: &mut R) -> (ml_kem::Ciphertext<Self::Kem>, ml_kem::kem::SharedKey<Self::Kem>)
    where
        R: rand::CryptoRng + ?Sized {
        todo!()
    }
}   

impl<G> TryKeyInit for X448Encapsulator<G>
{
    fn new(_key: &cipher::Key<Self>) -> Result<Self, ml_kem::InvalidKey> {
        todo!()
    }
}
impl<G> std::fmt::Debug for X448Encapsulator<G>
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("X448Encapsulator").field("recipient_public", &self.recipient_public).field("phantom", &self.phantom).finish()
    }
}
impl<G> Eq for X448Encapsulator<G>
{
   
}
impl<G> PartialEq for X448Encapsulator<G>
{
    fn eq(&self, other: &Self) -> bool {
        self.recipient_public == other.recipient_public && self.phantom == other.phantom
    }
}
impl<G> Clone for X448Encapsulator<G>
{
    fn clone(&self) -> Self {
        Self { recipient_public: self.recipient_public, phantom: self.phantom }
    }
}