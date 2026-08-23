//!
//! Implementation of a Key Encapsulation Mechanism using x448 (pure rust implementation
//! This module implements the KEM traits from the rustcrypto project
//! 
//! ```
//! use cipher::typenum::consts::U32;
//! 
//! use rand_core::OsRng;
//! use kdfs::iso18033_2::Kdf1;
//! use kem::{Decapsulate, Encapsulate};
//! use kems::x448kem::{X448Encapsulator, X448Decapsulator, X448Kem};
//! use kems::{KemExtensions, FromKeys};
//! use kems::kem_with_kdf::{CombinerAllPubKeys, KemWithKdf};
//! use sha2::Sha256;
//! use x448::{StaticSecret, PublicKey};
//! 
//! let recipient_secret_key = StaticSecret::random_from_rng(&mut rand::rng());
//! let recipient_public_key = PublicKey::from(&recipient_secret_key);
//! 
//! let encapsulator = KemWithKdf::<X448Kem, CombinerAllPubKeys, Kdf1::<Sha256>, U32>::from_public_key(recipient_public_key);
//! let (ct, k_send) = encapsulator.encapsulate();
//!
//! let decapsulator = KemWithKdf::<X448Kem, CombinerAllPubKeys, Kdf1::<Sha256>, U32>::from_private_key(recipient_secret_key);
//! let (k_recv) = decapsulator.decapsulate(&ct);
//! assert! ( k_send == k_recv);
//! ```
//! 
//! The example below shows the authenticated mode which uses two diffie hellman operations and concatenates the outptus
//! 
//! ```
//! use sha2::Sha256;
//! use rand_core::OsRng;
//! use x448::{StaticSecret, PublicKey};
//! use kem::{Decapsulate, Encapsulate};
//! use kems::x448kem::{X448AuthKem};
//! use cipher::typenum::consts::U32;
//! use kdfs::iso18033_2::Kdf1;
//! use kems::{FromKeys};
//! use kems::kem_with_kdf::{KemAuthWithKdf, CombinerAllPubKeys};
//! 
//! let sender_secret_key = StaticSecret::random_from_rng(&mut rand::rng());
//! let sender_public_key = PublicKey::from(&sender_secret_key);
//! let recipient_secret_key = StaticSecret::random_from_rng(&mut rand::rng());
//! let recipient_public_key = PublicKey::from(&recipient_secret_key);
//! 
//! let auth_encapsulator = KemAuthWithKdf::<X448AuthKem, CombinerAllPubKeys, Kdf1::<Sha256>, U32>::encap_from_keys(recipient_public_key, sender_secret_key);
//! let (ct, k_send) = auth_encapsulator.encapsulate();
//! 
//! let auth_decapsulator = KemAuthWithKdf::<X448AuthKem, CombinerAllPubKeys, Kdf1::<Sha256>, U32>::decap_from_keys(sender_public_key, recipient_secret_key);
//! let k_recv = auth_decapsulator.decapsulate(&ct);
//! assert!( k_send == k_recv);
//! ```


use crate::{EncapsulateDeterministic, FromKey, FromKeys};
use cipher::KeySizeUser;
use cipher::common::{KeyExport,TryKeyInit};
use cipher::typenum::{consts::*};
use hmac::KeyInit;
use kdfs::hybrid_array::Array;
use kem::{Ciphertext, Decapsulate, Decapsulator, Encapsulate, EncapsulationKey, Generate, InvalidKey, Kem, Key, SharedKey, TryDecapsulate};
use x448::{PublicKey, StaticSecret};

 
/// Factory struct used to create X448Encapsulator and X448Decapsulators
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, PartialOrd, Ord)]
pub struct X448Kem ();

impl Kem for X448Kem
{ 
    type DecapsulationKey = X448Decapsulator;
    type EncapsulationKey = X448Encapsulator;
    type SharedKeySize = U56;
    type CiphertextSize = U56;
}




///
/// Structure used to create encapsulated keys and derive 
/// shared secrets.
/// 
#[derive(Debug, Eq, PartialEq)]
pub struct X448Encapsulator //<K: EcdhCombiner, L: ArrayLength<u8>>
{
    recipient_public: PublicKey,
}

impl FromKey for X448Encapsulator
{
    type Key = PublicKey;
    /// Create a new Encapsulator struct using the given kdf
    fn from_key(recipient_public: PublicKey) -> Self {
        Self { recipient_public }
    }
}

/// Size of the encoded public/encapsulation key
impl KeySizeUser for X448Encapsulator
{
    type KeySize = U56;
}

/// Retrieve the byte array encoding of the encapsulation key
impl KeyExport for X448Encapsulator
{
    fn to_bytes(&self) -> cipher::Key<Self> {
        Array::from(*self.recipient_public.as_bytes())
    }
}
/// Create an encapsulator from encoded bytes
impl KeyInit for X448Encapsulator
{
    fn new(key: &Key<Self>) -> Self {
        let key = PublicKey::from_bytes(&key).unwrap();
        Self::from_key(key)
    }
}
/// Implement TryKeyInit, which fails if encoded value is one of the low order values
impl TryKeyInit for X448Encapsulator
{
    fn new(bytes: &Key<Self>) -> Result<Self, InvalidKey> {
        let Some(key) = PublicKey::from_bytes(&bytes) else { return Err(InvalidKey)};
        Ok(Self::from_key(key))
    }
}

impl Encapsulate for X448Encapsulator
{
    type Kem = X448Kem;

    fn encapsulate_with_rng<R>(&self, rng: &mut R) -> (Ciphertext<Self::Kem>, SharedKey<Self::Kem>)
    where R: rand::CryptoRng + ?Sized {
        let mut seed = Array::<u8, U56>::default();
        rng.fill_bytes(&mut seed);
        let (ct, ss) = self.encapsulate_deterministic(&seed);
        (ct, ss)
    }
}   

impl EncapsulateDeterministic for X448Encapsulator
{
    type Kem = X448Kem;
    type SeedSize = U56;
    
    fn encapsulate_deterministic(&self, seed: &[u8]) -> (Ciphertext<Self::Kem>, SharedKey<Self::Kem>) {
        let seed_as_array: [u8; 56] = seed.try_into().unwrap();
        let ephem_prv = StaticSecret::from(seed_as_array);
        let ephem_pub = PublicKey::from(&ephem_prv);

        let encapsulated_key = Array::from(*ephem_pub.as_bytes());
        let raw_shared_secret = ephem_prv.diffie_hellman(&self.recipient_public);
        
        (encapsulated_key, (*raw_shared_secret.as_bytes()).into())
    }
}



impl Clone for X448Encapsulator
{
    fn clone(&self) -> Self {
        Self { recipient_public: self.recipient_public }
    }
}








///
/// Structure used to decapsulate ciphertexts and output derived 
/// shared secrets.
/// 
pub struct X448Decapsulator
{
    recipient_private: StaticSecret,
    recipient_public: X448Encapsulator,
}

impl FromKey for X448Decapsulator {
    type Key = StaticSecret;
    fn from_key ( recipient_private: StaticSecret) -> Self {
        let recipient_public = PublicKey::from(&recipient_private);
        return Self{ recipient_private, recipient_public: X448Encapsulator { recipient_public }}
    }
}


impl KeySizeUser for X448Decapsulator
{
    type KeySize = U56;
}
impl KeyExport for X448Decapsulator
{
    fn to_bytes(&self) -> Key<Self> {
        Array::from(*self.recipient_private.as_bytes())
    }
}
impl KeyInit for X448Decapsulator
{
    fn new(key: &Key<Self>) -> Self {
        let recipient_private = StaticSecret::from(<[u8;56]>::from(key.clone()));
        Self::from_key(recipient_private)
    }
}
impl TryKeyInit for X448Decapsulator
{
    fn new(key: &Key<Self>) -> Result<X448Decapsulator, InvalidKey> {
        let recipient_private = StaticSecret::from(<[u8;56]>::from(key.clone()));
        Ok(Self::from_key(recipient_private))
    }
}

impl Generate for X448Decapsulator
{
    fn try_generate_from_rng<R: rand::TryCryptoRng + ?Sized>(rng: &mut R) -> Result<Self, R::Error> {
        let mut seed = Array::<u8, U56>::default();
        rng.try_fill_bytes(&mut seed)?;
        let recipient_private = StaticSecret::from(seed.0);
        let recipient_public = PublicKey::from(&recipient_private);
        Ok(Self{recipient_private, recipient_public: X448Encapsulator{recipient_public}})
    }
}
impl TryDecapsulate for X448Decapsulator
{
    type Error = InvalidKey;
    
    fn try_decapsulate(
        &self,
        ct: &Ciphertext<Self::Kem>,
    ) -> Result<SharedKey<Self::Kem>, Self::Error> {
        let Some(ephemeral_public) = PublicKey::from_bytes(ct) else { return Err(InvalidKey);};
        let raw_shared_secret = self.recipient_private.diffie_hellman(&ephemeral_public);
        Ok(Array::from(*raw_shared_secret.as_bytes()))
    }
}   
impl Decapsulator for X448Decapsulator
{
    type Kem = X448Kem;
    
    fn encapsulation_key(&self) -> &EncapsulationKey<Self::Kem> {
        &self.recipient_public
    }
}




#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, PartialOrd, Ord)]
pub struct X448AuthKem();

impl Kem for X448AuthKem
{
    type EncapsulationKey = X448AuthEncapsulator;
    type DecapsulationKey = X448AuthDecapsulator;
    type CiphertextSize = U56;
    type SharedKeySize = U112;
}




///
/// Implementation of the AuthEncapsulator for Curve X448
/// 
#[derive(Clone)]
pub struct X448AuthEncapsulator 
{
    sender_private: Option<StaticSecret>,
    sender_public: PublicKey,
    recipient_public: PublicKey,
}


impl FromKeys for X448AuthEncapsulator
{
    type PrivateKey = StaticSecret;
    type PublicKey = PublicKey;
    fn from_keys ( recipient_public: Self::PublicKey, sender_private: Self::PrivateKey ) -> Self {
        let sender_public = PublicKey::from(&sender_private);
        Self { sender_private:Some(sender_private), recipient_public, sender_public}
    }
}


impl Encapsulate for X448AuthEncapsulator
{
    type Kem = X448AuthKem;

    fn encapsulate_with_rng<R>(&self, rng: &mut R) -> (Ciphertext<Self::Kem>, SharedKey<Self::Kem>)
    where
        R: rand::prelude::CryptoRng + ?Sized {
        let mut seed = [0u8; 56];
        rng.fill_bytes(&mut seed);
        let ephem_prv = StaticSecret::from(seed);
        let ephem_pub = PublicKey::from(&ephem_prv);
        let encapsulated_key = Array::from(*ephem_pub.as_bytes());

        let raw_shared_secret1 = ephem_prv.diffie_hellman(&self.recipient_public);
        let raw_shared_secret1 = Array::<u8, U56>::from(*raw_shared_secret1.as_bytes());

        let raw_shared_secret2 = self.sender_private.as_ref().unwrap().diffie_hellman(&self.recipient_public);
        let raw_shared_secret2 = Array::<u8, U56>::from(*raw_shared_secret2.as_bytes());

        (encapsulated_key, raw_shared_secret1.concat(raw_shared_secret2))
    }
}

impl std::fmt::Debug for X448AuthEncapsulator {
    fn fmt(&self, _f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        todo!()
    }
}

impl TryKeyInit for X448AuthEncapsulator {
    fn new(_key: &Key<Self>) -> Result<Self, InvalidKey> {
        todo!()
    }
}
  

impl KeyExport for X448AuthEncapsulator {
    fn to_bytes(&self) -> kem::Key<Self> {
        let pub1 = Array::<u8, U56>::from(*self.recipient_public.as_bytes());
        let pub2 = Array::<u8, U56>::from(*PublicKey::from(self.sender_public).as_bytes());
        let result = pub1.concat(pub2);
        Array::from(result)
    }
}
    

impl KeySizeUser for X448AuthEncapsulator {
    type KeySize = U112; //U56;
}

impl PartialEq for X448AuthEncapsulator {
    fn eq(&self, _other: &Self) -> bool {
        todo!()
    }
}
impl Eq for X448AuthEncapsulator {
  
}

///
/// Implementation of authenticated key encapsulation
/// 



///
/// Implementation of an AuthDecapsulator for X448 using x448-dalek
/// 
pub struct X448AuthDecapsulator
{
    recipient_private: StaticSecret,
    encapsulation_key: X448AuthEncapsulator,
}

impl FromKeys for X448AuthDecapsulator
{
    type PrivateKey = StaticSecret;
    type PublicKey = PublicKey;
    fn from_keys ( sender_public: Self::PublicKey, recipient_private: Self::PrivateKey ) -> Self {
        let recipient_public = PublicKey::from(&recipient_private);
        Self { recipient_private, encapsulation_key: X448AuthEncapsulator{sender_public, sender_private: None, recipient_public}}
    }
}

impl Decapsulator for X448AuthDecapsulator
{
    type Kem = X448AuthKem;

    fn encapsulation_key(&self) -> &EncapsulationKey<Self::Kem> {
        &self.encapsulation_key
    }
}
impl Decapsulate for X448AuthDecapsulator
{
    fn decapsulate(&self, ct: &Ciphertext<Self::Kem>) -> SharedKey<Self::Kem> {
        let Some(ephemeral_public) = PublicKey::from_bytes(&ct) else { panic!()};
        let raw_shared_secret1 = self.recipient_private.diffie_hellman(&ephemeral_public);
        let raw_shared_secret1 = Array::<u8, U56>::from(*raw_shared_secret1.as_bytes());

        let raw_shared_secret2 = self.recipient_private.diffie_hellman(&self.encapsulation_key.sender_public);
        let raw_shared_secret2 = Array::<u8, U56>::from(*raw_shared_secret2.as_bytes());
        
        raw_shared_secret1.concat(raw_shared_secret2)
    }
}

impl Generate for X448AuthDecapsulator 
{
    fn try_generate_from_rng<R: rand::TryCryptoRng + ?Sized>(_rng: &mut R) -> Result<Self, R::Error> {
        todo!()
    }
}
