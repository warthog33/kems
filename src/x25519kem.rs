//!
//! Implementation of a Key Encapsulation Mechanism using x25519 (pure rust implementation, x25519_dalek)
//! This module implements the KEM traits from the rustcrypto project
//! 
//! ```
//! use sha2::Sha256;
//! use kem::{Kem, Encapsulate, Decapsulate};
//! use kems::x25519kem::{X25519Encapsulator, X25519Decapsulator, X25519Kem};
//! use kems::kem_with_kdf::{CombinerAllPubKeys, KemWithKdf};
//! use kdfs::hybrid_array::{Array, typenum::consts::*};
//! use kdfs::iso18033_2::Kdf1;
//! use x25519_dalek::{StaticSecret, PublicKey};
//! 
//! let (decapsulator, encapsulator) = KemWithKdf::<X25519Kem, CombinerAllPubKeys, Kdf1::<Sha256>, U32>::generate_keypair();
//! 
//! let (c0_send, k_send) = encapsulator.encapsulate();
//!  
//! let (k_recv) = decapsulator.decapsulate(&c0_send);
//! assert! ( k_send == k_recv);
//! ```
//! 
//! The example below shows the authenticated mode which uses two diffie hellman operations and concatenates the outptus
//! 
//! ```
//! use cipher::typenum::consts::U32;
//! use rand_core::OsRng;
//! use kem::{Encapsulate, Decapsulate};
//! use kems::{FromKey, FromKeys};
//! use kems::x25519kem::X25519AuthKem;
//! use kems::kem_with_kdf::{KemAuthWithKdf, CombinerAllPubKeys};
//! use kdfs::iso18033_2::Kdf1;
//! use sha2::Sha256;
//! use x25519_dalek::{StaticSecret, PublicKey};
//! 
//! let sender_secret_key = StaticSecret::random();
//! let sender_public_key = PublicKey::from(&sender_secret_key);
//! let recipient_secret_key = StaticSecret::random();
//! let recipient_public_key = PublicKey::from(&recipient_secret_key);
//! 
//! let auth_encapsulator = KemAuthWithKdf::<X25519AuthKem, CombinerAllPubKeys, Kdf1::<Sha256>,U32>::encap_from_keys(recipient_public_key, sender_secret_key);
//! let (c0, k_send) = auth_encapsulator.encapsulate();
//!
//! let auth_decapsulator = KemAuthWithKdf::<X25519AuthKem, CombinerAllPubKeys, Kdf1::<Sha256>, U32>::decap_from_keys(sender_public_key, recipient_secret_key);
//! let k_recv = auth_decapsulator.decapsulate(&c0);
//! assert!( k_send == k_recv);
//! ```


use crate::{EncapsulateDeterministic, FromKey, FromKeys};

use cipher::KeySizeUser;
use cipher::common::{TryKeyInit, KeyExport};
use cipher::typenum::consts::*;
use kem::{Ciphertext, Decapsulate, Decapsulator, Encapsulate, EncapsulationKey, Generate, InvalidKey, Kem, Key, SharedKey};

use hmac::KeyInit;
use kdfs::hybrid_array::Array;
use x25519_dalek::{PublicKey, StaticSecret};


/// Factory struct used to create X25519Encapsulator and X25519Decapsulators
//#[derive(PartialEq,Ord,PartialOrd,Eq,Default,Copy,Clone,Debug)]
#[derive(PartialEq,Ord,PartialOrd,Eq,Default,Copy,Clone,Debug)]
pub struct X25519Kem ();

impl Kem for X25519Kem
{ 
    type DecapsulationKey = X25519Decapsulator;
    type EncapsulationKey = X25519Encapsulator;
    type SharedKeySize = U32;
    type CiphertextSize = U32;
}


///
/// Structure used to create encapsulated keys and derive 
/// shared secrets.
/// 
//#[derive(Eq, PartialEq, Debug, Clone, Copy)]
pub struct X25519Encapsulator
{
    recipient_public: PublicKey,
}

///
/// Encapsulation method which takes an existing ephemeral private key and returns the matching public key and shared secret
/// 
impl X25519Encapsulator
{
    fn encapsulate_from_key(&self, ephem_prv: StaticSecret) -> Result<(Array<u8,U32>, Array<u8,U32>), ()> {
        let ephem_pub = PublicKey::from(&ephem_prv);
        
        let raw_shared_secret = ephem_prv.diffie_hellman(&self.recipient_public);
        Ok((ephem_pub.to_bytes().into(), raw_shared_secret.to_bytes().into()))
    }
}

impl Encapsulate for X25519Encapsulator
{
    type Kem = X25519Kem;

    fn encapsulate_with_rng<R>(&self, rng: &mut R) -> (Ciphertext<Self::Kem>, SharedKey<Self::Kem>)
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

impl KeySizeUser for X25519Encapsulator
{
    type KeySize = U32;
}
impl KeyExport for X25519Encapsulator
{
    fn to_bytes(&self) -> cipher::Key<Self> {
        Array::from(*self.recipient_public.as_bytes())
    }
}
impl KeyInit for X25519Encapsulator
{
    fn new(key: &cipher::Key<Self>) -> Self {
        let encoded_array: &[u8;32] = key.as_ref();
        Self::from_key(PublicKey::from(*encoded_array))
    }
}
impl TryKeyInit for X25519Encapsulator
{
    fn new(_key: &cipher::Key<Self>) -> Result<Self, InvalidKey> {
        Ok(KeyInit::new(_key))
    }
}


impl FromKey for X25519Encapsulator
{
    type Key = PublicKey;
    fn from_key(recipient_public: PublicKey) -> Self {
        Self{recipient_public}
    }
}


impl EncapsulateDeterministic for X25519Encapsulator
{
    type Kem = X25519Kem;
    type SeedSize = U32;
    
    fn encapsulate_deterministic(&self, seed: &[u8]) -> (kem::Ciphertext<Self::Kem>, kem::SharedKey<Self::Kem>) {
        let encoded_array: &[u8; 32] = seed.try_into().unwrap();
        let ephem_prv = StaticSecret::from(*encoded_array);
        
        let (ek, key) = self.encapsulate_from_key(ephem_prv).unwrap();
        (ek.as_slice().try_into().unwrap(), key)
    }
}

impl Ord for X25519Encapsulator
{
    fn cmp(&self, _other: &Self) -> std::cmp::Ordering {
        todo!()
    }
}
impl PartialOrd for X25519Encapsulator
{
    fn partial_cmp(&self, _other: &Self) -> Option<std::cmp::Ordering> {
        todo!()
    }
}
impl std::fmt::Debug for X25519Encapsulator
{
    fn fmt(&self, _f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        todo!()
    }
}
impl Clone for X25519Encapsulator
{
    fn clone(&self) -> Self {
        Self { recipient_public: self.recipient_public.clone()}
    }
}
impl Eq for X25519Encapsulator
{
}
impl PartialEq for X25519Encapsulator
{
    fn eq(&self, other: &Self) -> bool {
        self.recipient_public == other.recipient_public
    }
}









///
/// Struct enabling receipt of a ciphertext and recovery of the shared secret
/// 
pub struct X25519Decapsulator
{
    recipient_private: StaticSecret,
    encapsulation_key: X25519Encapsulator,
}

impl FromKey for X25519Decapsulator
{
    type Key = StaticSecret;
    /// Create a new Encapsulator struct using the given key
    fn from_key(value: StaticSecret) -> Self {
        let recipient_public = PublicKey::from(&value);
        Self{recipient_private: value, encapsulation_key: X25519Encapsulator { recipient_public}}
    }
}

impl Generate for X25519Decapsulator
{
    fn try_generate_from_rng<R: rand::TryCryptoRng + ?Sized>(rng: &mut R) -> Result<Self, R::Error> {
        let mut seed = Array::<u8, U32>::default();
        rng.try_fill_bytes(&mut seed)?;
        let private = StaticSecret::from(seed.0);
        Ok(X25519Decapsulator::from_key(private))
    }
}

impl Decapsulate for X25519Decapsulator
{
    fn decapsulate(&self, ct: &Ciphertext<Self::Kem>) -> SharedKey<Self::Kem> {
        let ephem_pub = PublicKey::from(ct.0);
        let raw_shared_secret = self.recipient_private.diffie_hellman (&ephem_pub);
        raw_shared_secret.to_bytes().into()
    }
}


impl KeySizeUser for X25519Decapsulator
{
    type KeySize = U32;
}
impl KeyExport for X25519Decapsulator
{
    fn to_bytes(&self) -> cipher::Key<Self> {
        Array::from(*self.recipient_private.as_bytes())
    }
}
impl KeyInit for X25519Decapsulator
{
    fn new(key: &cipher::Key<Self>) -> Self {
        let priv_key = StaticSecret::from(key.0);
        Self::from_key(priv_key)
    }
}
impl TryKeyInit for X25519Decapsulator
{
    fn new(key: &cipher::Key<Self>) -> Result<X25519Decapsulator, InvalidKey> {
        Ok(KeyInit::new(key))
    }
}

impl Decapsulator for X25519Decapsulator
{
    type Kem = X25519Kem;
    
    fn encapsulation_key(&self) -> &EncapsulationKey<Self::Kem> {
        &self.encapsulation_key
    }
}






#[derive(Debug, Clone, PartialEq, Copy, Eq, Ord, PartialOrd, Default)]
pub struct X25519AuthKem ();

impl Kem for X25519AuthKem
{ 
    type DecapsulationKey = X25519AuthDecapsulator;
    type EncapsulationKey = X25519AuthEncapsulator;
    type SharedKeySize = U64;
    type CiphertextSize = U32;
}










///
/// Implementation of the AuthEncapsulator for Curve X25519 using dalek-x25519
/// 
pub struct X25519AuthEncapsulator
{
    sender_private: Option<StaticSecret>,
    sender_public: PublicKey,
    recipient_public: PublicKey,
}


impl FromKeys for X25519AuthEncapsulator
{
    type PrivateKey = StaticSecret;
    type PublicKey = PublicKey;
    fn from_keys ( recipient_public: Self::PublicKey, sender_private: Self::PrivateKey ) -> Self {
        let sender_public = PublicKey::from(&sender_private);
        Self { sender_private: Some(sender_private), sender_public, recipient_public}
    }
}


impl Encapsulate for X25519AuthEncapsulator
{
    type Kem = X25519AuthKem;
    
    fn encapsulate_with_rng<R>(&self, rng: &mut R) -> (Ciphertext<Self::Kem>, SharedKey<Self::Kem>)
    where
        R: rand::prelude::CryptoRng + ?Sized {
        let mut seed = Array::<u8, U32>::default(); //Array::<u8, <Self as EncapsulateDeterministicN<GenericArray<u8,U32>, Array<u8,U64>>>::SeedSize>::default();
        rng.fill_bytes(&mut seed);
        self.encapsulate_deterministic(&seed)
    }
}

impl EncapsulateDeterministic for X25519AuthEncapsulator
{
    type Kem = X25519AuthKem;
    type SeedSize = U32;
    
    fn encapsulate_deterministic(&self, seed: &[u8]) -> (Ciphertext<Self::Kem>, SharedKey<Self::Kem>) {
        let seed_array: [u8;32] = seed.try_into().unwrap();
        let ephem_prv = StaticSecret::from(seed_array);

        let ephem_pub = PublicKey::from(&ephem_prv);
        let raw_shared_secret1 = ephem_prv.diffie_hellman(&self.recipient_public);
        let raw_shared_secret2 = self.sender_private.as_ref().unwrap().diffie_hellman(&self.recipient_public);

        let raw_shared_secret_1: &Array<u8, U32> = raw_shared_secret1.as_bytes().into();
        let raw_shared_secret_2: &Array<u8, U32> = raw_shared_secret2.as_bytes().into();
        let raw_shared_secret = raw_shared_secret_1.concat(*raw_shared_secret_2);

        let encapsulated_key: Array<u8, U32> = Array::from(*ephem_pub.as_bytes());
        (encapsulated_key, raw_shared_secret)
    }
}

///
/// Bit hacky, but the key for an authenticated KEM is the concatenation of two the two public keys, so the key size is 64 bytes
impl KeySizeUser for X25519AuthEncapsulator
{
    type KeySize = U64;
}
impl TryKeyInit for X25519AuthEncapsulator
{
    fn new(_key: &Key<Self>) -> Result<Self, InvalidKey> {
        todo!()
    }
}
impl KeyExport for X25519AuthEncapsulator
{
    fn to_bytes(&self) -> Key<Self> {
        let pub1: Array<u8, U32> = Array::from(*self.recipient_public.as_bytes());
        let pub2: Array<u8, U32> = Array::from(*self.sender_public.as_bytes());
        Array::from(pub1.concat(pub2))
    }
}
impl Default for X25519AuthEncapsulator
{
    fn default() -> Self {
        todo!()
    }
}
impl std::fmt::Debug for X25519AuthEncapsulator
{
    fn fmt(&self, _f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        todo!()
    }
}
impl Clone for X25519AuthEncapsulator
{
    fn clone(&self) -> Self {
        Self { sender_private: self.sender_private.clone(), sender_public: self.sender_public, recipient_public: self.recipient_public.clone()}
    }
}
impl Eq for X25519AuthEncapsulator
{
    
}
impl PartialEq for X25519AuthEncapsulator
{
    fn eq(&self, _other: &Self) -> bool {
        todo!()
    }
}
impl Ord for X25519AuthEncapsulator
{
    fn cmp(&self, _other: &Self) -> std::cmp::Ordering {
        todo!()
    }
}
impl PartialOrd for X25519AuthEncapsulator
{
    fn partial_cmp(&self, _other: &Self) -> Option<std::cmp::Ordering> {
        todo!()
    }
}




///
/// Implementation of an AuthDecapsulator for X25519 using x25519-dalek
/// 
//pub struct X25519AuthDecapsulator <K: EcdhAuthCombiner>
pub struct X25519AuthDecapsulator
{
    recipient_private: StaticSecret,
    encapsulation_key: X25519AuthEncapsulator,
}

impl Generate for X25519AuthDecapsulator
{
    fn try_generate_from_rng<R: rand::TryCryptoRng + ?Sized>(_rng: &mut R) -> Result<Self, R::Error> {
        panic! ( "Cannot generate keys using this function, auth decapsulators must be created from the from_keys method")
    }
}
impl FromKeys for X25519AuthDecapsulator
{
    type PrivateKey = StaticSecret;
    type PublicKey = PublicKey;
    fn from_keys ( sender_public: Self::PublicKey, recipient_private: Self::PrivateKey ) -> Self {
        let recipient_public = PublicKey::from(&recipient_private);
        Self { recipient_private, encapsulation_key: X25519AuthEncapsulator{sender_private:None, sender_public, recipient_public}}
        
    }
}

impl Decapsulate for X25519AuthDecapsulator
{
    fn decapsulate(&self, ct: &Ciphertext<Self::Kem>) -> SharedKey<Self::Kem> {
        let encoded_array: &[u8; 32] = ct.as_ref();
        let ephem_pub = PublicKey::from(*encoded_array);
        let raw_shared_secret1 = self.recipient_private.diffie_hellman(&ephem_pub);
        let raw_shared_secret2 = self.recipient_private.diffie_hellman(&self.encapsulation_key.sender_public);

        let raw_shared_secret1 = Array::<u8,U32>::from(raw_shared_secret1.to_bytes());
        let raw_shared_secret2 = Array::<u8,U32>::from(raw_shared_secret2.to_bytes());

        let x = raw_shared_secret1.concat(raw_shared_secret2);
        x.as_slice().try_into().unwrap()
    }

}
impl Decapsulator for X25519AuthDecapsulator
{
    type Kem = X25519AuthKem;

    fn encapsulation_key(&self) -> &EncapsulationKey<Self::Kem> {
        &self.encapsulation_key
    }
}



