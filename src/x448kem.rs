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
//! let encapsulator = KemWithKdf::<X448Capsulator<SeedAsScalar>, CombinerAllPubKeys, Kdf1::<Sha256>, U32>::new_encapsulator(recipient_public_key);
//! let (ct, k_send) = encapsulator.encapsulate(&mut OsRng).unwrap();
//!
//! let decapsulator = KemWithKdf::<X448Capsulator<SeedAsScalar>, CombinerAllPubKeys, Kdf1::<Sha256>, U32>::new_decapsulator(recipient_secret_key);
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

use std::marker::PhantomData;

use crate::{Capsulator, CryptoRngCore, Decapsulate, DeriveKeyPairFromSeed, Encapsulate, EncapsulateDeterministic2, EncodedSizeUser2, FromKey, FromKeys, GenerateCapsulatorFromSeed, GetEncapsulator, GetRecipientPublicKeyBytes, GetSenderPublicKeyBytes};
use crate::eckem::SeedAsScalar;
use cipher::typenum::{consts::*};
//use crypto_bigint::TryFromSliceError;
use kdfs::hybrid_array::Array;
use generic_array::GenericArray;
use crate::generic_array::typenum::Unsigned;
use x448::{PublicKey, StaticSecret};

// X448 uses an old version of Rng. Wrap it so we can use the same Encapsulator trait
// struct RngWrapper<'a, R: CryptoRngCore> {
//     core: &'a mut R,
// }
// impl<'a, R: CryptoRngCore> From<&'a mut R> for RngWrapper<'a, R> {
//     fn from(v: &'a mut R) -> Self {
//         Self { core: v}
//     }
// }

// impl<'a, R: CryptoRngCore> rand_core3::CryptoRng for RngWrapper<'a, R> {}

// impl<'a, R: CryptoRngCore> rand_core3::RngCore for RngWrapper<'a, R> {
//     fn fill_bytes(&mut self, dest: &mut [u8]) {
//         self.core.fill_bytes(dest)
//     }
//     fn next_u32(&mut self) -> u32 {
//         self.core.next_u32()
//     }
//     fn next_u64(&mut self) -> u64 {
//         self.core.next_u64()
//     }
//     fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core3::Error> {
//         self.core.try_fill_bytes(dest).map_err(|e|rand_core3::Error::from(e.code().unwrap()))
//     }
// }
 
/// Factory struct used to create X448Encapsulator and X448Decapsulators
pub struct X448Capsulator<G> (PhantomData<G>);

impl<G> Capsulator for X448Capsulator<G>
where G: DeriveKeyPairFromSeed<x448::StaticSecret, PublicKey=PublicKey>
{
    type Encapsulator = X448Encapsulator<G>;
    type Decapsulator = X448Decapsulator<G>;
    type CiphertextSize = U56;
    type SharedKeySize = U56;
    
    fn generate ( rng: &mut impl CryptoRngCore ) -> (Self::Encapsulator, Self::Decapsulator) 
    {
        let mut seed = Array::default();
        rng.fill_bytes(&mut seed);
        Self::derive_from_seed(&seed)
    }
}

/// Directly uses the 56 byte seed as the raw encoded private key
impl<G> GenerateCapsulatorFromSeed for X448Capsulator<G>
where G: DeriveKeyPairFromSeed<x448::StaticSecret, PublicKey=PublicKey>
{
    type SeedSize = G::SeedSize;
    fn derive_from_seed(seed: &cipher::Array::<u8, Self::SeedSize>) -> (Self::Encapsulator, Self::Decapsulator) {
        // let private = StaticSecret::from(seed.0);
        // let public = PublicKey::from(&private);
        let Ok((private, public)) = G::derive_keypair_from_seed(seed) else { panic! ( "Generateion failed")};
        (X448Encapsulator::from_key(public), X448Decapsulator::from_key(private))    
    }
}

impl DeriveKeyPairFromSeed<StaticSecret> for SeedAsScalar 
{
    type SeedSize = U56;
    type PublicKey = PublicKey;
    type Error = ();
    //fn derive_keypair_from_seed( seed: &Array::<u8, Self::SeedSize>) -> (StaticSecret, PublicKey) {
    fn derive_keypair_from_seed( seed: &[u8]) -> Result<(StaticSecret, PublicKey), Self::Error> {
        //let Ok(seed_as_array: [u8;56]) = [u8;56].try_from(seed) else { return Err(()) }; //seed.try_into() else { return Err(())};
        let seed_as_array: [u8; 56] = seed.try_into().map_err(|_|())?;
        let priv_key = StaticSecret::from(seed_as_array);
        let pub_key = PublicKey::from(&priv_key);
        Ok((priv_key, pub_key))
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
{
    type Error = ();
    fn encapsulate(&self, rng: &mut impl CryptoRngCore) -> Result<(GenericArray<u8,U56>, Array<u8,U56>), Self::Error> {
        let mut seed = [0u8; 56];
        rng.fill_bytes(&mut seed);
        let ephem_prv = StaticSecret::from(seed);

        let ephem_pub = PublicKey::from(&ephem_prv);
        let encapsulated_key = GenericArray::from(*ephem_pub.as_bytes());
        
        let raw_shared_secret = ephem_prv.diffie_hellman(&self.recipient_public);
        
        Ok((encapsulated_key, (*raw_shared_secret.as_bytes()).into()))
    }
}

impl<G> EncapsulateDeterministic2<GenericArray<u8, U56>, Array<u8, U56>> for X448Encapsulator<G>
where G: DeriveKeyPairFromSeed<x448::StaticSecret, PublicKey=PublicKey>
{
    type Error = ();
    type SeedSize = G::SeedSize; //U56;
    fn encapsulate_deterministic(&self, seed: &[u8]) -> Result<(GenericArray<u8, U56>, Array<u8, U56>), Self::Error> {
        //let ephem_prv = StaticSecret::from(seed.0);
        //let ephem_pub = PublicKey::from(&ephem_prv);
        if seed.len() < Self::SeedSize::USIZE { return Err(())};
        let Ok((ephem_prv, ephem_pub)) = G::derive_keypair_from_seed(seed) else { return Err(())};

        let encapsulated_key = GenericArray::from(*ephem_pub.as_bytes());
        
        let raw_shared_secret = ephem_prv.diffie_hellman(&self.recipient_public);
        
        Ok((encapsulated_key, (*raw_shared_secret.as_bytes()).into()))
    }
}


//impl<K: EcdhCombiner + Default, L:ArrayLength<u8>> EncodedSizeUser2 for X448Encapsulator<K,L>
impl<G> EncodedSizeUser2 for X448Encapsulator<G>
{
    type EncodedSize = U56;
    fn as_bytes(&self) -> crate::Encoded<Self> {
        GenericArray::from(*self.recipient_public.as_bytes())
    }
    fn from_bytes(encoded: &crate::Encoded<Self>) -> Self {
        let key = PublicKey::from_bytes(&encoded).unwrap();
        //Self { recipient_public: key } //, kdf: K::default(), phantom: PhantomData}
        Self::from_key(key)
    }
}

// impl EncodeGenericArray<Self> for X448Encapsulator
// {
//     type EncodedLen = U56;

//     fn encode(source: &Self) -> GenericArray<u8, Self::EncodedLen> {
//         GenericArray::from(*source.recipient_public.as_bytes())
//     }
// }
// impl DecodeGenericArray<Self> for X448Encapsulator
// {
//     type EncodedLen = U56;
//     type Error = ();
//     fn decode(encoded_bytes: &GenericArray<u8, Self::EncodedLen>) -> Result<Self, Self::Error> {
//         let Some(key) = PublicKey::from_bytes(&encoded_bytes) else { return Err(())};
//         Ok(Self { recipient_public: key }) //, kdf: K::default(), phantom: PhantomData}
//     }
// }

impl<G> GetRecipientPublicKeyBytes for X448Encapsulator<G>
{
    type EncodedLen = U56;

    fn get_recipient_public_key_bytes(&self) -> GenericArray<u8, Self::EncodedLen> {
        GenericArray::from(*self.recipient_public.as_bytes())
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

impl<G> crate::EncodedSizeUser2 for X448Decapsulator<G>
{
    type EncodedSize = U56;
    fn as_bytes(&self) -> crate::Encoded<Self> {
        GenericArray::from(*self.recipient_private.as_bytes())
    }
    fn from_bytes(encoded_private_key: &crate::Encoded<Self>) -> Self {
        let recipient_private = StaticSecret::from(<[u8;56]>::from(encoded_private_key.clone()));
        Self::from_key(recipient_private)
    }
}

// impl DecodeGenericArray<Self> for X448Decapsulator
// {
//     type EncodedLen = U56;

//     type Error = ();

//     fn decode(encoded_bytes: &GenericArray<u8, Self::EncodedLen>) -> Result<Self, Self::Error> {
//         let mut bytes = [0u8; 56];
//         bytes.copy_from_slice(&encoded_bytes);
//         let recipient_private = StaticSecret::from(bytes);
//         Ok(Self{recipient_private}) //, kdf: K::default(), phantom: PhantomData}
//     }
// }

impl<G> GetEncapsulator for X448Decapsulator<G>
{
    type Encapsulator = X448Encapsulator<G>;
    fn get_encapsulator(&self) -> Self::Encapsulator {
        let recipient_public = PublicKey::from(&self.recipient_private);
        Self::Encapsulator::from_key(recipient_public)
    }
}
impl<G> GetRecipientPublicKeyBytes for X448Decapsulator<G>
{
    type EncodedLen = U56;

    fn get_recipient_public_key_bytes(&self) -> GenericArray<u8, Self::EncodedLen> {
        self.get_encapsulator().as_bytes()
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

    fn get_recipient_public_key_bytes(&self) -> GenericArray<u8, Self::EncodedLen> {
        GenericArray::from(*self.recipient_public.as_bytes())
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

    fn get_recipient_public_key_bytes(&self) -> GenericArray<u8, Self::EncodedLen> {
        let recipient_public = PublicKey::from(&self.recipient_private);
        GenericArray::from(*recipient_public.as_bytes())
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
    
    fn generate ( _rng: &mut impl CryptoRngCore ) -> (Self::Encapsulator, Self::Decapsulator) {
        todo!()
        // let prv_a = x25519_dalek::StaticSecret::random_from_rng(&mut *rng);
        // let pub_a = x25519_dalek::PublicKey::from(&prv_a);
        // let prv_b = x25519_dalek::StaticSecret::random_from_rng(rng);
        // let pub_b = x25519_dalek::PublicKey::from(&prv_b);
        // (X25519AuthEncapsulator::from_keys(pub_a, prv_b), X25519AuthDecapsulator::from_keys(pub_b, prv_a))
    }
}




// impl<K: EcdhAuthCombiner+Default,L: ArrayLength<u8>> AuthCapsulator for X448Capsulator<K,L>{
//     type AuthSecretKey = Secret;  
//     type AuthEncapsulator = X448AuthEncapsulator<K,L>;
//     type AuthDecapsulator = X448AuthDecapsulator<K>;
// }


// Factory struct used to create X448AuthEncapsulator and X448AuthDecapsulators
// pub struct X448AuthCapsulator<K,L> (PhantomData<K>, PhantomData<L>);

// impl<K: DhAuthKemKdf+Default,L: ArrayLength<u8>> AuthCapsulator for X448AuthCapsulator<K,L>{
//     type AuthSecretKey = StaticSecret;  
//     type AuthEncapsulator = X448AuthEncapsulator<K,L>;
//     type AuthDecapsulator = X448AuthDecapsulator<K>;
// }




//
// Implementation of the DhKemKdf for use with key encapsulation mechanisms using dalek x448
// This struct converts the provided shared secret and public keys into encoded byte arrays and passes them to 
// Kdf provided as a generic type.
// 
// pub struct KdfX448AllPubKeys<K:Kdf> { 
//     kdf: K
// }
// impl<K: Kdf + Default> Default for KdfX448AllPubKeys<K>{
//     fn default() -> Self {
//         Self{ kdf: K::default()}
//     }
// }
// impl<K: Kdf + InitSalt> InitSalt for KdfX448AllPubKeys<K>
// {
//     fn new_with_salt(salt: &[u8]) -> Self {
//         return Self{kdf: K::new_with_salt(salt)}
//     }
// }
// impl<K: Kdf + Clone> DhKemKdf for KdfX448AllPubKeys<K>{
//     //type PublicKey = PublicKey;
//     //type SharedSecret = x448_dalek::SharedSecret;
//     fn derive<L:ArrayLength<u8>> (&self, raw_shared_secret: &[u8], /*Self::SharedSecret,*/ ephemeral_pub: &[u8] /*Self::PublicKey*/, recipient_pub: &[u8] /*&PublicKey*/ ) -> GenericArray<u8, L>
//     {
//         //return self.kdf.derive_self_secret_others (raw_shared_secret.as_bytes(), [ephemeral_pub, recipient_pub/*.as_bytes().as_ref()*/] )
//         return self.kdf.derive_self_secret_others (raw_shared_secret, [ephemeral_pub, recipient_pub/*.as_bytes().as_ref()*/] )
//     }
// }
// impl<K: Kdf + Clone> DhAuthKemKdf for KdfX448AllPubKeys<K>{
//     //type PublicKey = PublicKey;
//     //type SharedSecret = x448_dalek::SharedSecret;
//     fn derive<L:ArrayLength<u8>> (&self, raw_shared_secret_1: &[u8] /*Self::SharedSecret*/, raw_shared_secret_2: &[u8]/*Self::SharedSecret*/, ephemeral_pub: &[u8] /*PublicKey*/, recipient_pub: &[u8] /*PublicKey*/, sender_pub: &[u8] /*PublicKey*/ ) -> GenericArray<u8, L>
//     {
//         return self.kdf.derive_self_secrets_others ([raw_shared_secret_1, raw_shared_secret_2], [ephemeral_pub, recipient_pub, sender_pub] )
//     }
// }


//
// Implementation of the DhKemKdf for use with key encapsulation mechanisms using dalek x448
// This struct converts the provided shared secret into an encoded byte array and passes it to 
// Kdf provided as a generic type.
// 
// pub struct KdfX448NoPubKeys<K:Kdf> { 
//     kdf: K
// }
// impl<K: Kdf + Default> Default for KdfX448NoPubKeys<K>{
//     fn default() -> Self {
//         Self{ kdf: K::default()}
//     }
// }
// impl<K: Kdf + InitSalt> InitSalt for KdfX448NoPubKeys<K>
// {
//     fn new_with_salt(salt: &[u8]) -> Self {
//         return Self{kdf: K::new_with_salt(salt)}
//     }
// }
// impl<K: Kdf + Clone> DhKemKdf for KdfX448NoPubKeys<K>{
//     //type PublicKey = PublicKey;
//     //type SharedSecret = x448_dalek::SharedSecret;
//     fn derive<L:ArrayLength<u8>> (&self, raw_shared_secret: &[u8] /*Self::SharedSecret*/, _ephemeral_pub: &[u8] /*Self::PublicKey*/, _recipient_pub: &[u8]/*(&PublicKey*/ ) -> GenericArray<u8, L>
//     {
//         return self.kdf.derive_self_secret_others (raw_shared_secret, [] )
//     }
// }
// impl<K: Kdf + Clone> DhAuthKemKdf for KdfX448NoPubKeys<K>{
//     type PublicKey = PublicKey;
//     type SharedSecret = x448_dalek::SharedSecret;
//     fn derive<L:ArrayLength<u8>> (&self, raw_shared_secret_1: &Self::SharedSecret, raw_shared_secret_2: &Self::SharedSecret, ephemeral_pub: &PublicKey, recipient_pub: &PublicKey, sender_pub: &PublicKey ) -> GenericArray<u8, L>
//     {
//         return self.kdf.derive_self_secrets_others ([raw_shared_secret_1.as_bytes().as_ref(), raw_shared_secret_2.as_bytes().as_ref()], [ephemeral_pub.as_bytes().as_ref(), recipient_pub.as_bytes().as_ref(), sender_pub.as_bytes().as_ref()] )
//     }
// }






//
// Structure representing an encapsulated x448 key.
// Public x448 keys only have the x-coordinate, and are 32 bytes in length.
// The generic L field is the length of the shared secret as output from the
// try_encap and try_decap functions.
// 
// #[derive(Debug)]
// pub struct X448EncapKey <L> 
// where L: ArrayLength<u8>, 
// { 
//     //bytes: GenericArray<u8, U32>,
//     bytes: [u8; 56],
//     phantom: PhantomData<L>,
// } 
// impl <L> X448EncapKey<L> 
// where L: ArrayLength<u8> + Debug,
// {
//     pub fn generate<R: RngCore + CryptoRng> ( csprng: &mut R )-> ( X448EncapKey<L>, Secret, PublicKey )
//     {
//         let mut seed = [0u8; 56];
//         csprng.fill_bytes(&mut seed );
//         //let ephemeral_prv = Secret::new(csprng);
//         let ephemeral_prv = Secret::from_bytes(&seed).unwrap();
//         let ephemeral_pub = PublicKey::from(&ephemeral_prv);
//         let ephemeral_pub2 = PublicKey::from(&ephemeral_prv);
//         return ( Self::from(ephemeral_pub), ephemeral_prv, ephemeral_pub2);
//     }
//     ///
//     /// Convert the encapsulated key to a PublicKey
//     /// 
//     //pub fn to_public_key (&self) -> Result<PublicKey, kem::Error>{
//     pub fn to_public_key (&self) -> PublicKey{
//         //return <PublicKey as From<[u8;32]>>::from(self.bytes.into()); //.map_err(|_e|kem::Error);
//         //return <PublicKey as From<[u8;32]>>::from(self.bytes2);
//         return PublicKey::from_bytes(&self.bytes).unwrap();

//     }
    
// }


// ///
// /// Implementation of trait EncappedKey. Provides functions to import and export an X448EncapKey as a byte array
// ///
// impl <L> EncappedKey for X448EncapKey<L> 
// where L:  ArrayLength<u8> + Debug,
// {
//     type EncappedKeySize = U56;
//     type SharedSecretSize = L;
//     type SenderPublicKey = PublicKey;
//     type RecipientPublicKey = PublicKey;

//     fn from_bytes(bytes: &GenericArray<u8, Self::EncappedKeySize>) -> Result<Self, kem::Error> {
//         Ok(X448EncapKey { /*bytes: bytes.clone(),*/ bytes: (*bytes).into(), phantom: PhantomData })
//     }

    
// }
// /// Dereference coersion to a byte slice
// impl <L> AsRef<[u8]> for X448EncapKey<L> 
// where   L: ArrayLength<u8>
// {
//     /// Retrieve reference to encoded key as a byte slice
//     fn as_ref(&self) -> &[u8] {
//         //self.bytes.as_slice()
//         &self.bytes
//     }
// }


// ///
// /// Convert from x448 public key to X448EncapKey
// /// 
// impl <L> From<PublicKey> for X448EncapKey<L>
// where   L: ArrayLength<u8> + Debug,
// {
//     fn from(value: PublicKey) -> Self {
//         //let ga: &GenericArray<u8, U32> = value.as_bytes().into();
//         //return Self::from_bytes(ga).unwrap();
//         X448EncapKey { bytes: *value.as_bytes(), phantom: PhantomData }
//     }
// }




// impl<K: EcdhCombiner,L:ArrayLength<u8>> EncodedSizeUser for X448Encapsulator<K,L>
// {
//     type EncodedSize = U56;
//     fn as_bytes(&self) -> ml_kem::Encoded<Self> {
//         todo!()
//     }
//     fn from_bytes(_enc: &ml_kem::Encoded<Self>) -> Self {
//         todo!()
//     }
// }


// impl<K: EcdhCombiner, L: ArrayLength<u8>> std::fmt::Debug for X448Encapsulator<K,L>
// {
//     fn fmt(&self, _f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
//         todo!()
//     }
// }
// impl<K: EcdhCombiner,L:ArrayLength<u8>> PartialEq for X448Encapsulator<K,L>
// {
//     fn eq(&self, _other: &Self) -> bool {
//         todo!()
//     }
// }
// impl<K: EcdhCombiner,L: ArrayLength<u8>> EncapsulatorInit<K> for X448Encapsulator<K,L> 
// {
//     /// Create a new Encapsulator struct using the given kdf
//     fn new (kdf: K) -> Self {
//         Self { kdf, phantom: PhantomData, key: None } //, phantom: PhantomData }
//     }
// }

// impl<K: EcdhCombiner + Default , L: ArrayLength<u8>> Default for X448Encapsulator<K,L>
// {
//     /// Create a new Encapsulator struct using the given kdf
//     fn default () -> Self {
//         return Self::new(K::default());
//         //Self { kdf: K::default(), phantom:PhantomData, phantom2: PhantomData } //, phantom: PhantomData }
//     }
// }

// impl<K: EcdhCombiner + Default , L: ArrayLength<u8>> crate::GetPublicKey<PublicKey> for X448Encapsulator<K,L>
// {
//     fn get_public_key (&self) -> &PublicKey {
//         &self.key
//     }
    
// }



// impl<K,L> EncodePublicKey<PublicKey> for X448Encapsulator<K,L>
//     where L: ArrayLength<u8> + Debug,
//         K: EcdhCombiner<>
// {
//     type EncodedLen = U56;
//     fn encode(public_key: &PublicKey) -> GenericArray<u8, Self::EncodedLen> {
//         let b = public_key.as_bytes();
//         let g: &GenericArray<u8, U56> = b.into();
//         *g
//     }
// }




// impl<K, L> Encapsulator<X448EncapKey<L>> for X448Encapsulator<K,L> 
//     where L: ArrayLength<u8> + Debug,
//         //K: DhKemKdf<PublicKey=PublicKey,SharedSecret=x448_dalek::SharedSecret>
//         K: EcdhCombiner<>
// {
//     /// Generate and encapsulate a key using the given recipients public key
//     /// Returns the encapsulated key, as well as the shared secret
//     fn try_encap<R: CryptoRng + RngCore>(
//         &self,
//         csprng: &mut R,
//         recip_pubkey: &<X448EncapKey<L> as EncappedKey>::RecipientPublicKey
//     ) -> Result<(X448EncapKey<L>, kem::SharedSecret<X448EncapKey<L>>), kem::Error> 
//     {
//         let (encoded_ephem_pub, ephem_prv, ephem_pub) = X448EncapKey::generate(csprng);
        
//         let raw_shared_secret = ephem_prv.as_diffie_hellman(recip_pubkey).unwrap();
        
//         //let derived_shared_secret = self.kdf.derive(&raw_shared_secret, &ephem_pub, &recip_pubkey.as_bytes().as_slice());
//         let derived_shared_secret = self.kdf.combine(&raw_shared_secret.as_bytes().as_slice(), &[], &ephem_pub.as_bytes().as_slice(), &recip_pubkey.as_bytes().as_slice());
//         Ok((encoded_ephem_pub, SharedSecret::new(derived_shared_secret)))
//     }
// }

// pub struct X448Encoder();
// impl EncodePublicKey<PublicKey> for X448Encoder
// {
//     type EncodedLen = U56;
//     fn encode(public_key: &PublicKey) -> GenericArray<u8, Self::EncodedLen> {
//         let b = public_key.as_bytes();
//         let g: &GenericArray<u8, U56> = b.into();
//         *g
//     }
// }
// impl DecodePublicKey<PublicKey> for X448Encoder
// {
//     fn decode(encoded_bytes: &[u8]) -> Result<PublicKey, crate::Error> {
//         //let encoded_array: [u8; 56] = encoded_bytes.try_into()?;
//         Ok(PublicKey::from_bytes(encoded_bytes).unwrap())
//     }
// }


// impl<K,L: ArrayLength<u8>> NewAuthKem for X448AuthEncapsulator<K,L>
// where   K: EcdhAuthCombiner + Default
// {
//     fn new(sec_key: Secret) -> Self {
//         Self { kdf: K::default(), sec_key, phantom: PhantomData }
//     }
// }

// impl<K,L> Encapsulator<X448EncapKey<L>> for X448AuthEncapsulator<K,L>
// where   K: EcdhAuthCombiner<> + Default,
//         L: ArrayLength<u8> + Debug,
// {
//     /// Generate and encapsulate a key using the given recipients public key
//     /// Returns the encapsulated key, as well as the shared secret
//     fn try_encap<R: CryptoRng + RngCore>(
//         &self,
//         csprng: &mut R,
//         recip_pubkey: &<X448EncapKey<L> as EncappedKey>::RecipientPublicKey
//     ) -> Result<(X448EncapKey<L>, kem::SharedSecret<X448EncapKey<L>>), kem::Error> 
//     {
//         let (encoded_ephemeral_pub, ephem_prv, ephem_pub) = X448EncapKey::generate(csprng);
        
//         let raw_shared_secret1 = ephem_prv.as_diffie_hellman(recip_pubkey).unwrap();
//         let raw_shared_secret2 = self.sec_key.as_diffie_hellman(recip_pubkey).unwrap();

//         let derived_shared_secret = self.kdf.combine(&raw_shared_secret1.as_bytes().as_slice(), &raw_shared_secret2.as_bytes().as_slice(), &ephem_pub.as_bytes().as_slice(), recip_pubkey.as_bytes().as_slice(), &PublicKey::from(&self.sec_key).as_bytes().as_slice());
        
//         Ok((encoded_ephemeral_pub, SharedSecret::new(derived_shared_secret)))
//     }
// }



// impl<K: EcdhCombiner, L> std::fmt::Debug for X448Decapsulator<K,L>
// {
//     fn fmt(&self, _f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
//         todo!()
//     }
// }
// impl<K: EcdhCombiner,L> PartialEq for X448Decapsulator<K,L>
// {
//     fn eq(&self, _other: &Self) -> bool {
//         todo!()
//     }
// }
// impl<K,L> ml_kem::EncodedSizeUser for X448Decapsulator<K,L>
// where K: EcdhCombiner
// {
//     type EncodedSize = U56;
//     fn as_bytes(&self) -> ml_kem::Encoded<Self> {
//         todo!()
//     }
//     fn from_bytes(_enc: &ml_kem::Encoded<Self>) -> Self {
//         todo!()
//     }
//}
// impl<K: EcdhCombiner> crate::EncodePublicKey2 for X448Decapsulator<K>
// {
//     type EncodedLen = U56;
//     fn get_encoded_public_key(&self) -> GenericArray<u8, Self::EncodedLen> {
//         let pk = PublicKey::from(&self.private);
//         *GenericArray::from_slice(pk.as_bytes().as_slice())
//     }
// }

// impl<K> EncodePublicKey<PublicKey> for X448Decapsulator<K>
//     where K: EcdhCombiner
//     //where K: DhKemKdf<PublicKey=PublicKey,SharedSecret=x448_dalek::SharedSecret>
// {
//     type EncodedLen = U56;
//     fn encode(public_key: &PublicKey) -> GenericArray<u8, Self::EncodedLen> {
//         let b = public_key.as_bytes();
//         let g: &GenericArray<u8, U56> = b.into();
//         *g
//     }
// }

// impl<K: EcdhCombiner + Default> X448Decapsulator<K>{
//     /// Create a Decapsulator from a private key and kdf, which must match the recipient public key and kdf used 
//     /// during the encapsulation phase
//     pub fn new_with_params (private: Secret, kdf: K) -> Self {
//         Self { private, kdf }
//     }
// }

// impl<K,L> kem::Decapsulator<X448EncapKey<L>> for X448Decapsulator<K> 
// where K: EcdhCombiner<> + Default,
//     L: ArrayLength<u8> + Debug,
// {
//     ///
//     /// Decapsulate the provided Encapsulated key
//     /// 
//     fn try_decap(&self, encapped_key: &X448EncapKey<L>) -> Result<SharedSecret<X448EncapKey<L>>, kem::Error> 
//     {
//         let raw_shared_secret = self.private.as_diffie_hellman (&encapped_key.to_public_key()).unwrap();
//         let derived_shared_key = self.kdf.combine(&raw_shared_secret.as_bytes().as_slice(), &[], &encapped_key.bytes /*&encapped_key.to_public_key()*/, &PublicKey::from(&self.private).as_bytes().as_slice());

//         Ok(SharedSecret::<X448EncapKey<L>>::new(derived_shared_key))
//     }
// }



// impl <K: EcdhAuthCombiner + Default> PrivateKeyInit<Secret> for X448AuthDecapsulator<K> {
//     fn new ( private: Secret) -> Self {
//         Self { private, kdf: K::default() }
//     }
// }

//
// Authenticated decapsulation. X448Decapsulator object contains the private key needed
// to decrypt the message, and the passed in public key is used to ensure the sender is authenticated
// 
// impl<K,L> AuthDecapsulator<X448EncapKey<L>> for X448AuthDecapsulator<K> 
// where   K: EcdhAuthCombiner<>,
//         L: ArrayLength<u8> + Debug
// {
//     ///
//     /// Decapsulate the provided Encapsulated key
//     /// 
//     fn try_auth_decap(&self, encapped_key: &X448EncapKey<L>, sender_pubkey: &PublicKey) 
//         -> Result<SharedSecret<X448EncapKey<L>>, kem::Error> 
//     {
//         let raw_shared_secret1 = self.private.as_diffie_hellman(&encapped_key.to_public_key()).unwrap();
//         let raw_shared_secret2 = self.private.as_diffie_hellman(sender_pubkey).unwrap();

//         let derived_shared_key = self.kdf.combine(&raw_shared_secret1.as_bytes().as_slice(), &raw_shared_secret2.as_bytes().as_slice(), 
//             &encapped_key.as_bytes(), &PublicKey::from(&self.private).as_bytes().as_slice(), &sender_pubkey.as_bytes().as_slice());

//         Ok(SharedSecret::<X448EncapKey<L>>::new(derived_shared_key))
//     }
// }





/////////////
// Implementation of KEM traits from ml-kem
// 
// 

// impl<K, L> ml_kem::kem::Encapsulate<hybrid_array::Array<u8,U56>, hybrid_array::Array<u8,L>> for X448Encapsulator<K, L>
// where L:ArrayLength<u8> + Debug + ArraySize,
//     K: EcdhCombiner
// {
//     type Error = kem::Error;
//     fn encapsulate(&self, rng: &mut impl rand_core::CryptoRngCore) -> Result<(hybrid_array::Array<u8,U56>, hybrid_array::Array<u8,L>), Self::Error> {
//         let (ek, ss) = self.try_encap( rng, &self.key.as_ref().unwrap() )?;
//         Ok((hybrid_array::Array::from(ek.bytes), hybrid_array::Array::try_from(ss.as_bytes()).unwrap()))
//     }
// }


// impl<K, L> ml_kem::EncapsulateDeterministic<hybrid_array::Array<u8,U56>, hybrid_array::Array<u8,L>> for X448Encapsulator <K, L>
// where L:ArrayLength<u8> + Debug + ArraySize,
//     K: EcCombiner
// {
//     type Error = kem::Error;
//     fn encapsulate_deterministic(&self, _m: &ml_kem::B32) -> Result<(hybrid_array::Array<u8,U56>, hybrid_array::Array<u8,L>), Self::Error> {
//         todo!()
//     }
// }


// impl<K,L> ml_kem::KemCore for X448Capsulator<K,L>
// where L: ArrayLength<u8> + Debug + hybrid_array::ArraySize + PartialEq,
//     K: EcdhCombiner + Default
// {
//     type CiphertextSize = U56;
//     type SharedKeySize = L;
//     type DecapsulationKey = X448Decapsulator<K>;
//     type EncapsulationKey = X448Encapsulator<K,L>;

//     fn generate(rng: &mut impl rand_core::CryptoRngCore) -> (Self::DecapsulationKey, Self::EncapsulationKey) {
//         let mut seed = [0u8; 56];
//         rng.fill_bytes(&mut seed);
//         let private = x448::Secret::from_bytes(&seed).unwrap();
//         let public = x448::PublicKey::from(&private);
//         (X448Decapsulator::new(private), X448Encapsulator::from(public))
//     }
//     // fn generate_deterministic(_d: &ml_kem::B32, _z: &ml_kem::B32)
//     //         -> (Self::DecapsulationKey, Self::EncapsulationKey) {
//     //     todo!();
//     // }
// }


