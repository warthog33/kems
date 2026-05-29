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
//! let (encapsulator, decapsulator) = KemWithKdf::<X25519Capsulator<SeedAsScalar>, CombinerAllPubKeys, Kdf1::<Sha256>, U32>::generate(&mut OsRng);
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

use std::marker::PhantomData;
use crate::{Capsulator, CryptoRngCore, Decapsulate, DeriveKeyPairFromSeed, Encapsulate, EncapsulateDeterministic2, EncodedSizeUser2, FromKey, FromKeys, GenerateCapsulatorFromSeed, GetRecipientPublicKeyBytes, GetSenderPublicKeyBytes, GetEncapsulator};
use crate::eckem::{SeedAsScalar};
use crate::generic_array::{GenericArray};
use crate::generic_array::typenum::Unsigned;

use cipher::typenum::consts::*;
use kdfs::hybrid_array::Array;
use x25519_dalek::{PublicKey, StaticSecret};


impl DeriveKeyPairFromSeed<StaticSecret> for SeedAsScalar 
{
    type SeedSize = U32;
    type PublicKey = PublicKey;
    type Error = ();
    //fn derive_keypair_from_seed( seed: &Array::<u8, Self::SeedSize>) -> (StaticSecret, PublicKey) {
    fn derive_keypair_from_seed( seed: &[u8]) -> Result<(StaticSecret, PublicKey), Self::Error> {
        let Ok(seed_array) : Result<[u8; 32],_> = seed.try_into() else { return Err(())};
        let priv_key = StaticSecret::from(seed_array);
        let pub_key = PublicKey::from(&priv_key);
        Ok((priv_key, pub_key))
    }
}


/// Factory struct used to create X25519Encapsulator and X25519Decapsulators
pub struct X25519Capsulator<G> (PhantomData<G>);

impl<G> Capsulator for X25519Capsulator<G>
{
    type Encapsulator = X25519Encapsulator<G>;
    type Decapsulator = X25519Decapsulator<G>;
    type CiphertextSize = U32;
    type SharedKeySize = U32;
    
    fn generate ( rng: &mut impl CryptoRngCore ) -> (Self::Encapsulator, Self::Decapsulator) {
        let private = StaticSecret::random_from_rng(rng);
        let public = PublicKey::from(&private);
        (X25519Encapsulator::from_key(public), X25519Decapsulator::from_key(private))
    }
}

impl<G> GenerateCapsulatorFromSeed for X25519Capsulator<G>
where G: DeriveKeyPairFromSeed<StaticSecret, PublicKey = PublicKey>
{
    type SeedSize = G::SeedSize;
    fn derive_from_seed(seed: &cipher::Array::<u8, Self::SeedSize>) -> (Self::Encapsulator, Self::Decapsulator) {
        let Ok(( private, public)) = G::derive_keypair_from_seed(seed) else { panic! ( "Generation failed")};
        (X25519Encapsulator::from_key(public), X25519Decapsulator::from_key(private))    
    }
}




///
/// Structure used to create encapsulated keys and derive 
/// shared secrets.
/// 
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

impl<G> EncapsulateDeterministic2<GenericArray<u8,U32>, Array<u8,U32>> for X25519Encapsulator<G>
where G: DeriveKeyPairFromSeed<StaticSecret, PublicKey=PublicKey>
{
    type Error = ();
    type SeedSize = G::SeedSize; //U32;
    
    fn encapsulate_deterministic(&self, seed: &[u8]) -> Result<(GenericArray<u8,U32>, Array<u8,U32>), Self::Error> {
        //let ephem_prv = StaticSecret::from(seed.0);
        if seed.len() < Self::SeedSize::USIZE { return Err(())}
        let Ok((ephem_prv, _ephem_pub)) = G::derive_keypair_from_seed(seed) else { return Err(())};
        self.encapsulate_from_key(ephem_prv)
    }
}


impl<G> EncodedSizeUser2 for X25519Encapsulator<G>
{
    type EncodedSize = U32;
    fn as_bytes(&self) -> crate::Encoded<Self> {
        GenericArray::from(*self.recipient_public.as_bytes())
    }
    fn from_bytes(encoded_public_key: &crate::Encoded<Self>) -> Self {
        let encoded_array: &[u8;32] = encoded_public_key.as_ref();
        Self::from_key(PublicKey::from(*encoded_array))
    }
}

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

    fn get_recipient_public_key_bytes(&self) -> GenericArray<u8, Self::EncodedLen> {
        GenericArray::from(self.recipient_public.to_bytes())
    }
}





///
/// Struct enabling receipt of a X25519EncapKey and recovery of the shared secret
/// 
pub struct X25519Decapsulator<G>
{
    recipient_private: StaticSecret,
    phantom: PhantomData<G>
}


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


impl<G> crate::EncodedSizeUser2 for X25519Decapsulator<G>
{
    type EncodedSize = U32;
    fn as_bytes(&self) -> crate::Encoded<Self> {
        GenericArray::from(*self.recipient_private.as_bytes())
    }
    fn from_bytes(enc: &crate::Encoded<Self>) -> Self {
        let encoded_array: &[u8; 32] = enc.as_ref();
        Self::from_key(x25519_dalek::StaticSecret::from(*encoded_array))
    }
}

impl<G> GetEncapsulator for X25519Decapsulator<G>
{
    type Encapsulator = X25519Encapsulator<G>;
    fn get_encapsulator(&self) -> Self::Encapsulator {
        Self::Encapsulator::from_key ( PublicKey::from(&self.recipient_private))
    }
}

impl<G> GetRecipientPublicKeyBytes for X25519Decapsulator<G>
{
    type EncodedLen = U32;

    fn get_recipient_public_key_bytes(&self) -> GenericArray<u8, Self::EncodedLen> {
        GenericArray::from(PublicKey::from(&self.recipient_private).to_bytes())
    }
}





pub struct X25519AuthCapsulator<G=SeedAsScalar> (PhantomData<G>);

impl<G> Capsulator for X25519AuthCapsulator<G>
where G: DeriveKeyPairFromSeed<StaticSecret, PublicKey=PublicKey>
{
    type Encapsulator = X25519AuthEncapsulator<G>;
    type Decapsulator = X25519AuthDecapsulator;
    type CiphertextSize = U32;
    type SharedKeySize = U64;
    
    fn generate ( rng: &mut impl CryptoRngCore ) -> (Self::Encapsulator, Self::Decapsulator) {
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
where G: DeriveKeyPairFromSeed<StaticSecret, PublicKey=PublicKey>
{
    type Error = ();

    fn encapsulate(&self, rng: &mut impl CryptoRngCore) -> Result<(GenericArray<u8,U32>, Array<u8,U64>), Self::Error> {
        let mut seed = Array::<u8, <Self as EncapsulateDeterministic2<GenericArray<u8,U32>, Array<u8,U64>>>::SeedSize>::default();
        rng.fill_bytes(&mut seed);
        self.encapsulate_deterministic(&seed)
    }
}

impl<G> EncapsulateDeterministic2<GenericArray<u8,U32>, Array<u8,U64>> for X25519AuthEncapsulator<G>
where G: DeriveKeyPairFromSeed<StaticSecret, PublicKey=PublicKey>
{
    type Error = ();
    type SeedSize = G::SeedSize;
    
    fn encapsulate_deterministic(&self, seed: &[u8]) -> Result<(GenericArray<u8,U32>, Array<u8,U64>), Self::Error> {
        if seed.len() < Self::SeedSize::USIZE { return Err(())}
        let Ok((ephem_prv, ephem_pub)) = G::derive_keypair_from_seed(seed) else { return Err(())};
        
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

    fn get_recipient_public_key_bytes(&self) -> GenericArray<u8, Self::EncodedLen> {
        GenericArray::from(*self.recipient_public.as_bytes())
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

        let mut raw_shared_secret = Array::default(); //raw_shared_secret_1.concat(raw_shared_secret_2);
        raw_shared_secret[..U32::USIZE].copy_from_slice(raw_shared_secret1.as_bytes());
        raw_shared_secret[U32::USIZE..].copy_from_slice(raw_shared_secret2.as_bytes());

        Ok ( raw_shared_secret)
    }
}

impl GetRecipientPublicKeyBytes for X25519AuthDecapsulator
{
    type EncodedLen = U32;

    fn get_recipient_public_key_bytes(&self) -> GenericArray<u8, Self::EncodedLen> {
        let recipient_public = PublicKey::from(&self.recipient_private);
        GenericArray::from(*recipient_public.as_bytes())
    }
}

impl GetSenderPublicKeyBytes for X25519AuthDecapsulator
{
    type EncodedLen = U32;

    fn get_sender_public_key_bytes(&self) -> GenericArray<u8, Self::EncodedLen> {
        GenericArray::from(*self.sender_public.as_bytes())
    }
}





// impl <K: EcdhCombiner + Default> From<StaticSecret> for X25519Decapsulator<K> {
//     fn from ( private: StaticSecret) -> Self {
//         return Self::new_with_params(private, K::default())
//     }
// }



// X25519AuthCapsulator<kems::eckem::EcCombinerAllPubKeys<
//     key_derivation::rfc9180_hpke::HpkeKemKdf<Tkdf<Ktf1<CoreWrapper<HmacCore<CoreWrapper<CtVariableCoreWrapper<Sha256VarCore, UInt<UInt<UInt<UInt<UInt<UInt<UTerm, B1>, B0>, B0>, B0>, B0>, B0>, OidSha256>>>>>, 
//     Kpf1<CoreWrapper<HmacCore<CoreWrapper<CtVariableCoreWrapper<Sha256VarCore, UInt<UInt<UInt<UInt<UInt<UInt<UTerm, B1>, B0>, B0>, B0>, B0>, B0>, OidSha256>>>>, u8>>, 32>>, 
//     UInt<UInt<UInt<UInt<UInt<UInt<UTerm, B1>, B0>, B0>, B0>, B0>, B0>>: Capsulator


// /
// / Structure representing an encapsulated x25519 key.
// / Public x25519 keys only have the x-coordinate, and are 32 bytes in length.
// / The generic L field is the length of the shared secret as output from the
// / try_encap and try_decap functions.
// / 
// #[derive(Debug)]
// pub struct X25519EncapKey <L> 
// where L: ArrayLength<u8>, 
// { 
//     //bytes: GenericArray<u8, U32>,
//     bytes: [u8; 32],
//     phantom: PhantomData<L>,
// } 
// impl <L> X25519EncapKey<L> 
// where L: ArrayLength<u8> + Debug,
// {
//     pub fn generate<R: CryptoRng + RngCore> ( csprng: &mut R )-> ( X25519EncapKey<L>, EphemeralSecret, PublicKey )
//     {
//         let ephemeral_prv = EphemeralSecret::random_from_rng(csprng);
//         let ephemeral_pub = PublicKey::from(&ephemeral_prv);
//         return ( Self::from(ephemeral_pub), ephemeral_prv, ephemeral_pub);
//     }
//     ///
//     /// Convert the encapsulated key to a PublicKey
//     /// 
//     //pub fn to_public_key (&self) -> Result<PublicKey, kem::Error>{
//     pub fn to_public_key (&self) -> PublicKey{
//         //return <PublicKey as From<[u8;32]>>::from(self.bytes.into()); //.map_err(|_e|kem::Error);
//         //return <PublicKey as From<[u8;32]>>::from(self.bytes2);
//         return PublicKey::from(self.bytes);

//     }
    
// }


//
// Implementation of trait EncappedKey. Provides functions to import and export an X25519EncapKey as a byte array
//
// impl <L> EncappedKey for X25519EncapKey<L> 
// where L:  ArrayLength<u8> + Debug,
// {
//     type EncappedKeySize = U32;
//     type SharedSecretSize = L;
//     type SenderPublicKey = PublicKey;
//     type RecipientPublicKey = PublicKey;

//     fn from_bytes(bytes: &GenericArray<u8, Self::EncappedKeySize>) -> Result<Self, kem::Error> {
//         Ok(X25519EncapKey { /*bytes: bytes.clone(),*/ bytes: (*bytes).into(), phantom: PhantomData })
//     }

    
// }
// /// Dereference coersion to a byte slice
// impl <L> AsRef<[u8]> for X25519EncapKey<L> 
// where   L: ArrayLength<u8>
// {
//     /// Retrieve reference to encoded key as a byte slice
//     fn as_ref(&self) -> &[u8] {
//         //self.bytes.as_slice()
//         &self.bytes
//     }
// }


// ///
// /// Convert from x25519 public key to X25519EncapKey
// /// 
// impl <L> From<PublicKey> for X25519EncapKey<L>
// where   L: ArrayLength<u8> + Debug,
// {
//     fn from(value: PublicKey) -> Self {
//         //let ga: &GenericArray<u8, U32> = value.as_bytes().into();
//         //return Self::from_bytes(ga).unwrap();
//         X25519EncapKey { bytes: *value.as_bytes(), phantom: PhantomData }
//     }
// }




// impl<K: EcdhCombiner,L: ArrayLength<u8>> EncapsulatorInit<K> for X25519Encapsulator<K,L> 
// {
//     /// Create a new Encapsulator struct using the given kdf
//     fn new (kdf: K) -> Self {
//         Self { kdf, phantom: PhantomData, key: None } //, phantom: PhantomData }
//     }
// }


// impl<K, L> Encapsulator<X25519EncapKey<L>> for X25519Encapsulator<K,L> 
//     where L: ArrayLength<u8> + Debug,
//         //K: DhKemKdf<PublicKey=PublicKey,SharedSecret=x25519_dalek::SharedSecret>
//         K: EcdhCombiner<>
// {
//     /// Generate and encapsulate a key using the given recipients public key
//     /// Returns the encapsulated key, as well as the shared secret
//     fn try_encap<R: CryptoRng + RngCore>(
//         &self,
//         csprng: &mut R,
//         recip_pubkey: &<X25519EncapKey<L> as EncappedKey>::RecipientPublicKey
//     ) -> Result<(X25519EncapKey<L>, kem::SharedSecret<X25519EncapKey<L>>), kem::Error> 
//     {
//         let (encoded_ephem_pub, ephem_prv, ephem_pub) = X25519EncapKey::generate(csprng);
        
//         let raw_shared_secret = ephem_prv.diffie_hellman(recip_pubkey);
        
//         //let derived_shared_secret = self.kdf.derive(&raw_shared_secret, &ephem_pub, &recip_pubkey.as_bytes().as_slice());
//         let derived_shared_secret = self.kdf.combine(&raw_shared_secret.as_bytes().as_slice(), &[], &ephem_pub.as_bytes().as_slice(), &recip_pubkey.as_bytes().as_slice());
//         Ok((encoded_ephem_pub, SharedSecret::new(derived_shared_secret)))
//     }
// }



// impl<K,L> Clone for X25519Encapsulator<K,L>
//     where L: ArrayLength<u8> + Debug,
//         K: EcdhCombiner<> + Default
// {
//     fn clone(&self) -> Self {
//         Self { kdf: K::default(), phantom: PhantomData, recipient_public: self.recipient_public.clone() }
//     }    
// }



// impl<K: EcdhCombiner, L: ArrayLength<u8>> EncodedSizeUser for X25519Encapsulator<K,L>
// where K: Default
// {
//     type EncodedSize = U32;
//     fn as_bytes(&self) -> ml_kem::Encoded<Self> {
//         let key = &self.key;
//         hybrid_array::Array::from(*key.as_bytes())
//     }
//     fn from_bytes(enc: &ml_kem::Encoded<Self>) -> Self {
//         //let enc =
//         let encoded_array: [u8; 32] = enc.as_slice().try_into().unwrap();
//         let pk = PublicKey::from(encoded_array);

//         Self { kdf: K::default(), phantom: PhantomData, key: pk}
//     }
// }
// impl<K: EcdhCombiner, L: ArrayLength<u8>> std::fmt::Debug for X25519Encapsulator<K,L>
// {
//     fn fmt(&self, _f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
//         todo!()
//     }
// }
// impl<K: EcdhCombiner,L:ArrayLength<u8>> PartialEq for X25519Encapsulator<K,L>
// {
//     fn eq(&self, _other: &Self) -> bool {
//         todo!()
//     }
// }

// impl<K,L> EncodePublicKey<PublicKey> for X25519Encapsulator<K,L>
//     where L: ArrayLength<u8> + Debug,
//         K: EcdhCombiner<>
// {
//     type EncodedLen = U32;
//     fn encode(public_key: &PublicKey) -> GenericArray<u8, Self::EncodedLen> {
//         X25519Encoder::encode(public_key)
//     }
// }
// impl<K,L> crate::Encode for X25519Encapsulator<K,L>
//     where L: ArrayLength<u8> + Debug,
//         K: EcdhCombiner<>
// {
//     type EncodedLen = U32;
//     fn encode(&self) -> GenericArray<u8, Self::EncodedLen> {
//         let b = GenericArray::default(); //self.public_key.as_bytes();
//         let g: &GenericArray<u8, U32> = &b.into();
//         *g
//     }
//     fn decode(enc: &GenericArray<u8, Self::EncodedLen>) -> Self {
//         todo!()
//     }
// }






// impl<K,L: ArrayLength<u8>> PrivateKeyInit<StaticSecret> for X25519AuthEncapsulator<K,L>
// where   K: EcdhAuthCombiner + Default
// {
//     fn new(sec_key: StaticSecret) -> Self {
//         Self { kdf: K::default(), sec_key, phantom: PhantomData, recip_key: None }
//     }
// }

//
// Implementation of authenticated key encapsulation
// 
// impl<K,L> Encapsulator<X25519EncapKey<L>> for X25519AuthEncapsulator<K,L>
// where   K: EcdhAuthCombiner<> + Default,
//         L: ArrayLength<u8> + Debug,
// {
//     /// Generate and encapsulate a key using the given recipients public key
//     /// Returns the encapsulated key, as well as the shared secret
//     fn try_encap<R: CryptoRng + RngCore>(
//         &self,
//         csprng: &mut R,
//         recip_pubkey: &<X25519EncapKey<L> as EncappedKey>::RecipientPublicKey
//     ) -> Result<(X25519EncapKey<L>, kem::SharedSecret<X25519EncapKey<L>>), kem::Error> 
//     {
//         let (encoded_ephemeral_pub, ephem_prv, ephem_pub) = X25519EncapKey::generate(csprng);
        
//         let raw_shared_secret1 = ephem_prv.diffie_hellman(recip_pubkey);
//         let raw_shared_secret2 = self.sec_key.diffie_hellman(recip_pubkey);

//         let derived_shared_secret = self.kdf.combine(&raw_shared_secret1.as_bytes().as_slice(), &raw_shared_secret2.as_bytes().as_slice(), &ephem_pub.as_bytes().as_slice(), recip_pubkey.as_bytes().as_slice(), &PublicKey::from(&self.sec_key).as_bytes().as_slice());
        
//         Ok((encoded_ephemeral_pub, SharedSecret::new(derived_shared_secret)))
//     }
// }







// impl<K,L> kem::Decapsulator<X25519EncapKey<L>> for X25519Decapsulator<K> 
// where K: EcdhCombiner<> + Default,
//     L: ArrayLength<u8> + Debug,
// {
//     ///
//     /// Decapsulate the provided Encapsulated key
//     /// 
//     fn try_decap(&self, encapped_key: &X25519EncapKey<L>) -> Result<SharedSecret<X25519EncapKey<L>>, kem::Error> 
//     {
//         let raw_shared_secret = self.private.diffie_hellman (&encapped_key.to_public_key());
//         let derived_shared_key = self.kdf.combine(&raw_shared_secret.as_bytes().as_slice(), &[], &encapped_key.bytes /*&encapped_key.to_public_key()*/, &PublicKey::from(&self.private).as_bytes().as_slice());

//         Ok(SharedSecret::<X25519EncapKey<L>>::new(derived_shared_key))
//     }
// }

// impl<K,L> DecapsulatorWithKeyWrap<X25519EncapKey<L>> for X25519Decapsulator<K> 
// where K: DhKemKdf<> + Default,
//     L: ArrayLength<u8> + Debug,
//     {}






// impl<K: EcdhAuthCombiner> EncodedSizeUser2 for X25519AuthDecapsulator<K> {
//     type EncodedSize = U32;
//     fn as_bytes(&self) -> crate::Encoded<Self> {
//         todo!()
//     }
//     fn from_bytes(enc: &crate::Encoded<Self>) -> Self {
//         todo!()
//     }
// }

// impl <K: EcdhAuthCombiner + Default> PrivateKeyInit<StaticSecret> for X25519AuthDecapsulator<K> {
//     fn new ( private: StaticSecret) -> Self {
//         Self { private, kdf: K::default(), sender: None }
//     }
// }


// impl <K: EcdhAuthCombiner + Default> X25519AuthDecapsulator<K> {
//     pub fn new2 ( private: StaticSecret, sender: PublicKey) -> Self {
//         Self { private, kdf: K::default(), sender: Some(sender) }
//     }
// }

//
// Authenticated decapsulation. X25519Decapsulator object contains the private key needed
// to decrypt the message, and the passed in public key is used to ensure the sender is authenticated
// 
// impl<K,L> AuthDecapsulator<X25519EncapKey<L>> for X25519AuthDecapsulator<K> 
// where   K: EcdhAuthCombiner<>,
//         L: ArrayLength<u8> + Debug
// {
//     ///
//     /// Decapsulate the provided Encapsulated key
//     /// 
//     fn try_auth_decap(&self, encapped_key: &X25519EncapKey<L>, sender_pubkey: &PublicKey) 
//         -> Result<SharedSecret<X25519EncapKey<L>>, kem::Error> 
//     {
//         let raw_shared_secret1 = self.private.diffie_hellman(&encapped_key.to_public_key());
//         let raw_shared_secret2 = self.private.diffie_hellman(sender_pubkey);

//         let derived_shared_key = self.kdf.combine(&raw_shared_secret1.as_bytes().as_slice(), &raw_shared_secret2.as_bytes().as_slice(), 
//             &encapped_key.as_bytes(), &PublicKey::from(&self.private).as_bytes().as_slice(), &sender_pubkey.as_bytes().as_slice());

//         Ok(SharedSecret::<X25519EncapKey<L>>::new(derived_shared_key))
//     }
// }

// impl<K: EcdhCombiner> PartialEq for X25519Decapsulator<K>
// {
//     fn eq(&self, _other: &Self) -> bool {
//         todo!()
//     }
// }


//////////////
// Implementation of KEM traits from ml-kem
// 
// 

// impl<K, L> ml_kem::kem::Encapsulate<hybrid_array::Array<u8,U32>, hybrid_array::Array<u8,L>> for X25519Encapsulator <K, L>
// where L:ArrayLength<u8> + Debug + ArraySize,
//     K: EcdhCombiner
// {
//     type Error = kem::Error;
//     fn encapsulate(&self, rng: &mut impl rand_core::CryptoRngCore) -> Result<(hybrid_array::Array<u8,U32>, hybrid_array::Array<u8,L>), Self::Error> {
//         let (ek, ss) = self.try_encap( rng, &self.key.unwrap() )?;
//         Ok((hybrid_array::Array::from(ek.bytes), hybrid_array::Array::try_from(ss.as_bytes()).unwrap()))
//     }
// }




// impl<K, L> ml_kem::EncapsulateDeterministic<hybrid_array::Array<u8,U32>, hybrid_array::Array<u8,L>> for X25519Encapsulator <K, L>
// where L:ArrayLength<u8> + Debug + ArraySize,
//     K: EcCombiner
// {
//     type Error = kem::Error;
//     fn encapsulate_deterministic(&self, _m: &ml_kem::B32) -> Result<(hybrid_array::Array<u8,U32>, hybrid_array::Array<u8,L>), Self::Error> {
//         todo!()
//     }
// }

// impl<K,L> ml_kem::kem::Decapsulate<hybrid_array::Array<u8, U32>, hybrid_array::Array<u8, L>> for X25519Decapsulator<K>
// where L: hybrid_array::ArraySize + ArrayLength<u8> + Debug,
//     K: EcdhCombiner + Default
// {
//     type Error = kem::Error;
//     fn decapsulate(&self, encapsulated_key: &hybrid_array::Array<u8, U32>) -> Result<hybrid_array::Array<u8, L>, Self::Error> {

//         let ek = X25519EncapKey::<L>::from_bytes(GenericArray::from_slice(encapsulated_key.as_slice()))?;
//         let ss = self.try_decap(&ek)?;
//         Ok(hybrid_array::Array::try_from(ss.as_bytes()).unwrap())
//     }
// }





// impl<K,L> ml_kem::KemCore for X25519Capsulator<K,L>
// where L: ArrayLength<u8> + Debug + hybrid_array::ArraySize + PartialEq,
//     K: EcdhCombiner + Default
// {
//     type CiphertextSize = U32;
//     type SharedKeySize = L;
//     type DecapsulationKey = X25519Decapsulator<K>;
//     type EncapsulationKey = X25519Encapsulator<K,L>;

//     fn generate(rng: &mut impl rand_core::CryptoRngCore) -> (Self::DecapsulationKey, Self::EncapsulationKey) {
//         let private = x25519_dalek::StaticSecret::random_from_rng(rng);
//         let public = x25519_dalek::PublicKey::from(&private);
//         (X25519Decapsulator::new(private), X25519Encapsulator::from(public))
//     }
//     // fn generate_deterministic(_d: &ml_kem::B32, _z: &ml_kem::B32)
//     //         -> (Self::DecapsulationKey, Self::EncapsulationKey) {
//     //     todo!();
//     // }
// }







// impl<K, L> ml_kem::kem::Encapsulate<hybrid_array::Array<u8,U32>, hybrid_array::Array<u8,L>> for X25519AuthEncapsulator <K, L>
// where L:ArrayLength<u8> + Debug + ArraySize,
//     K: DhAuthKemKdf
// {
//     type Error = kem::Error;
//     fn encapsulate(&self, rng: &mut impl rand_core::CryptoRngCore) -> Result<(hybrid_array::Array<u8,U32>, hybrid_array::Array<u8,L>), Self::Error> {
//         let (ek, ss) = self.try_encap( rng, &self.key.unwrap() )?;
//         Ok((hybrid_array::Array::from(ek.bytes), hybrid_array::Array::try_from(ss.as_bytes()).unwrap()))
//     }
// }
// impl<K, L> ml_kem::EncapsulateDeterministic<hybrid_array::Array<u8,U32>, hybrid_array::Array<u8,L>> for X25519AuthEncapsulator <K, L>
// where L:ArrayLength<u8> + Debug + ArraySize,
//     K: DhAuthKemKdf
// {
//     type Error = kem::Error;
//     fn encapsulate_deterministic(&self, m: &ml_kem::B32) -> Result<(hybrid_array::Array<u8,U32>, hybrid_array::Array<u8,L>), Self::Error> {
//         todo!()
//     }
// }

// impl<K,L> ml_kem::kem::Decapsulate<hybrid_array::Array<u8, U32>, hybrid_array::Array<u8, L>> for X25519AuthDecapsulator<K>
// where L: hybrid_array::ArraySize + ArrayLength<u8> + Debug,
//     K: DhAuthKemKdf + Default
// {
//     type Error = kem::Error;
//     fn decapsulate(&self, encapsulated_key: &hybrid_array::Array<u8, U32>) -> Result<hybrid_array::Array<u8, L>, Self::Error> {

//         let ek = X25519EncapKey::<L>::from_bytes(GenericArray::from_slice(encapsulated_key.as_slice()))?;
//         let ss = self.try_decap(&ek)?;
//         Ok(hybrid_array::Array::try_from(ss.as_bytes()).unwrap())
//     }
// }
// impl<K> ml_kem::EncodedSizeUser for X25519AuthDecapsulator<K>
// where K: DhAuthKemKdf
// {
//     type EncodedSize = U32;
//     fn as_bytes(&self) -> ml_kem::Encoded<Self> {
//         todo!()
//     }
//     fn from_bytes(enc: &ml_kem::Encoded<Self>) -> Self {
//         todo!()
//     }
// }
// impl<K: DhAuthKemKdf> std::fmt::Debug for X25519AuthDecapsulator<K>
// {
//     fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
//         todo!()
//     }
// }
// impl<K: DhAuthKemKdf, L: ArrayLength<u8>> std::fmt::Debug for X25519AuthEncapsulator<K,L>
// {
//     fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
//         todo!()
//     }
// }
// impl<K: DhAuthKemKdf> PartialEq for X25519AuthDecapsulator<K>
// {
//     fn eq(&self, other: &Self) -> bool {
//         todo!()
//     }
// }
// impl<K: DhAuthKemKdf,L:ArrayLength<u8>> PartialEq for X25519AuthEncapsulator<K,L>
// {
//     fn eq(&self, other: &Self) -> bool {
//         todo!()
//     }
// }
// impl<K: DhAuthKemKdf,L:ArrayLength<u8>> EncodedSizeUser for X25519AuthEncapsulator<K,L>
// {
//     type EncodedSize = U32;
//     fn as_bytes(&self) -> ml_kem::Encoded<Self> {
//         todo!()
//     }
//     fn from_bytes(enc: &ml_kem::Encoded<Self>) -> Self {
//         todo!()
//     }
// }
// impl<K,L> ml_kem::KemCore for X25519AuthCapsulator<K,L>
// where L: ArrayLength<u8> + Debug + hybrid_array::ArraySize + PartialEq,
//     K: DhAuthKemKdf + Default
// {
//     type CiphertextSize = U32;
//     type SharedKeySize = L;
//     type DecapsulationKey = X25519Decapsulator<K>;
//     type EncapsulationKey = X25519Encapsulator<K,L>;

//     fn generate(rng: &mut impl rand_core::CryptoRngCore) -> (Self::DecapsulationKey, Self::EncapsulationKey) {
//         let private = x25519_dalek::StaticSecret::random_from_rng(rng);
//         let public = x25519_dalek::PublicKey::from(&private);
//         (X25519Decapsulator::new(private), X25519Encapsulator::from(public))
//     }
//     fn generate_deterministic(d: &ml_kem::B32, z: &ml_kem::B32)
//             -> (Self::DecapsulationKey, Self::EncapsulationKey) {
//         todo!();
//     }
// }
// pub struct X25519Encoder();
// impl EncodePublicKey<PublicKey> for X25519Encoder
// {
//     type EncodedLen = U32;
//     fn encode(public_key: &PublicKey) -> GenericArray<u8, Self::EncodedLen> {
//         let b = public_key.as_bytes();
//         let g: &GenericArray<u8, U32> = b.into();
//         *g
//     }
// }
// impl DecodePublicKey<PublicKey> for X25519Encoder
// {
//     fn decode(encoded_bytes: &[u8]) -> Result<PublicKey, crate::Error> {
//         let encoded_array: [u8; 32] = encoded_bytes.try_into()?;
//         Ok(PublicKey::from(encoded_array))
//     }
// }
