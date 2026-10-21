//!
//! Key exchange mechanism using RSA cryptography as per ISO 18033-3 and NIST SP800-56B
//! 
//! This module implements functionality required by both a sender and a recipient.
//! The sender obtains the public key of the recipient and uses it to encrypt a randomly generated secret.
//! The encrypted value is sent to the recipient, which uses its private key to decrypt the message and recover the secret.
//! Both sender and recipient pass the secret through a key derivation function to calculate the shared secret usable as a cryptographic key
//!  
//! # Example 
//! ```
//! use elliptic_curve::consts::*;
//! use sha2::Sha256;
//! use kems::{FromKey, KemExtensions};
//! use kem::{TryDecapsulate, Encapsulate};
//! use kems::rsakem::{RsaOrigKem};
//! use kdfs::iso18033_2::Kdf1;
//! use rand_core::OsRng;
//! 
//! let recipient_private_key = rsa::RsaPrivateKey::new(&mut rand::rng(), 1024).expect("failed to generate a key");
//! let recipient_public_key = recipient_private_key.to_public_key();
//! 
//! let encapsulator = RsaOrigKem::<U128, U16, Kdf1::<Sha256>>::from_public_key(recipient_public_key);
//! let (ct, k_send) = encapsulator.encapsulate();
//! 
//! let decapsulator = RsaOrigKem::<U128, U16,Kdf1::<Sha256>>::from_private_key(recipient_private_key);
//! let (k_recv) = decapsulator.try_decapsulate(&ct).unwrap();
//! assert! ( k_send == k_recv);
//!

use std::marker::PhantomData;
use std::fmt::Debug;
use std::ops::Add;

use crate::kem_with_kdf::{CombinerNoKeys, KemWithKdf};
use crate::{EncapsulateDeterministic, FromKey};
use cipher::KeySizeUser;
use cipher::common::{KeyExport, TryKeyInit};
use cipher::consts::{U14};
use cipher::typenum::{Sum};
use const_oid::{AssociatedOid, ObjectIdentifier};
use const_oid::db::rfc5912::{ID_RSAES_OAEP, RSA_ENCRYPTION};
use digest::{FixedOutput, HashMarker};
use kdfs::hybrid_array::{Array, ArraySize};
use kem::{Ciphertext, TryDecapsulate, DecapsulationKey, Decapsulator, Encapsulate, EncapsulationKey, FromSeed, Generate, InvalidKey, Kem, Key, KeyInit, Seed, SharedKey};
use kem::consts::U1;
use rsa::{traits::{PaddingScheme, PublicKeyParts}, Oaep, Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey};
use rsa::pkcs1::{DecodeRsaPrivateKey, DecodeRsaPublicKey, EncodeRsaPublicKey};
use sha2::digest::{Digest, FixedOutputReset};


// /// Wrapper structure for making different RNG traits interoperable
// mod wrapper {
//     use std::convert::Infallible;

//     pub use rsa::rand_core::{TryCryptoRng, TryRng};

//     // RSA uses an new version of Rng. Wrap it so we can use the same Encapsulator trait
//     pub struct RngWrapper<'a, R: super::CryptoRngCore> {
//         core: &'a mut R,
//     }
//     impl<'a, R: super::CryptoRngCore> From<&'a mut R> for RngWrapper<'a, R> {
//         fn from(v: &'a mut R) -> Self {
//             Self { core: v}
//         }
//     }

//     impl<'a, R: super::CryptoRngCore> TryCryptoRng for RngWrapper<'a, R> {}

//     impl<'a, R: super::CryptoRngCore> TryRng for RngWrapper<'a, R> {
//         type Error = Infallible;
        
//         fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
//             Ok(self.core.next_u32())
//         }
        
//         fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
//             Ok(self.core.next_u64())
//         }
        
//         fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
//             Ok(self.core.fill_bytes(dst))
//         }
//     }
// }





///
/// Factory struct designed to produce encapsulators and decapsulators
/// LC = Length of Encoding (pkcs1)
pub struct RsaKem<LE, LI, P, LC=digest::consts::U0> (PhantomData<LE>, PhantomData<LI>, PhantomData<P>, PhantomData<LC>);

///
/// Implementation of the Capsulator trait such that this struct can be passed to other implementations
/// The trait provides default implmentations of the new_encapsulator and new_decapsulator functions
/// 
// impl<LE, LI, P: PaddingScheme+Default> Capsulator for RsaKem<LE, LI, P>
// where LI: Debug + ArraySize + ArrayLength,
//     LE: ArraySize + PartialEq + ArrayLength + Debug,
// {
//     type Encapsulator = RsaEncapsulator<LE, LI, P>;
//     type Decapsulator = RsaDecapsulator<LE, LI, P>;
//     type CiphertextSizeOld = LE;
//     type SharedKeySizeOld = LI;
    
//     fn generate_from_rng ( rng: &mut impl CryptoRngCore ) -> (Self::Encapsulator, Self::Decapsulator) {
//         let private = rsa::RsaPrivateKey::new(&mut wrapper::RngWrapper::from(rng), LE::USIZE*8).unwrap();
//         let public = private.to_public_key();
//         (RsaEncapsulator::from_key(public), RsaDecapsulator::from_key(private))
//     }
// }

// Implementation of the regular RsaKem algorithm as specified in ISO 18033-3 and NIST SP800-56B
pub type RsaOrigKem<LE,LK,K> = KemWithKdf<RsaKem<LE,LE,RsaRaw>, CombinerNoKeys, K, LK>;
// Implemenation of a KEM which generates a random symmetric key and encrypts it using RSA with OAEP 
pub type RsaOaepKem<LE,LK,D,F> = RsaKem<LE, LK, Oaep2<D,F>>;
// // Implemenation of a KEM which generates a random symmetric key and encrypts it using RSA with OAEP with a specified encoded length
// pub type RsaOaepKem2<LE,LK,D,F> = RsaKem<LE, LK, Oaep2<D,F>>;
// Implemenation of a KEM which generates a random symmetric key and encrypts it using RSA with PKCS#1 v1.5 
pub type RsaPkcs15Kem<LE,LK> = RsaKem<LE, LK, Pkcs1v15Encrypt>;

// Defined by ISO 18033-2
pub const ID_KEM_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.0.18033.2.2.4");

impl<LE,LK,K> AssociatedOid for RsaOrigKem<LE,LK,K>
{
    const OID: ObjectIdentifier = ID_KEM_RSA;
}

impl<LE,LK> AssociatedOid for RsaPkcs15Kem<LE,LK> 
{
    const OID: ObjectIdentifier = RSA_ENCRYPTION;
}
impl<LE,LK,D,F> AssociatedOid for RsaOaepKem<LE,LK,D,F>
where D: FixedOutput + Default + HashMarker,
    F: FixedOutput + Default + Digest
{
    const OID: ObjectIdentifier = ID_RSAES_OAEP;
}

///
/// Implementation of RSA KEM as defined by 18033-3
/// This struct implements encrypt and decrypt functions as commonly used by the PaddingScheme trait.
/// This mean a common RsaKem struct can be used with regular padding - OAEP and PKCS1.5 and this RSAKem method
/// 
pub struct RsaRaw ();
impl Default for RsaRaw {
    fn default() -> Self {
        return Self();
    }
}

///
/// RSAKem doesnt really have any padding, but it does require the values to be converted to big integers before being
/// passed to the rsa_encrypt / rsa_decrypt functions. There are also various error conditions which need to be
/// detected and returned
/// 
impl PaddingScheme for RsaRaw
{
    fn decrypt<Rng: rsa::rand_core::TryCryptoRng + ?Sized>(
        self,
        _rng: Option<&mut Rng>,
        recipient_private: &rsa::RsaPrivateKey,
        ciphertext: &[u8],
    ) -> rsa::Result<Vec<u8>> {

        let c0_bigint = rsa::BoxedUint::from_be_slice(ciphertext, (ciphertext.len()*8) as u32)?; 
        let Ok(raw_secret) = rsa::hazmat::rsa_decrypt::<Rng>(None, recipient_private, &c0_bigint) else {
            return Err(rsa::Error::Decryption);
        };
        return Ok(raw_secret.to_be_bytes().to_vec());
    }

    fn encrypt<Rng: rsa::rand_core::TryCryptoRng + ?Sized>(
            self,
            _rng: &mut Rng,
            pub_key: &RsaPublicKey,
            msg: &[u8],
        ) -> rsa::Result<Vec<u8>> {
        // Want top byte to contain at least one bit, otherwise it is danger of being stripped off
        if msg[0] == 0 {
            return Err(rsa::Error::Internal);
        }
        
        let plaintext_shared_secret = rsa::BoxedUint::from_be_slice(msg, 4096).unwrap();
        // shared secret should be less than the modulus, otherwise it wont decrypt properly
        if plaintext_shared_secret.clone().to_nz().unwrap() > *pub_key.n() {
            return Err(rsa::Error::Internal);
        }
        // confirm value encrypts without error
        let Ok(enciphered_shared_secret) = rsa::hazmat::rsa_encrypt ( pub_key, &plaintext_shared_secret) else {
            return Err(rsa::Error::Internal);
        };

        // confirm ciphertext is same size - ie top byte is non-zero and hasn't been stripped
        let enciphered_shared_secret_as_vec = enciphered_shared_secret.to_be_bytes();
        if enciphered_shared_secret_as_vec.len() != msg.len() {
            return Err(rsa::Error::Internal);
        }
        Ok (enciphered_shared_secret_as_vec.to_vec())
    }
}


///
/// Wrapper for Oaep which implements the Default trait such that it can be passed to the RsaEncapsulator and RsaDecapsulator classes
/// for instantation as needed.
/// 
pub struct Oaep2<D: Digest, F: Digest> (Oaep::<D,F>, PhantomData<D>, PhantomData<F>);

impl<D: 'static + Digest + Sync + Send + Clone + FixedOutputReset, F: 'static + Digest + Send + Sync + Clone + FixedOutputReset> Default for Oaep2<D,F> 
{
    fn default() -> Self {
        Self(Oaep::<D,F>::new_with_mgf_hash(), PhantomData, PhantomData)
    }
}
impl<D: Digest + FixedOutputReset, F: Digest + FixedOutputReset> PaddingScheme for Oaep2<D,F>
{
    fn decrypt<Rng: rsa::rand_core::TryCryptoRng + ?Sized>(
        self,
        rng: Option<&mut Rng>,
        priv_key: &rsa::RsaPrivateKey,
        ciphertext: &[u8],
    ) -> rsa::Result<Vec<u8>> {
        return self.0.decrypt (rng, priv_key, ciphertext);
    }

    fn encrypt<Rng: rsa::rand_core::TryCryptoRng + ?Sized>(
        self,
        rng: &mut Rng,
        pub_key: &rsa::RsaPublicKey,
        msg: &[u8],
    ) -> rsa::Result<Vec<u8>> {
        return self.0.encrypt(rng, pub_key, msg);
    }
}


///
/// Structure used for RSA encapsulation of a symmetric key.
/// The encapsulation function generates a raw shared secret of length LE. The shared secret is encapsulated to create an EncappedKey which can be sent to the recipient.
/// THe raw shared secret is passed through the KDF (K) and produces an output of length LK
/// 
/// A few generic parameters are used
/// LE is the length of the encapsulated message to send to the recipient. Must be equal to the length of the modulus
/// LI is the length of any raw shared secret. For RSA-KEM this is the full size of the modulus, for OAEP and PKCS#1 1.5 tthe raw shared secret size is typically the same as the derived secret size
/// P is the padding type which implements the trait PaddingScheme
/// K represents the KDF used to convert the raw decrypted value to a secret
/// 

pub struct RsaEncapsulator <LE, LI, /*LK: ArrayLength<u8>,*/ P >
{
    sender_public: rsa::RsaPublicKey,

    phantom1: PhantomData<LE>,
    phantom2: PhantomData<LI>,
    phantom3: PhantomData<P>,
}

impl<LE: ArraySize, LI: ArraySize, P> FromKey for RsaEncapsulator<LE, LI, P> {
    type Key = RsaPublicKey;
    fn from_key(value: RsaPublicKey) -> Self {
        Self { sender_public: value, phantom1: PhantomData, phantom2: PhantomData, phantom3: PhantomData }
    }
}

impl<LE, LI, P> KeySizeUser for RsaEncapsulator<LE, LI, P>
where LE: ArraySize + Debug + PartialEq + Add<U14>,
    Sum<LE, U14>: ArraySize,
    LI: ArraySize + PartialEq + Debug
{
    type KeySize = Sum<LE, U14>;
}

impl<LE, LI, P> KeyExport for RsaEncapsulator<LE, LI, P>
where LE: ArraySize + Debug + PartialEq + Add<U14>,
    Sum<LE, U14>: ArraySize,
    LI: ArraySize + PartialEq + Debug
{
    fn to_bytes(&self) -> cipher::Key<Self> {
        let sender_public_der = self.sender_public.to_pkcs1_der().unwrap();
        Array::try_from(sender_public_der.as_bytes()).unwrap()
        //Array::from(*self.recipient_public.as_bytes())
    }
}





// impl<LE, LI, P> EncodedSizeUser2 for RsaEncapsulator<LE, LI, P>
// where LE: ArrayLength + ArraySize + Debug + PartialEq + Add<U14>,
//     Sum<LE, U14>: ArrayLength,
//     LI: ArrayLength + ArraySize + PartialEq + Debug
// {
//     // PKCS#1 encoding add 14 bytes to the modulus size (at least with a 2 byte public exponent)
//     type EncodedSize = Sum<LE, U14>;

//     fn as_bytes(&self) -> crate::Encoded<Self> {
//         let sender_public_der = self.sender_public.to_pkcs1_der().unwrap();
//         GenericArray::from_slice(sender_public_der.as_bytes()).clone()
//     }
//     fn from_bytes(enc: &crate::Encoded<Self>) -> Self {
//         let sender_public = rsa::RsaPublicKey::from_pkcs1_der(&enc).unwrap();
//         Self { sender_public, phantom2: PhantomData, phantom1: PhantomData, /*phantom4: PhantomData,*/ phantom3: PhantomData}
//     }
// }

impl<LE, LI, P> TryFrom<&[u8]> for RsaEncapsulator<LE, LI, P>
where LE: ArraySize + Debug + PartialEq,
LI: ArraySize + PartialEq + Debug
{
    type Error = rsa::pkcs1::Error;
    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let sender_public = rsa::RsaPublicKey::from_pkcs1_der(&value)?;
        Ok(Self { sender_public, phantom2: PhantomData, phantom1: PhantomData, phantom3: PhantomData})
    }
}


// impl<LE, LI, P> EncapsulateOld<GenericArray<u8,LE>, Array<u8,LI>> for RsaEncapsulator <LE, LI, P>
// where LI:ArrayLength + Debug + ArraySize,
//     LE: ArrayLength + Debug + ArraySize,
//     P: PaddingScheme + Default,
// {
//     type Error = ();
//     fn encapsulate_old(&self, rng: &mut impl CryptoRngCore) -> Result<(GenericArray<u8,LE>, Array<u8,LI>), Self::Error> {
//         let mut raw_shared_key = Array::<u8, LI>::default();
        
//         let mut rng2 = wrapper::RngWrapper::from(rng);
            
//         // Use a loop because the RSA-KEM padding technique may fail. Simply retry with a new random number
//         for _i in 1..10 {
//             //if wrapper::RngWrapper::try_fill_bytes(&mut rng2, &mut raw_shared_key).is_err() {
//             if rng2.try_fill_bytes(&mut raw_shared_key).is_err() {
//                 continue;
//             }
//             let Ok(encapsulated_key_as_vec) = self.sender_public.encrypt(&mut rng2, P::default(), &raw_shared_key) else {
//                 continue 
//             };
            
//             if encapsulated_key_as_vec.len() != LE::USIZE { 
//                 continue;
//             }
            
//             let encapsulated_key = GenericArray::from_slice(&encapsulated_key_as_vec); //).map_err(|_err| kem::Error)?;
//             return Ok((encapsulated_key.clone(), raw_shared_key))
//         }
//         return Err(())
//     }
// }


// impl<LE, LI, P> EncapsulateDeterministic2<GenericArray<u8,LE>, Array<u8,LI>> for RsaEncapsulator <LE, LI, /*LK,*/ P>
// where LI:ArrayLength + Debug + ArraySize,
//     LE: ArrayLength + Debug + ArraySize,
//     P: PaddingScheme + Default,
// {
//     type Error = ();
//     type SeedSize = LI;
//     fn encapsulate_deterministic(&self, seed: &[u8]) -> Result<(GenericArray<u8,LE>, Array<u8,LI>), Self::Error> {
//         let Ok(raw_shared_key) = Array::try_from(seed) else { return Err(())};
        
//         for _i in 1..10 {
//             let Ok(encapsulated_key_as_vec) = self.sender_public.encrypt(&mut rand::rng(), P::default(), &raw_shared_key) else {
//                 continue 
//             };
            
//             if encapsulated_key_as_vec.len() != LE::USIZE { 
//                 continue;
//             }
            
//             let encapsulated_key = GenericArray::from_slice(&encapsulated_key_as_vec); //).map_err(|_err| kem::Error)?;
//             return Ok((encapsulated_key.clone(), raw_shared_key))
//         }
//         return Err(())
//     }
// }


impl<LE, LI, P> EncapsulateDeterministic for RsaEncapsulator <LE, LI, P>
where LI: Debug + ArraySize + Send + Sync,
    LE:  Debug + ArraySize,
    P: PaddingScheme + Default,
    LI: Debug + ArraySize +  Send + Sync + PartialEq,
    LE: ArraySize + PartialEq + Debug + Sync + Send + Add<U14>,
    P: Sync + Send + 'static,
    Sum<LE, U14>: ArraySize,
{
    type SeedSize = p256::U32;
    
    fn encapsulate_deterministic(&self, seed: &[u8]) -> (Ciphertext<Self::Kem>, SharedKey<Self::Kem>) {
        let Ok(raw_shared_key) = Array::try_from(seed) else { panic!("DFSDF")};
        
        for _i in 1..10 {
            let Ok(encapsulated_key_as_vec) = self.sender_public.encrypt(&mut rand::rng(), P::default(), &raw_shared_key) else {
                continue 
            };
            
            if encapsulated_key_as_vec.len() != LE::USIZE { 
                continue;
            }
            
            if let Ok(encapsulated_key) = Array::try_from(&encapsulated_key_as_vec) { //).map_err(|_err| kem::Error)?;
                return (encapsulated_key.clone(), raw_shared_key)
            }
        }
        panic!("DFSDF");
    }
}


// impl<LI, LK, P: PaddingScheme + Default> GetRecipientPublicKeyBytes for RsaEncapsulator<LI, LK, P>
// where LI: ArraySize,
//     LK: ArraySize
// {
//     type EncodedLen = LI;

//     fn get_recipient_public_key_bytes<'a>(&'a self) -> Cow<'a, [u8]> {
//         self.sender_public.to_pkcs1_der().unwrap().into_vec().into()
//     }
// }


///
/// Functionality for decoding an encapsulated key and recoving the shared secret
/// 

pub struct RsaDecapsulator <LI, LK, P: PaddingScheme + Default>
{
    recipient_private: RsaPrivateKey,
    encapsulation_key: RsaEncapsulator<LI,LK,P>,
    phantom1: PhantomData<LI>,
    phantom2: PhantomData<LK>,
    phantom3: PhantomData<P>,
}

impl<LI, LK, P: PaddingScheme + Default> From<rsa::RsaPrivateKey> for RsaDecapsulator<LI, LK, P> 
{
    fn from(recipient_private: rsa::RsaPrivateKey) -> Self {
        let encapsulation_key = RsaEncapsulator{sender_public: recipient_private.to_public_key(), phantom1: PhantomData, phantom2: PhantomData, phantom3: PhantomData};
        Self { recipient_private, encapsulation_key, phantom1: PhantomData, phantom2: PhantomData, phantom3: PhantomData }
    }
}

///
/// Implementation of FromKey trait allowing creation of an RsaDecapsulator from a key
/// 
impl<LI, LK, P: PaddingScheme + Default> FromKey for RsaDecapsulator<LI, LK, P> 
{
    type Key = rsa::RsaPrivateKey;
    fn from_key (recipient_private: rsa::RsaPrivateKey) -> Self {
        Self::from(recipient_private)
    }
}

// impl<LI, LK, P> DecapsulateOld<GenericArray<u8, LI>, Array<u8, LK>> for RsaDecapsulator<LI, LK, P>
// where
//     LI: ArrayLength + ArraySize + Debug,
//     LK: ArrayLength + ArraySize + Debug,
//     P: PaddingScheme + Default
// {
//     type Error = ();
//     fn decapsulate_old(&self, encapsulated_key: &GenericArray<u8, LI>) -> Result<Array<u8, LK>, Self::Error> {
//         let raw_secret = self.recipient_private.decrypt(P::default(), &encapsulated_key).map_err(|_v|())?;
//         Array::try_from(raw_secret).map_err(|_|())
//     }
// }


impl<LI: Debug + ArraySize + PartialEq, LK, P: PaddingScheme + Default > TryFrom<&[u8]> for RsaDecapsulator<LI, LK, P>
{
    type Error = rsa::pkcs1::Error;
    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let recipient_private = rsa::RsaPrivateKey::from_pkcs1_der(&value)?;
        Ok(Self::from(recipient_private))
        //Ok(Self{recipient_private, phantom1: PhantomData, phantom2: PhantomData, phantom3: PhantomData})
    }
}
impl<LI: Debug + ArraySize + PartialEq, LK, P: PaddingScheme + Default > KeySizeUser for RsaDecapsulator<LI, LK, P>
{
    type KeySize = LI;
}

impl<LI: Debug + ArraySize + PartialEq, LK, P: PaddingScheme + Default > TryKeyInit for RsaDecapsulator<LI, LK, P>
{
    fn new(_key: &Key<Self>) -> Result<Self, InvalidKey> {
        todo!()
    }
    fn new_from_slice(key: &[u8]) -> Result<Self, InvalidKey> {
        let recipient_private = rsa::RsaPrivateKey::from_pkcs1_der(&key).map_err(|_|InvalidKey)?;
        Ok(Self::from(recipient_private))
    }
}




// impl<LI, LK, P: PaddingScheme + Default> GetEncapsulator for RsaDecapsulator<LI, LK, P>
// where LI: ArraySize,
//     LK: ArraySize
// {
//     type Encapsulator = RsaEncapsulator<LI, LI, P>;
//     fn encapsulation_key_old(&self) -> Self::Encapsulator {
//         Self::Encapsulator{sender_public: self.recipient_private.to_public_key(), phantom2: PhantomData, phantom1: PhantomData, phantom3: PhantomData}
//     }
// }

// impl<LI, LK, P: PaddingScheme + Default> GetRecipientPublicKeyBytes for RsaDecapsulator<LI, LK, P>
// where LI: ArraySize,
//     LK: ArraySize
// {
//     type EncodedLen = LI;

//     fn get_recipient_public_key_bytes<'a>(&'a self) -> Cow<'a, [u8]> {
//         self.recipient_private.to_public_key().to_pkcs1_der().unwrap().to_vec().into()
//     }
// }




//////////////////////////////
///  Repeat using rustcryto trait
/// 
/// 
impl<LE, LI, P: PaddingScheme+Default> Kem for RsaKem<LE, LI, P>
where LI: Debug + ArraySize + Send + Sync + PartialEq,
    LE: ArraySize + PartialEq + Debug + Sync + Send + Add<U14>,
    P: Sync + Send + 'static,
    Sum<LE, U14>: ArraySize,

    // where LE: ArrayLength + ArraySize + Debug + PartialEq + Add<U14>,
    // Sum<LE, U14>: ArraySize,
    // LI: ArrayLength + ArraySize + PartialEq + Debug
    
{
    type DecapsulationKey = RsaDecapsulator<LE, LI, P>;
    type EncapsulationKey= RsaEncapsulator<LE, LI, P>;
    type CiphertextSize = LE;
    type SharedKeySize = LI;
    
    fn generate_keypair_from_rng<R: kem::common::rand_core::CryptoRng> ( rng: &mut R ) -> (Self::DecapsulationKey, Self::EncapsulationKey) {
        let private = rsa::RsaPrivateKey::new(rng, LE::USIZE*8).unwrap();
        let public = private.to_public_key();
        (RsaDecapsulator::from_key(private), RsaEncapsulator::from_key(public) )
    }
}

// impl<LE, LI, P: PaddingScheme+Default> Capsulator2 for RsaKem<LE, LI, P>
// where LI: Debug + ArraySize +  Send + Sync + PartialEq,
//     LE: ArraySize + PartialEq + Debug + Sync + Send + Add<U14>,
//     P: Sync + Send + 'static,
//     Sum<LE, U14>: ArraySize,
// {

// }


impl<LE, LI,P> FromSeed for RsaKem<LE, LI, P>
where P: PaddingScheme + Default + Sync + Send + 'static,
    LI: ArraySize + Sync + Send + PartialEq,
    LE: ArraySize + Sync + Send + PartialEq + Add<U14>,
    Sum<LE, U14>: ArraySize,
{
    type SeedSize = U1;

    fn from_seed(_seed: &Seed<Self>) -> (DecapsulationKey<Self>, EncapsulationKey<Self>) {
        todo!()
    }
}

impl<LE, LI, P> Default for RsaKem<LE, LI, P>
{
    fn default() -> Self {
        Self(Default::default(), Default::default(), Default::default(), Default::default())
    }
}
impl<LE, LI, P> Clone for RsaKem<LE, LI, P>
{
    fn clone(&self) -> Self {
        Self(self.0.clone(), self.1.clone(), self.2.clone(), self.3.clone())
    }
}
impl<LE, LI, P> Copy for RsaKem<LE, LI, P>
{

}
impl<LE, LI, P> Eq for RsaKem<LE, LI, P>
{

}
impl<LE, LI, P> Debug for RsaKem<LE, LI, P>
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("RsaKem").field(&self.0).field(&self.1).field(&self.2).field(&self.3).finish()
    }
}
impl<LE, LI, P> PartialEq for RsaKem<LE, LI, P>
{
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0 && self.1 == other.1 && self.2 == other.2 && self.3 == other.3
    }
}
impl<LE, LI, P> Ord for RsaKem<LE, LI, P>
{
    fn cmp(&self, _other: &Self) -> std::cmp::Ordering {
        todo!()
    }
}
impl<LE, LI, P> PartialOrd for RsaKem<LE, LI, P>
{
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        match self.0.partial_cmp(&other.0) {
            Some(core::cmp::Ordering::Equal) => {}
            ord => return ord,
        }
        match self.1.partial_cmp(&other.1) {
            Some(core::cmp::Ordering::Equal) => {}
            ord => return ord,
        }
        match self.2.partial_cmp(&other.2) {
            Some(core::cmp::Ordering::Equal) => {}
            ord => return ord,
        }
        self.3.partial_cmp(&other.3)
    }
}





impl<LI, LK, P> Generate for RsaDecapsulator<LI, LK, P>
where P: PaddingScheme + Default,
    LI: ArraySize
{
    fn generate_from_rng<R: rand::CryptoRng + ?Sized>(rng: &mut R) -> Self {
        let Ok(private) = rsa::RsaPrivateKey::new(rng, LI::USIZE*8) else { panic!( "DDD")};
        RsaDecapsulator::from_key(private)
    }
    
    fn try_generate_from_rng<R: rand::TryCryptoRng + ?Sized>(_rng: &mut R) -> Result<Self, R::Error> {
        todo!()
    }
}

impl<LI, LK, P> Decapsulator for RsaDecapsulator<LI, LK, P>
where P: PaddingScheme + Default + Sync + Send + 'static,
    LI: ArraySize + Send + Sync+ PartialEq + Add<U14>,
    LK: ArraySize + Send + Sync + PartialEq, 
    Sum<LI, U14>: ArraySize,
{
    type Kem = RsaKem::<LI, LK,P>;

    fn encapsulation_key(&self) -> &EncapsulationKey<Self::Kem> {
        &self.encapsulation_key
    }
}

impl<LI, LK, P> TryDecapsulate for RsaDecapsulator<LI, LK, P>
where P: PaddingScheme + Default + Sync + Send + 'static,
    LI: ArraySize + Send + Sync+ PartialEq + Add<U14>,
    LK: ArraySize + Send + Sync + PartialEq, 
    Sum<LI, U14>: ArraySize,
{
    type Error = rsa::Error; //std::array::TryFromSliceError;
    fn try_decapsulate(
        &self,
        _ct: &Ciphertext<Self::Kem>,
    ) -> Result<SharedKey<Self::Kem>, Self::Error> {
        let raw_secret = self.recipient_private.decrypt(P::default(), &_ct)?;
        Array::try_from(raw_secret).map_err(|_err| rsa::Error::Decryption)
    }
}



impl<LI, LK, P> Eq for RsaEncapsulator<LI, LK, P>
where P: PaddingScheme + Default,
    LI: ArraySize,
    LK: ArraySize,
{
    
}
impl<LI, LK, P> PartialEq for RsaEncapsulator<LI, LK, P>
where P: PaddingScheme + Default,
    LI: ArraySize,
    LK: ArraySize,
{
    fn eq(&self, other: &Self) -> bool {
        self.sender_public == other.sender_public && self.phantom1 == other.phantom1 && self.phantom2 == other.phantom2 && self.phantom3 == other.phantom3
    }
}
impl<LI, LK, P> Debug for RsaEncapsulator<LI, LK, P>
where P: PaddingScheme + Default,
    LI: ArraySize,
    LK: ArraySize,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RsaEncapsulator").field("sender_public", &self.sender_public).field("phantom1", &self.phantom1).field("phantom2", &self.phantom2).field("phantom3", &self.phantom3).finish()
    }
}
impl<LI, LK, P> Clone for RsaEncapsulator<LI, LK, P>
where P: PaddingScheme + Default,
    LI: ArraySize,
    LK: ArraySize,
{
    fn clone(&self) -> Self {
        Self { sender_public: self.sender_public.clone(), phantom1: self.phantom1.clone(), phantom2: self.phantom2.clone(), phantom3: self.phantom3.clone() }
    }
}

impl<LI, LK, P> TryKeyInit for RsaEncapsulator<LI, LK, P>
where LI: ArraySize + Debug + PartialEq + Add<U14>,
    Sum<LI, U14>: ArraySize,
    LK: ArraySize + PartialEq + Debug
{
    fn new(key: &Key<Self>) -> Result<Self, InvalidKey> {
        <Self as TryKeyInit>::new_from_slice(&key)
    }
    fn new_from_slice(key: &[u8]) -> Result<Self, InvalidKey> {
        let sender_public = RsaPublicKey::from_pkcs1_der(&key).map_err(|_|InvalidKey)?;
        Ok(Self { sender_public, phantom2: PhantomData, phantom1: PhantomData, phantom3: PhantomData})
    }
}
impl<LI, LK, P> KeyInit for RsaEncapsulator<LI, LK, P>
where LI: ArraySize + Debug + PartialEq + Add<U14>,
    Sum<LI, U14>: ArraySize,
    LK: ArraySize + PartialEq + Debug
{
    fn new(_key: &cipher::Key<Self>) -> Self {
        todo!()
    }
}



impl<LI, LK, P> Encapsulate for RsaEncapsulator<LI, LK, P>
where P: PaddingScheme + Default + 'static + Sync + Send,
    LI: ArraySize + Debug + PartialEq + Add<U14> + Sync + Send,
    Sum<LI, U14>: ArraySize,
    LK: ArraySize + PartialEq + Debug + Send + Sync,
{
    type Kem = RsaKem::<LI, LK,P>;

    fn encapsulate_with_rng<R>(&self, _rng: &mut R) -> (Ciphertext<Self::Kem>, SharedKey<Self::Kem>)
    where
        R: rand::CryptoRng + ?Sized {
        let mut raw_shared_key = Array::<u8, LK>::default();
        
        // Use a loop because the RSA-KEM padding technique may fail. Simply retry with a new random number
        for _i in 1..10 {
            //if wrapper::RngWrapper::try_fill_bytes(&mut rng2, &mut raw_shared_key).is_err() {
            if _rng.try_fill_bytes(&mut raw_shared_key).is_err() {
                continue;
            }
            let Ok(encapsulated_key_as_vec) = self.sender_public.encrypt(_rng, P::default(), &raw_shared_key) else {
                continue 
            };
            
            if encapsulated_key_as_vec.len() != LI::USIZE { 
                continue;
            }
            
            if let Ok(encapsulated_key) = Array::try_from(&encapsulated_key_as_vec) {
                return (encapsulated_key, raw_shared_key)
            }
        }
        panic! ( "Unhandled)");
        
    }
}