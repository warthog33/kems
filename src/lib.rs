//! This crate provides mplementations of Key Encapsulation Mechanism as defined in various standards.
//! 
//! Many of the standards describe similar KEMs, so heavy use is made of generics and type aliases.
//! The root of the crate contains traits and common structures, whilst specific implementations are
//! included in the sub modules
//! 
#[allow(unused)]
use std::{array::TryFromSliceError, ops::{Add, Rem}};
#[allow(unused)]
use cipher::{BlockCipherDecrypt, BlockCipherEncrypt, typenum::Zero};
//pub use hybrid_array::{Array, ArraySize}; //, typenum::{NonZero, Sum, consts::*}};

// pub mod typenum {
//     //pub use generic_array::typenum::{NonZero, Sum};
//     //pub use generic_array::typenum::consts::*;
// }

pub extern crate generic_array;
use generic_array::{GenericArray, ArrayLength};
#[allow(unused)]
use generic_array::typenum::{NonZero, Sum, consts::*};

pub use kdfs::hybrid_array::{Array, ArraySize};
use kdfs::Label;
pub use rand_core::{CryptoRngCore};
pub use rand_core::{CryptoRng, RngCore, OsRng};

pub extern crate rand_core;

pub use kem::{Encapsulate, Decapsulate};
//pub use kem::{Encapsulator, Decapsulator};

pub mod kem_with_kdf;

//use crate::typenum::*;

#[cfg(feature="rustcrypto-rsa")]
pub mod rsakem;
pub mod eckem;
#[cfg(feature="rustcrypto-x25519")]
pub mod x25519kem;

#[cfg(feature="rustcrypto-x448")]
pub mod x448kem;

#[cfg(feature="rustcrypto-ml-kem")]
pub mod ml_kem;

pub mod hybrid;

/// Errors returned from KEM
#[derive(Debug)]
pub enum Error
{
    AeadError, 
    KemError,
    KeyError,
    LenError,
    TryFromSliceError,
    EllipticCurveError,
}
impl From<TryFromSliceError> for Error {
    fn from(_value: TryFromSliceError) -> Self {
        return Error::TryFromSliceError;
    }
}
impl From<elliptic_curve::Error> for Error {
    fn from(_value: elliptic_curve::Error) -> Self {
        return Error::EllipticCurveError;
    }
}
///
/// Trait used for decapsulators and auth encapsulators which need a private key to be specified
/// during creation
///
pub trait FromKey {
    type Key;
    fn from_key(key: Self::Key) -> Self;
}

pub trait FromKeys {
    type PrivateKey;
    type PublicKey;
    fn from_keys ( pub_key: Self::PublicKey, priv_key: Self::PrivateKey ) -> Self;
}

pub trait EncapsulateDeterministic2<EK, SS> {
    /// Encapsulation error
    type Error;
    /// Nominal seed size, but not strictly requirement
    type SeedSize: ArraySize;

    /// Encapsulates a fresh shared secret
    //fn encapsulate_deterministic(&self, seed: &Array<u8, Self::SeedSize>) -> Result<(EK, SS), Self::Error>;
    fn encapsulate_deterministic(&self, seed: &[u8]) -> Result<(EK, SS), Self::Error>;
}

///
/// Trait used to create an encapsulator passing in a kdf structure
///
// pub trait EncapsulatorInit<K> {
//     fn new (kdf: K) -> Self;
// }
// pub trait GetPublicKey<P> {
//     fn get_public_key (&self) -> &P;
// }
// pub trait GetPublicKey2<P> {
//     fn get_public_key2 (&self) -> P;
// }

pub trait GetEncapsulator {
    type Encapsulator; //: EncodedSizeUser2;
    fn get_encapsulator(&self) -> Self::Encapsulator;
}

pub trait SetKdf {
    type Kdf;
    fn set_kdf(&mut self, kdf: Self::Kdf);
}




/// An object that knows what size it is
/// Similar to the trait from ML-KEM except is uses Generic Array in place of Hybrid Array because
/// hybrid arrays only support a subset of all sizes
pub trait EncodedSizeUser2 {
    /// The size of an encoded object
    type EncodedSize: ArrayLength; //<u8>;

    /// Parse an object from its encoded form
    fn from_bytes(enc: &Encoded<Self>) -> Self;

    /// Serialize an object to its encoded form
    fn as_bytes(&self) -> Encoded<Self>;
}
/// A byte array encoding a value the indicated size
pub type Encoded<T> = GenericArray<u8, <T as EncodedSizeUser2>::EncodedSize>;


pub trait EncodeHybridArray<T> {
    type EncodedLen: ArraySize;
    fn encode ( point: &T ) -> Array<u8, Self::EncodedLen>;
}

//
/// Used for encoding a public key to a byte array
pub trait EncodeGenericArray<P> {
    //type EncodedLen: ArrayLength<u8>;
    type EncodedLen: ArrayLength;
    fn encode(source: &P) -> GenericArray<u8, Self::EncodedLen>;
}

// pub trait EncodeGenericArraySelf {
//     type EncodedLen: ArrayLength<u8>;
//     fn encode(&self) -> GenericArray<u8, Self::EncodedLen>;
// }

/// Inverse function which accepts a byte array and returns a public key
pub trait DecodeSlice<P> {
    type Error;
    fn decode(encoded_bytes: &[u8]) -> Result<P, Self::Error>;
}
pub trait DecodeGenericArray<P> {
    type EncodedLen: ArrayLength; //<u8>;
    type Error;
    fn decode(encoded_bytes: &GenericArray<u8, Self::EncodedLen>) -> Result<P, Self::Error>;
}

pub trait GetSenderPublicKeyBytes {
    type EncodedLen: ArrayLength; //<u8>;
    fn get_sender_public_key_bytes(&self) -> GenericArray<u8, Self::EncodedLen>;
}

pub trait GetRecipientPublicKeyBytes {
    type EncodedLen: ArrayLength; //<u8>;
    fn get_recipient_public_key_bytes(&self) -> GenericArray<u8, Self::EncodedLen>;
}

/// Used for encoding a public key to a byte array
// pub trait EncodePublicKey2 {
//     type EncodedLen: ArrayLength<u8>;
//     fn get_encoded_public_key(&self) -> GenericArray<u8, Self::EncodedLen>;
// }

/// Used for encoding a public key to a byte array
// pub trait EncodeGenericArray<P> {
//     type EncodedLen: ArrayLength<u8>;
//     fn encode(private_key: &P) -> GenericArray<u8, Self::EncodedLen>;
// }
/// Inverse function which accepts a byte array and returns a public key
// pub trait Decode<P> {
//     type Error;
//     fn decode(encoded_bytes: &[u8]) -> Result<P, Self::Error>;
// }


/// Encode a key to a series of bytes
// pub trait Encode {
//     type EncodedLen: ArrayLength<u8>;
//     fn encode(&self) -> GenericArray<u8, Self::EncodedLen>;
//     fn decode(enc: &GenericArray<u8, Self::EncodedLen>) -> Self;

// }




pub trait EncodeSeed {
    /// The size of an encoded object
    type EncodedSize: ArraySize;

    /// Parse an object from its encoded form
    fn from_seed_bytes(enc: &Array::<u8, Self::EncodedSize>) -> Self;

    /// Serialize an object to its encoded form
    fn as_seed_bytes(&self) -> Option<Array::<u8, Self::EncodedSize>>;
}



pub trait EncapsulateWithKeyWrap<EK,SS1, KW, SS2> : Encapsulate<EK,SS1>{
    //type Error = Encapsulate::Error
    //fn encapsulate_with_key_wrap() -> Result((), Error);
    //type Error;
    type LW: ArraySize;
    type LK: ArraySize;
    fn encapsulate_and_wrap(&self, rng: &mut impl CryptoRngCore, key: &Array<u8, Self::LK>) -> Result<(EK, Array<u8, Self::LW>), Self::Error>;
}
pub trait EncapsulateWithKeyWrapDeterministic<EK,SS1, KW, SS2> : EncapsulateDeterministic2<EK,SS1>{
    //type Error = Encapsulate::Error
    //fn encapsulate_with_key_wrap() -> Result((), Error);
    //type Error;
    type LW: ArraySize;
    type LK: ArraySize;
    
    //fn encapsulate_and_wrap_deterministic(&self, seed: &Array<u8, Self::SeedSize>, key: &Array<u8, Self::LK>) -> Result<(EK, Array<u8, Self::LW>), Self::Error>;
    fn encapsulate_and_wrap_deterministic(&self, seed: &[u8], key: &Array<u8, Self::LK>) -> Result<(EK, Array<u8, Self::LW>), Self::Error>;
}

pub trait DecapsulateWithKeyWrap<EK,SS1,KW,SS2> : Decapsulate<EK,SS1>
// where LW: ArraySize,
//     LK: ArraySize
{
    type Error;
    type LW: ArraySize;
    type LK: ArraySize;
    //type Error = Encapsulate::Error
    //fn encapsulate_with_key_wrap() -> Result((), Error);
    fn decapsulate_and_unwrap(&self, encapsulated_key: &EK, wrapped_key: &Array<u8, Self::LW>) -> Result<Array<u8, Self::LK>, <Self as DecapsulateWithKeyWrap<EK, SS1, KW, SS2>>::Error>;
}


#[cfg(feature="rustcrypto-aeskw")]
//impl<T,EK,SSL1,A,SSL> DecapsulateWithKeyWrap<EK,Array<u8, SSL1>, aes_kw::AesKw<A>, SSL> for T
impl<T,EK,A,SSL> DecapsulateWithKeyWrap<EK,Array<u8, A::KeySize>, aes_kw::AesKw<A>, SSL> for T
where 
    T: Decapsulate<EK,Array<u8, A::KeySize>>,
    SSL: ArraySize + Add<U8> + NonZero + Rem<U8>,
    <SSL as Add<U8>>::Output: ArraySize,
    <SSL as Rem<U8>>::Output: Zero,
    A: BlockCipherDecrypt<BlockSize = U16> + cipher::KeyInit,
{
    type Error = ();
    type LW = Sum<SSL, U8>;
    type LK = SSL;
    
    fn decapsulate_and_unwrap(&self, encapsulated_key: &EK, wrapped_key: &Array<u8, Self::LW>) 
    -> Result<Array<u8, SSL>, <Self as DecapsulateWithKeyWrap<EK, Array<u8, A::KeySize>, aes_kw::AesKw<A>, SSL>>::Error> {
    
        //println! ( "SSL={}", SSL::USIZE );
        //println! ( "LK={}", Self::LK::USIZE );
        
        let shared_secret2 = self.decapsulate(encapsulated_key).unwrap();
        use cipher::KeyInit;
        //let wrapping_key = aes_kw::AesKw::<A>::new_from_slice(shared_secret2.as_ref()).unwrap();
        let wrapping_key = aes_kw::AesKw::<A>::new(&shared_secret2);
        let cek: Array<u8, Self::LK> = wrapping_key.unwrap_fixed_key(wrapped_key).unwrap();

        //println! ( "cek={:02X?}", cek);
        //todo!()
        Ok(cek)
    }
}
 
#[cfg(feature="rustcrypto-aeskw")]
impl<T,EK,A,SSL> EncapsulateWithKeyWrap<EK,Array<u8, A::KeySize>, aes_kw::AesKw<A>, SSL> for T
where 
    T: Encapsulate<EK,Array<u8, A::KeySize>>,
    SSL: ArraySize + Add<U8> + NonZero + Rem<U8>,
    <SSL as Add<U8>>::Output: ArraySize,
    <SSL as Rem<U8>>::Output: Zero,
    A: BlockCipherEncrypt<BlockSize = U16> + cipher::KeyInit,
{
    //type Error = ();
    type LW = Sum<SSL, U8>;
    type LK = SSL;
    
    fn encapsulate_and_wrap(&self, rng: &mut impl CryptoRngCore, key: &Array<u8, Self::LK>) -> Result<(EK, Array<u8, Self::LW>), Self::Error> {
        let (ek, shared_secret2) = self.encapsulate(rng).unwrap();
        use cipher::KeyInit;
        let wrapping_key = aes_kw::AesKw::<A>::new(&shared_secret2);
        let cek: Array<u8, Self::LW> = wrapping_key.wrap_fixed_key(&key);
        Ok((ek, cek))
    }
    
    // fn decapsulate_and_unwrap(&self, encapsulated_key: &EK, wrapped_key: &Array<u8, Self::LW>) -> Result<Array<u8, SSL>, <Self as DecapsulateWithKeyWrap<EK, Array<u8, A::KeySize>, aes_kw::AesKw<A>, SSL>>::Error> {
    
    //     println! ( "SSL={}", SSL::USIZE );
    //     println! ( "LK={}", Self::LK::USIZE );
        
    //     let shared_secret2 = self.decapsulate(encapsulated_key).unwrap();
    //     use cipher::KeyInit;
    //     //let wrapping_key = aes_kw::AesKw::<A>::new_from_slice(shared_secret2.as_ref()).unwrap();
    //     let wrapping_key = aes_kw::AesKw::<A>::new(&shared_secret2);
    //     let cek: Array<u8, Self::LK> = wrapping_key.unwrap_fixed_key(wrapped_key).unwrap();

    //     println! ( "cek={:02X?}", cek);
    //     //todo!()
    //     Ok(cek)
    // }
}

#[cfg(feature="rustcrypto-aeskw")]
impl<T,EK,A,SSL> EncapsulateWithKeyWrapDeterministic<EK,Array<u8, A::KeySize>, aes_kw::AesKw<A>, SSL> for T
where 
    T: EncapsulateDeterministic2<EK,Array<u8, A::KeySize>>,
    //<T as EncapsulateDeterministic2<EK, cipher::Array<u8, <A as cipher::KeySizeUser>::KeySize>>>::Error: std::fmt::Debug,
    //<T as EncapsulateDeterministic2<EK, Array<u8, <A::KeySize>> >>::Error: Debug,
    SSL: ArraySize + Add<U8> + NonZero + Rem<U8>,
    <SSL as Add<U8>>::Output: ArraySize,
    <SSL as Rem<U8>>::Output: Zero,
    A: BlockCipherEncrypt<BlockSize = U16> + cipher::KeyInit,
    
{
    //type Error = ();
    type LW = Sum<SSL, U8>;
    type LK = SSL;
    
    fn encapsulate_and_wrap_deterministic(&self, seed: &[u8]/*&Array<u8, Self::SeedSize>*/, key: &Array<u8, Self::LK>) -> Result<(EK, Array<u8, Self::LW>), Self::Error> {
        let Ok((ek, shared_secret2)) = self.encapsulate_deterministic(seed) else { panic! ( "AAAgh")};
        use cipher::KeyInit;
        let wrapping_key = aes_kw::AesKw::<A>::new(&shared_secret2);
        let cek: Array<u8, Self::LW> = wrapping_key.wrap_fixed_key(&key);
        Ok((ek, cek))
    }
    
    // fn decapsulate_and_unwrap(&self, encapsulated_key: &EK, wrapped_key: &Array<u8, Self::LW>) -> Result<Array<u8, SSL>, <Self as DecapsulateWithKeyWrap<EK, Array<u8, A::KeySize>, aes_kw::AesKw<A>, SSL>>::Error> {
    
    //     println! ( "SSL={}", SSL::USIZE );
    //     println! ( "LK={}", Self::LK::USIZE );
        
    //     let shared_secret2 = self.decapsulate(encapsulated_key).unwrap();
    //     use cipher::KeyInit;
    //     //let wrapping_key = aes_kw::AesKw::<A>::new_from_slice(shared_secret2.as_ref()).unwrap();
    //     let wrapping_key = aes_kw::AesKw::<A>::new(&shared_secret2);
    //     let cek: Array<u8, Self::LK> = wrapping_key.unwrap_fixed_key(wrapped_key).unwrap();

    //     println! ( "cek={:02X?}", cek);
    //     //todo!()
    //     Ok(cek)
    // }
}


///
/// Trait used for types which support both Encapsulation and Decapsulation.
/// Default implementations are provided for new_encapsulator and new_decapsulator
///
pub trait Capsulator{
    //type SecretKey;
    type Encapsulator: Encapsulate<GenericArray<u8, Self::CiphertextSize>, Array<u8, Self::SharedKeySize>>;
    type Decapsulator: Decapsulate<GenericArray<u8, Self::CiphertextSize>, Array<u8, Self::SharedKeySize>>;
    type SharedKeySize: ArraySize;
    type CiphertextSize: ArrayLength; //<u8>;
    //type EncappedKey: EncappedKey;
   
    // fn new_encapsulator () -> Self::Encapsulator
    //     where Self::Encapsulator: Default
    // {
    //     return Self::Encapsulator::default();
    // }

    fn generate ( rng: &mut impl CryptoRngCore ) -> (Self::Encapsulator, Self::Decapsulator);
    //fn generate2 ( rng: &mut impl rand_core2::CryptoRng ) -> (Self::Encapsulator, Self::Decapsulator);

    fn new_encapsulator (public_key: <Self::Encapsulator as FromKey>::Key) -> Self::Encapsulator
        //where Self::Encapsulator: From<T>
        where Self::Encapsulator: FromKey
    {
        return Self::Encapsulator::from_key(public_key);
    }
    fn new_decapsulator (priv_key: <Self::Decapsulator as FromKey>::Key) -> Self::Decapsulator
        //where Self::Decapsulator: PrivateKeyInit<T>
        //where Self::Decapsulator: From<T>
        where Self::Decapsulator: FromKey
    {
        return Self::Decapsulator::from_key(priv_key);
    }
    

    fn from_bytes_encap ( bytes: &GenericArray::<u8, <Self::Encapsulator as EncodedSizeUser2>::EncodedSize> ) -> Self::Encapsulator
    where Self::Encapsulator: EncodedSizeUser2,
    {
        Self::Encapsulator::from_bytes(bytes)
    }
    // fn from_bytes_encap ( bytes: &GenericArray::<u8, <Self::Encapsulator as DecodeGenericArray<Self::Encapsulator>>::EncodedLen> ) -> Self::Encapsulator
    //     where Self::Encapsulator: DecodeGenericArray<Self::Encapsulator>
    // {
    //     let Ok(r) = <Self::Encapsulator as DecodeGenericArray<Self::Encapsulator>>::decode(bytes) else { panic! ("error in decode")};
    //     r
    // }



    fn from_bytes_decap ( bytes: &GenericArray::<u8, <Self::Decapsulator as EncodedSizeUser2>::EncodedSize> ) -> Self::Decapsulator
    where Self::Decapsulator: EncodedSizeUser2,
    {
        Self::Decapsulator::from_bytes(bytes)
    }
    // fn from_bytes_decap ( bytes: &GenericArray::<u8, <Self::Decapsulator as DecodeGenericArray<Self::Decapsulator>>::EncodedLen> ) -> Self::Decapsulator
    // where Self::Decapsulator: DecodeGenericArray<Self::Decapsulator>, 
    // {
    //     let Ok(r) = <Self::Decapsulator as DecodeGenericArray<Self::Decapsulator>>::decode(bytes) else { panic! ("error in decode")};
    //     r
    // }
    
}

/// Ciphertext, a fixed size field representing the encapsulated key
pub type Ciphertext<C> = GenericArray<u8, <C as Capsulator>::CiphertextSize>;
/// SharedKey, a fixed size type containing the shared key
pub type SharedKey<C> = Array<u8, <C as Capsulator>::SharedKeySize>;


pub trait GenerateCapsulatorFromSeed : Capsulator{
    type SeedSize: ArraySize;
    fn derive_from_seed(seed: &Array::<u8, Self::SeedSize>) -> (Self::Encapsulator, Self::Decapsulator);
}

pub trait DeriveKeyPairFromSeed<SK> {
    type SeedSize: ArraySize;
    type PublicKey;
    type Error;
    //fn derive_keypair_from_seed( seed: &Array::<u8, Self::SeedSize>) -> (SK, Self::PublicKey);
    fn derive_keypair_from_seed( seed: &[u8]) -> Result<(SK, Self::PublicKey), Self::Error>;

}
/// Seed, a fixed size type used to generate the private key
//pub type Seed<SK,PK> = Array<u8, <S as DerivePairFromSeed>::SeedSize>;


///
/// Trait used for types which support both Authenticated Encapsulation and Authenticated Decapsulation.
/// Default implementations are provided for new_auth_encapsulator and new_auth_decapsulator
/// 
// pub trait AuthCapsulator{
//     type AuthSecretKey;
//     type AuthEncapsulator: PrivateKeyInit<Self::AuthSecretKey>;
//     type AuthDecapsulator: PrivateKeyInit<Self::AuthSecretKey>;
    
//     fn new_auth_encapsulator (priv_key: Self::AuthSecretKey) -> Self::AuthEncapsulator
//     {
//         return Self::AuthEncapsulator::new(priv_key);
//     }
//     fn new_auth_decapsulator (priv_key: Self::AuthSecretKey) -> Self::AuthDecapsulator
//     {
//         return Self::AuthDecapsulator::new(priv_key);
//     }
// }


/// Implementation of some of the Key Encapsulation Mechanisms described in NIST SP 800-56A - DH and ECDH based
pub mod nistsp800_56a {
    use crate::{eckem::{EcdhAuthCapsulatorCompressed, SeedAsScalar}, kem_with_kdf::{CombinerNoKeys, KemAuthWithKdf}};

    use super::eckem::EcUncompressedEncoder;
    //use kdfs::nistsp800_56::ConcatKdf;

    /// NIST describes key agreement using ECC in SP800-56A, this is option 1 from the document
    //pub type EcCombinerConcat<H> = super::eckem::EcCombinerNoPubKeys<ConcatKdf<H>>; 
    // NIST SP800-56A includes two key derivation methods for using the shared secret, this is option 2 which uses 
    // ASN.1 DER encoding of Algorithm ID, PartyUInfo, PartyVInfo and optionally SuppPubInfo and/or SuppPrivInfo
    
    /// Type for party U as described in NIST SP 800-56A, 6.2.2.2 (Cofactor) One-Pass Diffie-Hellman Scheme
    //pub type EccOnePassDhEncapsulator<C,K,L> = super::eckem::EcdhEncapsulatorUncompressed<C,K,L>;
    pub type EccOnePassDhCapsulator<C,K,L> = KemAuthWithKdf<super::eckem::EcdhKemUncompressed<C, SeedAsScalar>, CombinerNoKeys, K, L>;
    
    /// Type for party V as described in NIST SP 800-56A, 6.2.2.2 (Cofactor) One-Pass Diffie-Hellman Scheme
    //pub type EccOnePassDhDecapsulator<C,K,L> = super::eckem::EcdhDecapsulator<C,K,L,EcUncompressedEncoder<C>>;

    /// Type for party U as described in NIST SP 800-56A, 6.2.1.2 (Cofactor) One-Pass Unified Model Scheme
    //pub type EccOnePassUnifiedEncapsulator<C,K,L> = super::eckem::EcdhAuthEncapsulatorCompressed<C,K,L>;
    pub type EccOnePassUnifiedEncapsulator<C,K,L> = KemAuthWithKdf<super::eckem::EcdhAuthEncapsulatorCompressed<C>, CombinerNoKeys, K, L>;
    /// Type for party V as described in NIST SP 800-56A, 6.2.1.2 (Cofactor) One-Pass Unified Model Scheme
    //pub type EccOnePassUnifiedDecapsulator<C,K,L> = super::eckem::EcdhAuthDecapsulator<C,K,L,EcUncompressedEncoder<C>>;
    pub type EccOnePassUnifiedDecapsulator<C,K,L> = KemAuthWithKdf<super::eckem::EcdhAuthDecapsulator<C,EcUncompressedEncoder<C>>, CombinerNoKeys, K,L>;

    pub type EccOnePassUnifiedCapsulator<C,K,L> = KemAuthWithKdf<EcdhAuthCapsulatorCompressed<C>, CombinerNoKeys, K, L>;

    /// Type for party U as described in NIST SP 800-56A, 6.2.1.4 One-Pass MQV, C(1e, 2s, ECC MQV) Scheme
    //pub type EccOnePassMqvEncapsulator<C,K,L> = super::eckem::EcMqvAuthEncapsulatorUncompressed<C,K,L>;
    pub type EccOnePassMqvEncapsulator<C,K,L> = KemAuthWithKdf<super::eckem::EcMqvAuthEncapsulatorUncompressed<C>, CombinerNoKeys, K,L>;
    /// Type for party V as described in NIST SP 800-56A, 6.2.1.4 One-Pass MQV, C(1e, 2s, ECC MQV) Scheme
    //pub type EccOnePassMqvDecapsulator<C,K,L> = super::eckem::EcMqvAuthDecapsulator<C,K,L,EcUncompressedEncoder<C>>;
    pub type EccOnePassMqvDecapsulator<C,K,L> = KemAuthWithKdf<super::eckem::EcMqvAuthDecapsulator<C,EcUncompressedEncoder<C>>, CombinerNoKeys,K,L>;
}

/// Implementation of some of the Key Encapsulation Mechanisms described in NIST SP 800-56B - RSA based
pub mod nistsp800_58b {
    #[cfg(feature="rustcrypto-rsa")]
    pub type Kas1Capsulator<LE, LK, K> = super::rsakem::RsaOrigKem<LE, LK, K>;
    
    // Kas2 requires both ends to generate data encrypted using RsaKem and then have the key derivation work across
    // both shared secrets. This doesn't fit in nicely with the hybrid encryption so there is no type provided
}

/// Types implementing some of the Key Agreement Mechanisms described in ANSI X9.63
pub mod ansi_x9_63 {
    use kdfs::{ansi_x9_63::X963Kdf, nistsp800_56::ConcatKdf};

    use crate::{eckem::SeedAsScalar, kem_with_kdf::{CombinerNoKeys, KemAuthWithKdf, KemWithKdf}};

    /// The first combiner as described in ANSI X9.63. It passes the x component of shared secret to the concat kdf
    //pub type EcCombinerConcat<H> = super::eckem::EcCombinerNoPubKeys<kdfs::nistsp800_56::ConcatKdf<H>>;
    /// The second combiner as described in ANSI X9.63. It passes the x component of shared secret to a hash based kdf which includes a counter
    //pub type EcCombinerX963<H> = super::eckem::EcCombinerNoPubKeys<kdfs::ansi_x9_63::X963Kdf<H>>;

    /// Type representing the 1-Pass Diffie Helmann Scheme using the NIST SP 800-56 Concat Kdf, as described in ANSI X9.63, 6.2.1 
    /// Shared Data, if used, is passed as the other-info field in the creation of the Kdf object
    pub type EccOnePassDhConcatKdfKem<C,H,L> = KemWithKdf<super::eckem::EcdhKemUncompressed<C,SeedAsScalar>, CombinerNoKeys, ConcatKdf<H>, L>;
    /// Type representing the 1-Pass Diffie Helmann Scheme using the Kdf defined in X9.63 as described in ANSI X9.63, 6.2.1
    //pub type EccOnePassDhX963KdfKem<C,H,L> = super::eckem::EcdhKemUncompressed<C,EcCombinerX963<H>,L,SeedAsScalar>;
    pub type EccOnePassDhX963KdfKem<C,H,L> = KemWithKdf<super::eckem::EcdhKemUncompressed<C,SeedAsScalar>, CombinerNoKeys, X963Kdf<H>, L>;
    /// Type representing the 1-Pass Unified Model Scheme using the Concat KDF from X9.63, 6.5.1 
    //pub type EccOnePassUnifiedConcatKdfKem<C,H,L> = super::eckem::EcdhAuthCapsulatorCompressed<C,EcCombinerConcat<H>,L>;
    pub type EccOnePassUnifiedConcatKdfKem<C,H,L> = KemAuthWithKdf<super::eckem::EcdhAuthCapsulatorCompressed<C>, CombinerNoKeys, ConcatKdf<H>,L>;
    /// Type representing the 1-Pass Unified Model Scheme using the X9.63 KDF from X9.63, 6.5.1 
    //pub type EccOnePassUnifiedX963KdfKem<C,H,L> = super::eckem::EcdhAuthCapsulatorCompressed<C,EcCombinerX963<H>,L>;
    pub type EccOnePassUnifiedX963KdfKem<C,H,L> = KemAuthWithKdf<super::eckem::EcdhAuthCapsulatorCompressed<C>, CombinerNoKeys, X963Kdf<H>, L>;
    /// Type representing the 1-Pass MQV Scheme using the Concat KDF from X9.63, 6.9.1
    //pub type EccOnePassMqvConcatKdfKem<C,H,L> = super::eckem::EcMqvAuthCapsulatorUncompressed<C,EcCombinerConcat<H>,L>;
    pub type EccOnePassMqvConcatKdfKem<C,H,L> = KemAuthWithKdf<super::eckem::EcMqvAuthCapsulatorUncompressed<C>, CombinerNoKeys, kdfs::nistsp800_56::ConcatKdf<H>,L>;
    /// Type representing the 1-Pass MQV Scheme using the X9.63 KDF from X9.63, 6.9.1 
    //pub type EccOnePassMqvX963KdfKem<C,H,L> = super::eckem::EcMqvAuthCapsulatorUncompressed<C,EcCombinerX963<H>,L>;
    pub type EccOnePassMqvX963KdfKem<C,H,L> = KemAuthWithKdf<super::eckem::EcMqvAuthCapsulatorUncompressed<C>, CombinerNoKeys, kdfs::ansi_x9_63::X963Kdf<H>,L>;
    
}

/// Key Encapsulation Mechanisms specified in ISO 18033-2
pub mod iso18033_2 {
    use crate::{eckem::{EcdhKemCompressed, EcdhKemUncompressed, SeedAsScalar}, kem_with_kdf::{CombinerEphemOnly, CombinerNoKeys, KemWithKdf}};

    /// Combiner using Kdf1 as defined in ISO 18033-2 6.2.2 and for use with compressed elliptic curve keys
    //pub type EcCombinerKdf1Compressed<H> = super::eckem::EcCombinerEphemPubKey<kdfs::iso18033_2::Kdf1<H>>;
    /// Combiner using Kdf1 as defined in ISO 18033-2 6.2.2 for use with uncompressed elliptic curve keys
    //pub type EcCombinerKdf1Uncompressed<H> = super::eckem::EcCombinerEphemPubKey<kdfs::iso18033_2::Kdf1<H>>;
    /// Combiner using Kdf2 as defined in ISO 18033-2 6.2.3 for use with compressed elliptic curve keys
    //pub type EcCombinerKdf2Compressed<H> = super::eckem::EcCombinerEphemPubKey<kdfs::iso18033_2::Kdf2<H>>;
    /// Combiner using Kdf2 as defined in ISO 18033-2 6.2.3 for use with uncompressed elliptic curve keys
    //pub type EcCombinerKdf2Uncompressed<H> = super::eckem::EcCombinerEphemPubKey<kdfs::iso18033_2::Kdf2<H>>;

    /// Implementation of the ECIES-KEM function as described in ISO 18033-2, 10.2.3. 
    /// This type uses compressed encoding, which is the same as SEC1 compressed encoding
    pub type EciesKemCompressed<C,K,L> = KemWithKdf<EcdhKemCompressed<C, SeedAsScalar>, CombinerEphemOnly, K, L>;
    
    /// Implementation of the ECIES-KEM function as described in ISO 18033-2, 10.2.3. using Kdf1
    pub type EciesKemCompressedKdf1<C,H,L> = KemWithKdf::<EcdhKemCompressed::<C, SeedAsScalar>, CombinerEphemOnly, kdfs::iso18033_2::Kdf1<H>, L>;
    
    /// Implementation of the ECIES-KEM function as described in ISO 18033-2, 10.2.3. using Kdf2
    pub type EciesKemCompressedKdf2<C,H,L> = KemWithKdf::<EcdhKemCompressed::<C, SeedAsScalar>, CombinerEphemOnly, kdfs::iso18033_2::Kdf2<H>, L>;

    /// Implementation of the ECIES-KEM function as described in ISO 18033-2, 10.2.3. 
    /// This type uses uncompressed encoding, which is the same as SEC1 uncompressed encoding
    pub type EciesKemUncompressed<C,K,L> = KemWithKdf::<EcdhKemUncompressed<C, SeedAsScalar>, CombinerNoKeys, K, L>;
    
    /// Implementation of the ECIES-KEM function as described in ISO 18033-2, 10.2.3. using Kdf1 and uncompressed encoding
    pub type EciesKemUncompressedKdf1<C,H,L> = KemWithKdf::<EcdhKemUncompressed::<C, SeedAsScalar>, CombinerEphemOnly, kdfs::iso18033_2::Kdf1<H>, L>;

    /// Implementation of the ECIES-KEM function as described in ISO 18033-2, 10.2.3. using Kdf2 and uncompressed encoding
    pub type EciesKemUncompressedKdf2<C,H,L> = KemWithKdf::<EcdhKemUncompressed::<C, SeedAsScalar>, CombinerEphemOnly, kdfs::iso18033_2::Kdf2<H>, L>;
    
    /// Implementation of the RSA-KEM.Encryption and Decryption function as described in ISO 18033-2, 11.5.3. & 4.
    /// LE is the modulus length, LK is the output key length and K is the key derivation function
    #[cfg(feature="rustcrypto-rsa")]
    pub type RsaKem<LE,LK,K> = super::rsakem::RsaOrigKem<LE,LK,K>;
    
    /// Implementation of the RSA-KEM.Encryption and Decryption function as described in ISO 18033-2, 11.5.3. & 4 using Kdf1
    #[cfg(feature="rustcrypto-rsa")]
    pub type RsaKemKdf1<LE,LK,H> = super::rsakem::RsaOrigKem<LE,LK,kdfs::iso18033_2::Kdf1<H>>;
    
    /// Implementation of the RSA-KEM.Encryption and Decryption function as described in ISO 18033-2, 11.5.3. & 4 using Kdf2
    #[cfg(feature="rustcrypto-rsa")]
    pub type RsaKemKdf2<LE,LK,H> = super::rsakem::RsaOrigKem<LE,LK,kdfs::iso18033_2::Kdf2<H>>;

    /// Implementation of the REM1 Encode and Decode function as described in ISO 18033-2, 11.3.2.2
    /// LE is the modulus length, LK is the key length, D is the digest to use in the OAEP label hash function and F is digest to use in the OAEP mask generation
    #[cfg(feature="rustcrypto-rsa")]
    pub type Rem1Kem<LE,LK,D,F> = super::rsakem::RsaOaepKem<LE,LK,D,F>;
}

/// Types and OIDs from RFC 5753: Use of Elliptic Curve Cryptography (ECC) Algorithms in Cryptographic Message Syntax (CMS)
pub mod rfc5753 {
    #[allow(unused)]
    use generic_array::ArrayLength;
    #[allow(unused)]
    use const_oid::{AssociatedOid, ObjectIdentifier};
    #[allow(unused)]
    use elliptic_curve::{point::PointCompression, CurveArithmetic};
    #[allow(unused)]
    use kdfs::ansi_x9_63::X963Kdf;
    #[cfg(feature="rustcrypto-sha1")]
    use sha1::Sha1;
    #[cfg(feature="rustcrypto-sha2")]
    use sha2::{Sha224, Sha256, Sha384, Sha512};
    #[allow(unused)]
    use crate::eckem::SeedAsScalar;
    #[allow(unused)]
    use crate::kem_with_kdf::{KemWithKdf,CombinerNoKeys, KemAuthWithKdf};
        
    /// All these have OIDs from RFC5753
    #[cfg(feature="rustcrypto-sha1")]
    pub type DhSinglePassStdDhSha1KdfScheme<C,L>   = KemWithKdf::<super::eckem::EcdhKemUncompressed<C, SeedAsScalar>, CombinerNoKeys, X963Kdf<Sha1>,L>;
    #[cfg(feature="rustcrypto-sha2")]
    pub type DhSinglePassStdDhSha224KdfScheme<C,L> = KemWithKdf::<super::eckem::EcdhKemUncompressed<C, SeedAsScalar>, CombinerNoKeys, X963Kdf<Sha224>,L>;
    #[cfg(feature="rustcrypto-sha2")]
    pub type DhSinglePassStdDhSha256KdfScheme<C,L> = KemWithKdf::<super::eckem::EcdhKemUncompressed<C, SeedAsScalar>, CombinerNoKeys, X963Kdf<Sha256>,L>;
    #[cfg(feature="rustcrypto-sha2")]
    pub type DhSinglePassStdDhSha384KdfScheme<C,L> = KemWithKdf::<super::eckem::EcdhKemUncompressed<C, SeedAsScalar>, CombinerNoKeys, X963Kdf<Sha384>,L>;
    #[cfg(feature="rustcrypto-sha2")]
    pub type DhSinglePassStdDhSha512KdfScheme<C,L> = KemWithKdf::<super::eckem::EcdhKemUncompressed<C, SeedAsScalar>, CombinerNoKeys, X963Kdf<Sha512>,L>;
    // The Cofactor types have a different OID, but the same generics, use compressed as a hack to seperate
    #[cfg(feature="rustcrypto-sha1")]
    pub type DhSinglePassCofactorDhSha1KdfScheme<C,L> = KemWithKdf::<super::eckem::EcdhKemCompressed<C, SeedAsScalar>, CombinerNoKeys, X963Kdf<Sha1>,L>;
    #[cfg(feature="rustcrypto-sha2")]
    pub type DhSinglePassCofactorDhSha224KdfScheme<C,L> = KemWithKdf::<super::eckem::EcdhKemCompressed<C, SeedAsScalar>, CombinerNoKeys, X963Kdf<Sha224>,L>;
    #[cfg(feature="rustcrypto-sha2")]
    pub type DhSinglePassCofactorDhSha256KdfScheme<C,L> = KemWithKdf::<super::eckem::EcdhKemCompressed<C, SeedAsScalar>, CombinerNoKeys, X963Kdf<Sha256>,L>;
    #[cfg(feature="rustcrypto-sha2")]
    pub type DhSinglePassCofactorDhSha384KdfScheme<C,L> = KemWithKdf::<super::eckem::EcdhKemCompressed<C, SeedAsScalar>, CombinerNoKeys, X963Kdf<Sha384>,L>;
    #[cfg(feature="rustcrypto-sha2")]
    pub type DhSinglePassCofactorDhSha512KdfScheme<C,L> = KemWithKdf::<super::eckem::EcdhKemCompressed<C, SeedAsScalar>, CombinerNoKeys, X963Kdf<Sha512>,L>;

    #[cfg(feature="rustcrypto-sha1")]
    //pub type MqvSinglePassSha1KdfScheme<C,L> = super::eckem::EcMqvAuthCapsulatorCompressed<C, EcCombinerX963<Sha1>,L>;
    pub type MqvSinglePassSha1KdfScheme<C,L> = KemAuthWithKdf<super::eckem::EcMqvAuthCapsulatorCompressed<C>, CombinerNoKeys, kdfs::ansi_x9_63::X963Kdf<Sha1>, L>;
    #[cfg(feature="rustcrypto-sha2")]
    //pub type MqvSinglePassSha224KdfScheme<C,L> = super::eckem::EcMqvAuthCapsulatorCompressed<C, EcCombinerX963<Sha224>,L>;
    pub type MqvSinglePassSha224KdfScheme<C,L> = KemAuthWithKdf<super::eckem::EcMqvAuthCapsulatorCompressed<C>, CombinerNoKeys, kdfs::ansi_x9_63::X963Kdf<Sha224>, L>;
    #[cfg(feature="rustcrypto-sha2")]
    //pub type MqvSinglePassSha256KdfScheme<C,L> = super::eckem::EcMqvAuthCapsulatorCompressed<C, EcCombinerX963<Sha256>,L>;
    pub type MqvSinglePassSha256KdfScheme<C,L> = KemAuthWithKdf<super::eckem::EcMqvAuthCapsulatorCompressed<C>, CombinerNoKeys, kdfs::ansi_x9_63::X963Kdf<Sha256>, L>;
    #[cfg(feature="rustcrypto-sha2")]
    //pub type MqvSinglePassSha384KdfScheme<C,L> = super::eckem::EcMqvAuthCapsulatorCompressed<C, EcCombinerX963<Sha384>,L>;
    pub type MqvSinglePassSha384KdfScheme<C,L> = KemAuthWithKdf<super::eckem::EcMqvAuthCapsulatorCompressed<C>, CombinerNoKeys, kdfs::ansi_x9_63::X963Kdf<Sha384>, L>;
    #[cfg(feature="rustcrypto-sha2")]
    //pub type MqvSinglePassSha512KdfScheme<C,L> = super::eckem::EcMqvAuthCapsulatorCompressed<C, EcCombinerX963<Sha512>,L>;
    pub type MqvSinglePassSha512KdfScheme<C,L> = KemAuthWithKdf<super::eckem::EcMqvAuthCapsulatorCompressed<C>, CombinerNoKeys, kdfs::ansi_x9_63::X963Kdf<Sha512>, L>;

    // impl<C: CurveArithmetic+PointCompression, L: ArrayLength<u8>> AssociatedOid for DhSinglePassStdDhSha256KdfScheme<C,L>  where <C as elliptic_curve::Curve>::FieldBytesSize: ModulusSize  {
    //     const OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.1.11.1");
    // }
    
    #[cfg(feature="rustcrypto-sha1")]
    //impl<C: CurveArithmetic+PointCompression, L: ArrayLength<u8>> AssociatedOid for DhSinglePassStdDhSha1KdfScheme<C,L>
    impl<C: CurveArithmetic+PointCompression, L: ArrayLength> AssociatedOid for DhSinglePassStdDhSha1KdfScheme<C,L>
    {   //OBJECT IDENTIFIER ::= {x9-63-scheme 2 }
        const OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.133.16.840.63.0.2");
    }
    #[cfg(feature="rustcrypto-sha2")]
    //impl<C: CurveArithmetic+PointCompression, L: ArrayLength<u8>> AssociatedOid for DhSinglePassStdDhSha224KdfScheme<C,L> 
    impl<C: CurveArithmetic+PointCompression, L: ArrayLength> AssociatedOid for DhSinglePassStdDhSha224KdfScheme<C,L> 
    {   //OBJECT IDENTIFIER ::= {secg-scheme 11 0 }
        const OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.1.11.0");
    }
    #[cfg(feature="rustcrypto-sha2")]
    //impl<C: CurveArithmetic+PointCompression, L: ArrayLength<u8>> AssociatedOid for DhSinglePassStdDhSha256KdfScheme<C,L> 
    impl<C: CurveArithmetic+PointCompression, L: ArrayLength> AssociatedOid for DhSinglePassStdDhSha256KdfScheme<C,L> 
    {   //OBJECT IDENTIFIER ::= {secg-scheme 11 1 }
        const OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.1.11.1");
    }
    #[cfg(feature="rustcrypto-sha2")]
    impl<C: CurveArithmetic+PointCompression, L: ArrayLength> AssociatedOid for DhSinglePassStdDhSha384KdfScheme<C,L> 
    {   //OBJECT IDENTIFIER ::= {secg-scheme 11 2 }
        const OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.1.11.2");
    }
    #[cfg(feature="rustcrypto-sha2")]
    impl<C: CurveArithmetic+PointCompression, L: ArrayLength> AssociatedOid for DhSinglePassStdDhSha512KdfScheme<C,L> 
    {   //OBJECT IDENTIFIER ::= {secg-scheme 11 3 }
        const OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.1.11.3");
    }
    #[cfg(feature="rustcrypto-sha1")]
    impl<C: CurveArithmetic+PointCompression, L: ArrayLength> AssociatedOid for DhSinglePassCofactorDhSha1KdfScheme<C,L> 
    {   //OBJECT IDENTIFIER ::= {x9-63-scheme 3 }
        const OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.133.16.840.63.0.3");
    }
    #[cfg(feature="rustcrypto-sha2")]
    impl<C: CurveArithmetic+PointCompression, L: ArrayLength> AssociatedOid for DhSinglePassCofactorDhSha224KdfScheme<C,L> 
    {   //OBJECT IDENTIFIER ::= {secg-scheme 14 0 }
        const OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.1.14.0");
    }
    #[cfg(feature="rustcrypto-sha2")]
    impl<C: CurveArithmetic+PointCompression, L: ArrayLength> AssociatedOid for DhSinglePassCofactorDhSha256KdfScheme<C,L> 
    {   //OBJECT IDENTIFIER ::= {secg-scheme 14 1 }
        const OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.1.14.1");
    }
    #[cfg(feature="rustcrypto-sha2")]
    impl<C: CurveArithmetic+PointCompression, L: ArrayLength> AssociatedOid for DhSinglePassCofactorDhSha384KdfScheme<C,L>
    {   //OBJECT IDENTIFIER ::= {secg-scheme 14 2 }
        const OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.1.14.2");
    }
    #[cfg(feature="rustcrypto-sha2")]
    impl<C: CurveArithmetic+PointCompression, L: ArrayLength> AssociatedOid for DhSinglePassCofactorDhSha512KdfScheme<C,L>
    {   //OBJECT IDENTIFIER ::= {secg-scheme 14 3 }
        const OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.1.14.3");
    }
    #[cfg(feature="rustcrypto-sha1")]
    impl<C: CurveArithmetic+PointCompression, L: ArrayLength> AssociatedOid for MqvSinglePassSha1KdfScheme<C,L> 
    {   //OBJECT IDENTIFIER ::= {x9-63-scheme 16 }
        const OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.133.16.840.63.0.16");
    }
    #[cfg(feature="rustcrypto-sha2")]
    impl<C: CurveArithmetic+PointCompression, L: ArrayLength> AssociatedOid for MqvSinglePassSha224KdfScheme<C,L>
    {   //OBJECT IDENTIFIER ::= {secg-scheme 15 0 }
        const OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.1.15.0");
    }
    #[cfg(feature="rustcrypto-sha2")]
    impl<C: CurveArithmetic+PointCompression, L: ArrayLength> AssociatedOid for MqvSinglePassSha256KdfScheme<C,L>
    {   //OBJECT IDENTIFIER ::= {secg-scheme 15 1 }
        const OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.1.15.1");
    }
    #[cfg(feature="rustcrypto-sha2")]
    impl<C: CurveArithmetic+PointCompression, L: ArrayLength> AssociatedOid for MqvSinglePassSha384KdfScheme<C,L>
    {   //OBJECT IDENTIFIER ::= {secg-scheme 15 2 }
        const OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.1.15.2");
    }
    #[cfg(feature="rustcrypto-sha2")]impl<C: CurveArithmetic+PointCompression, L: ArrayLength> AssociatedOid for MqvSinglePassSha512KdfScheme<C,L> 
    {   // OBJECT IDENTIFIER ::= {secg-scheme 15 3 }
        const OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.1.15.3");
    }


    //   AsymmKeyWrapUsingEncapsulatorAndAesKw::<EcEncapKey::<NistP256,U24,U65>,rfc5753::DhSinglePassStdDhSha256KdfSchemeDecapsulator::<NistP256,U24>,Aes192>::new(decap2); 
    //pub type DhSinglePassStdDhSha256KdfAes192Kw<C> = AsymmKeyWrapUsingEncapsulatorAndAesKw<EcEncapKey<C,U24,EcUncompressedEncoder<C>>,DhSinglePassStdDhSha256KdfSchemeCapsulator<C,U24>,Aes192>;
    
    
}

/// Key Encasulation Mechanisms from draft RFC which uses ML-KEM but adds an additional key derivation step
pub mod draft_ietf_lamps_cms_kyber {
    #[cfg(all(feature="rustcrypto-ml-kem", feature="rustcrypto-sha2"))]

    use crate::kem_with_kdf::{CombinerNoKeys, KemWithKdf};
    #[cfg(all(feature="rustcrypto-ml-kem", feature="rustcrypto-sha2"))]
    use crate::ml_kem::MlKemWrapper;

    #[cfg(all(feature="rustcrypto-ml-kem", feature="rustcrypto-sha2", feature ="rustcrypto-hmac"))]
    //pub type MlKem512Hkdf256<L> = super::ml_kem::MlKemWithAddKeyDer<crate::hybrid::MlKemWrapper<ml_kem::MlKem512>, L, key_derivation::rfc5869_hkdf::Hkdf::<sha2::Sha256>>;
    //pub type MlKem512Hkdf256<L> = super::ml_kem::MlKemWithAddKeyDer<ml_kem::MlKem512, kdfs::rfc5869_hkdf::Hkdf::<sha2::Sha256>, L, PassThroughKdf>;
    pub type MlKem512Hkdf256<L> = KemWithKdf<MlKemWrapper<ml_kem::MlKem512>, CombinerNoKeys, kdfs::rfc5869_hkdf::Hkdf::<sha2::Sha256>, L>;

    // impl<L: cipher::ArrayLength<u8>> rsa::pkcs8::AssociatedOid for MlKem512Hkdf256<L> {
    //     const OID: rsa::pkcs8::ObjectIdentifier = rsa::pkcs8::ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.4.1");
    // }
}

/// Kem combining ML-KEM and a traditional KEM as per draft RFC
pub mod draft_irtf_cfrg_hybrid_kems {
    #[cfg(all(feature="rustcrypto-ml-kem", feature="rustcrypto-x25519", feature="rustcrypto-sha2", feature="rustcrypto-sha3"))]
    use ml_kem::MlKem768;

    
    #[derive(Debug)]
    pub struct QsfLabelMlKem768P256;
    impl super::Label for QsfLabelMlKem768P256 {
        const LABEL: &'static[u8] = b"QSF-KEM(ML-KEM-768,P-256)-XOF(SHAKE256)-KDF(SHA3-256)";
    }
    pub struct UniversalCombinerLabelMlKem768P256;
    impl super::Label for UniversalCombinerLabelMlKem768P256 {
        const LABEL: &'static[u8] = b"KitchenSink-KEM(ML-KEM-768,P-256)-XOF(SHAKE256)-KDF(HKDF-SHA-256)";
    }

    #[derive(Debug)]
    pub struct UniversalCombinerLabelMlKem768X25519;
    impl super::Label for UniversalCombinerLabelMlKem768X25519 {
        const LABEL: &'static[u8] = b"KitchenSink-KEM(ML-KEM-768,X25519)-XOF(SHAKE256)-KDF(HKDF-SHA-256)";
    }
    #[derive(Debug)]
    pub struct QsfLabelMlKem1024P384;
    impl super::Label for QsfLabelMlKem1024P384 {
        const LABEL: &'static[u8] = b"QSF-KEM(ML-KEM-1024,P-384)-XOF(SHAKE256)-KDF(SHA3-256)";
    }

    #[cfg(all(feature="rustcrypto-ml-kem", feature="rustcrypto-p256", feature="rustcrypto-sha3"))]
    pub type HybridKemQsfMlKem768P256 = super::hybrid::HybridKem::<
            crate::ml_kem::MlKemWrapper<ml_kem::MlKem768>,
            super::eckem::EcdhKem<p256::NistP256, super::eckem::EcCompressedEncoder<p256::NistP256>,crate::eckem::ReduceSeed>, 
            super::hybrid::QsfCombiner<kdfs::iso11770_6::Okdf3::<sha3::Sha3_256, kdfs::u0>, QsfLabelMlKem768P256>,
            crate::hybrid::ExpandSeed<super::U32, shake::Shake256>>;
 

    #[cfg(all(feature="rustcrypto-ml-kem", feature="rustcrypto-p256", feature="rustcrypto-sha3"))]
    pub type HybridCapsulatorKitchenSinkMlKem768P256 = super::hybrid::HybridKem::<
            crate::ml_kem::MlKemWrapper<ml_kem::MlKem768>,
            super::eckem::EcdhKem<p256::NistP256, super::eckem::EcCompressedEncoder<p256::NistP256>>, 
            super::hybrid::KitchenSinkCombiner<kdfs::rfc5869_hkdf::Hkdf::<sha2::Sha256>,UniversalCombinerLabelMlKem768P256>,
            //crate::hybrid::ExpandSeed<typenum::U32, kdfs::cshake::XofKdf<sha3::Shake256>>>;
            crate::hybrid::ExpandSeed<super::U32, shake::Shake256>>;
            
    #[cfg(all(feature="rustcrypto-ml-kem", feature="rustcrypto-x25519", feature="rustcrypto-sha2", feature="rustcrypto-sha3"))]
    pub type HybridCapsulatorKitchenSinkMlKem768X25519 = super::hybrid::HybridKem::<
            //crate::ml_kem::MlKemWithAddKeyDer<ml_kem::MlKem768>,
            crate::ml_kem::MlKemWrapper<MlKem768>,
            //crate::x25519kem::X25519Capsulator<crate::eckem::EcCombinerNoPubKeys<kdfs::misc::PassThroughKdf>, cipher::consts::U32, crate::eckem::SeedAsScalar>,
            crate::x25519kem::X25519Capsulator<crate::eckem::SeedAsScalar>,
            super::hybrid::KitchenSinkCombiner<kdfs::rfc5869_hkdf::Hkdf::<sha2::Sha256>,UniversalCombinerLabelMlKem768X25519>,
            //crate::hybrid::ExpandSeed<typenum::U32, kdfs::cshake::XofKdf<sha3::Shake256>>>;
            crate::hybrid::ExpandSeed<super::U32, shake::Shake256>>;

    #[cfg(all(feature="rustcrypto-p384", feature="rustcrypto-sha3"))]
    pub type HybridCapsulatorQsfMlKem1024P384 = super::hybrid::HybridKem::<
            //crate::ml_kem::MlKemWithAddKeyDer<ml_kem::MlKem1024>,
            crate::ml_kem::MlKemWrapper<ml_kem::MlKem1024>,
            //super::eckem::EcdhKem<p384::NistP384, crate::eckem::EcCombinerNoPubKeys<kdfs::misc::PassThroughKdf>, cipher::consts::U48, super::eckem::EcCompressedEncoder<p384::NistP384>, crate::eckem::ReduceSeed>, 
            super::eckem::EcdhKem<p384::NistP384, super::eckem::EcCompressedEncoder<p384::NistP384>, crate::eckem::ReduceSeed>, 
            super::hybrid::QsfCombiner<kdfs::iso11770_6::Okdf3::<sha3::Sha3_256, kdfs::u0>, QsfLabelMlKem1024P384>,
            //crate::hybrid::ExpandSeed<typenum::U32, kdfs::cshake::XofKdf<sha3::Shake256>>>;
            crate::hybrid::ExpandSeed<super::U32, shake::Shake256>>;

}

pub mod draft_ietf_hpke_pq
{
    #[derive(Debug)]
    pub struct QsfLabelP256MlKem768;
    impl super::Label for QsfLabelP256MlKem768 {
        //const LABEL: &'static[u8] = b"QSF-P256-MLKEM768-SHAKE256-SHA3256"; 
        const LABEL: &'static[u8] = b"MLKEM768-P256"; // https://datatracker.ietf.org/doc/draft-irtf-cfrg-concrete-hybrid-kems/
        //const LABEL: &'static[u8] = b""; 
        // const LABEL: &'static[u8] = b"QSF-KEM(P-256,ML-KEM-768)-XOF(SHAKE256)-KDF(SHA3-256)";
    }
    #[derive(Debug)]
    pub struct QsfLabelX25519MlKem768;
    impl super::Label for QsfLabelX25519MlKem768 {
        const LABEL: &'static[u8] = b"QSF-X25519-MLKEM768-SHAKE256-SHA3256"; 
        //const LABEL: &'static[u8] = b""; 
        // const LABEL: &'static[u8] = b"QSF-KEM(P-256,ML-KEM-768)-XOF(SHAKE256)-KDF(SHA3-256)";
    }
    #[derive(Debug)]
    pub struct QsfLabelP384MlKem1024;
    impl super::Label for QsfLabelP384MlKem1024 {
        //const LABEL: &'static[u8] = b"QSF-P384-MLKEM1024-SHAKE256-SHA3256"; 
        const LABEL: &'static[u8] = b"MLKEM1024-P384"; 
        //const LABEL: &'static[u8] = b""; 
        // const LABEL: &'static[u8] = b"QSF-KEM(P-256,ML-KEM-768)-XOF(SHAKE256)-KDF(SHA3-256)";
    }

    // #[cfg(all(feature="rustcrypto-p256", feature="rustcrypto-ml-kem", feature="rustcrypto-sha3"))]
    // pub type HybridKemQsfP256MlKem768 = super::hybrid::HybridKem::<
    //     super::ml_kem::MlKemWithAddKeyDer<ml_kem::MlKem768, kdfs::misc::PassThroughKdf, typenum::U32>,
            
    //         super::eckem::EcdhKem<p256::NistP256, crate::eckem::EcCombinerNoPubKeys<kdfs::misc::PassThroughKdf>, cipher::consts::U32, super::eckem::EcUncompressedEncoder<p256::NistP256>, crate::eckem::SeedAsScalar>, 
    //         super::hybrid::QsfCombiner2<kdfs::iso11770_6::Okdf3::<sha3::Sha3_256, kdfs::u0>, QsfLabelP256MlKem768>,
    //         crate::hybrid::ExpandSeed<cipher::consts::U32, kdfs::cshake::XofKdf<sha3::Shake256>>>;

    // #[cfg(all(feature="rustcrypto-ml-kem", feature="rustcrypto-x25519", feature="rustcrypto-sha3"))]
    // pub type HybridKemQsfX25519MlKem768 = super::hybrid::HybridKem::<
    //         super::x25519kem::X25519Capsulator<crate::eckem::EcCombinerNoPubKeys<kdfs::misc::PassThroughKdf>, cipher::consts::U32, crate::eckem::SeedAsScalar>, 
    //         super::ml_kem::MlKemWithAddKeyDer<ml_kem::MlKem768>,
    //         //super::hybrid::QsfCombiner2<kdfs::iso11770_6::Okdf3::<sha3::Sha3_256, kdfs::u0>, QsfLabelX25519MlKem768>,
    //         super::hybrid::QsfCombiner2<kdfs::iso11770_6::Okdf3::<sha3::Sha3_256, kdfs::u0>, super::xwing::LabelXWing>,
    //         crate::hybrid::ExpandSeed<cipher::consts::U64, kdfs::cshake::XofKdf<sha3::Shake256>>>;

    
    // #[cfg(all(feature="rustcrypto-p384", feature="rustcrypto-ml-kem", feature="rustcrypto-sha3"))]
    // pub type HybridKemQsfP384MlKem1024 = super::hybrid::HybridKem::<
    //         super::ml_kem::MlKemWithAddKeyDer<ml_kem::MlKem1024>,
    //         super::eckem::EcdhKem<p384::NistP384, crate::eckem::EcCombinerNoPubKeys<kdfs::misc::PassThroughKdf>, cipher::consts::U48, super::eckem::EcCompressedEncoder<p384::NistP384>, crate::eckem::SeedAsScalar>, 
    //         //super::ml_kem::MlKemWithAddKeyDer<ml_kem::MlKem1024>,
    //         super::hybrid::QsfCombiner2<kdfs::iso11770_6::Okdf3::<sha3::Sha3_256, kdfs::u0>, QsfLabelP384MlKem1024>,
    //         crate::hybrid::ExpandSeed<cipher::consts::U32, kdfs::cshake::XofKdf<sha3::Shake256>>>;
}

pub mod apple_hpke {
    #[cfg(all(feature="rustcrypto-ml-kem", feature="rustcrypto-x25519", feature="rustcrypto-sha3"))]
    pub type HybridKemXwing = super::hybrid::HybridKem::<
            //super::x25519kem::X25519Capsulator<crate::eckem::EcCombinerNoPubKeys<kdfs::misc::PassThroughKdf>, cipher::consts::U32, crate::eckem::SeedAsScalar>, 
            super::x25519kem::X25519Capsulator<crate::eckem::SeedAsScalar>, 
            super::ml_kem::MlKemWrapper<ml_kem::MlKem768>,
            //super::hybrid::QsfCombiner2<kdfs::iso11770_6::Okdf3::<sha3::Sha3_256, kdfs::u0>, QsfLabelX25519MlKem768>,
            super::hybrid::QsfCombiner2<kdfs::iso11770_6::Okdf3::<sha3::Sha3_256, kdfs::u0>, super::xwing::LabelXWing>,
            crate::hybrid::ExpandSeed<cipher::consts::U32, shake::Shake256>>;
}
/// Composite KEMs as describe in a draft RFC. 
/// 
/// Combines ML-KEM with an Elliptic Curve or RSA based KEM to create a new KEM
#[cfg(all(feature="rustcrypto-ml-kem"))]
pub mod draft_ietf_lamps_pq_composite_kem_07
{
    #[cfg(all(feature="rustcrypto-ml-kem"))]
    use crate::ml_kem::MlKemWrapper;
    //use crate::hybrid::{QsfCombiner, SplitSeed};
    
    use cipher::consts::{B0, B1, U32, U256, U384, U512};
    use cipher::typenum::{UInt, UTerm};
    //use hex_literal::hex;
    //use hybrid_array2::sizes::{U1792};
    // use typenum::U64;
    // use crate::hybrid::HybridKem;
    // #[cfg(feature="rustcrypto-ml-kem")]
    // use ml_kem::{MlKem768, MlKem1024};
    // use crate::eckem::{EcCombinerNoPubKeys, EcUncompressedEncoder, EcdhKem, SeedAsScalar};
    // use kdfs::misc::PassThroughKdf;
    //use kdfs::rfc5869_hkdf::HkdfExtract;
    
    // #[cfg(feature="rustcrypto-p256")]
    // use p256::NistP256;
    // #[cfg(feature="rustcrypto-p384")]
    // use p384::NistP384;
    // #[cfg(feature="rustcrypto-p521")]
    // use p521::NistP521;
    // use kdfs::iso11770_6::Okdf3;
    // use kdfs::u0;
    
    #[cfg(all(feature="rustcrypto-ml-kem", feature="rustcrypto-x25519", feature="rustcrypto-sha3"))]
    pub type HybridKemMlKem768X25519Sha3_256 = crate::hybrid::HybridKem::<MlKemWrapper<ml_kem::MlKem768>,
        //crate::x25519kem::X25519Capsulator<crate::eckem::EcCombinerNoPubKeys<kdfs::misc::PassThroughKdf>, digest::consts::U32, crate::eckem::SeedAsScalar>,
        crate::x25519kem::X25519Capsulator<crate::eckem::SeedAsScalar>,
        crate::hybrid::QsfCombiner<kdfs::iso11770_6::Okdf3::<sha3::Sha3_256, kdfs::u0>,LabelMlKey768X25519Sha3_256>, U32>;

    // #[cfg(all(feature="rustcrypto-ml-kem", feature="rustcrypto-sha2", feature="rustcrypto-p256", feature="rustcrypto-hmac"))]
    // pub type HybridKemMlKem768P256HmacSha256 = crate::hybrid::HybridKem::<MlKemSeedAsPriv<ml_kem::MlKem768>,
    //     crate::eckem::EcdhKem<p256::NistP256, 
    //     crate::eckem::EcCombinerNoPubKeys<kdfs::misc::PassThroughKdf>, digest::consts::U32, crate::eckem::EcUncompressedEncoder<p256::NistP256>>,
    //     crate::hybrid::QsfCombiner<kdfs::rfc5869_hkdf::HkdfExtract<hmac::HmacReset<sha2::Sha256>>,
    //     LabelMlKey768EcdhP256HmacSha256>, typenum::U32>;
    #[cfg(all(feature="rustcrypto-ml-kem", feature="rustcrypto-sha2", feature="rustcrypto-p256", feature="rustcrypto-hmac"))]
    pub type HybridKemMlKem768P256Sha3_256 = crate::hybrid::HybridKem::<MlKemWrapper<ml_kem::MlKem768>,
        crate::eckem::EcdhKem<p256::NistP256, crate::eckem::EcUncompressedEncoder<p256::NistP256>>,
        crate::hybrid::QsfCombiner<kdfs::iso11770_6::Okdf3::<sha3::Sha3_256, kdfs::u0>,
        LabelMlKem768P256Sha3_256>, U32>;

    #[cfg(all(feature="rustcrypto-p384", feature="rustcrypto-hmac"))]
    pub type HybridKemMlKem768P384Sha3_256 = crate::hybrid::HybridKem::<MlKemWrapper<ml_kem::MlKem768>,
        crate::eckem::EcdhKem<p384::NistP384, crate::eckem::EcUncompressedEncoder<p384::NistP384>>,
        crate::hybrid::QsfCombiner<kdfs::iso11770_6::Okdf3::<sha3::Sha3_256, kdfs::u0>,
        LabelMlKey768EcdhP384Sha3_256>, U32>;

    #[cfg(all(feature="rustcrypto-p384", feature="rustcrypto-hmac"))]
    pub type HybridKemMlKem1024P384Sha3_256 = crate::hybrid::HybridKem::<MlKemWrapper<ml_kem::MlKem1024>,
        crate::eckem::EcdhKem<p384::NistP384, crate::eckem::EcUncompressedEncoder<p384::NistP384>>,
        crate::hybrid::QsfCombiner<kdfs::iso11770_6::Okdf3::<sha3::Sha3_256, kdfs::u0>,
        LabelMlKey1024EcdhP384Sha3_256>, U32>;

    #[cfg(all(feature="rustcrypto-ml-kem", feature="rustcrypto-x448", feature="rustcrypto-sha3"))]
    pub type HybridKemMlKem1024X448Sha3_256 = crate::hybrid::HybridKem::<MlKemWrapper<ml_kem::MlKem1024>,
        crate::x448kem::X448Capsulator<crate::eckem::SeedAsScalar>,
        crate::hybrid::QsfCombiner<kdfs::iso11770_6::Okdf3::<sha3::Sha3_256, kdfs::u0>, LabelMlKey1024X448Sha3_256>, 
        crate::hybrid::SplitSeed /*typenum::U32*/>;

    #[cfg(all(feature="rustcrypto-ml-kem", feature="rustcrypto-p521", feature="rustcrypto-hmac", feature="rustcrypto-sha2"))]
    pub type HybridKemMlKem1024P521Sha3_256 = crate::hybrid::HybridKem::<crate::ml_kem::MlKemWrapper<ml_kem::MlKem1024>,
        crate::eckem::EcdhKem<p521::NistP521, crate::eckem::EcUncompressedEncoder<p521::NistP521>>,
        crate::hybrid::QsfCombiner<kdfs::iso11770_6::Okdf3::<sha3::Sha3_256, kdfs::u0>, LabelMlKey1024EcdhP521Sha3_256>, U32>;

    //pub type U1218 = UInt<UInt<UInt<UInt<UInt<UInt<UInt<UInt<UInt<UInt<UInt<UTerm, B1>, B0>, B0>, B1>, B1>, B0>, B0>, B0>, B0>, B1>, B0>;
    pub type U1192 = UInt<UInt<UInt<UInt<UInt<UInt<UInt<UInt<UInt<UInt<UInt<UTerm, B1>, B0>, B0>, B1>, B0>, B1>, B0>, B1>, B0>, B0>, B0>;
    #[cfg(all(feature="rustcrypto-ml-kem", feature="rustcrypto-rsa", feature="rustcrypto-sha2", feature="rustcrypto-sha3"))]
    pub type HybridKemMlkem768Rsa2048HmacSha256 = crate::hybrid::HybridKem::<crate::ml_kem::MlKemWrapper<ml_kem::MlKem768>,
        //crate::rsakem::RsaOaepKem2<U256,typenum::U32,sha2_old::Sha256,sha2_old::Sha256,U1218>,
        //crate::rsakem::RsaOaepKem2<U256,typenum::U32,sha2_old::Sha256,sha2_old::Sha256>,
        crate::rsakem::RsaOaepKem2<U256,super::U32,sha2::Sha256,sha2::Sha256>,
        //crate::hybrid::QsfCombiner<kdfs::rfc5869_hkdf::HkdfExtract<hmac::HmacReset<sha2::Sha256>>, LabelMlKey768Rsa2048HmacSha256>, typenum::U32>;
         crate::hybrid::QsfCombiner<kdfs::iso11770_6::Okdf3::<sha3::Sha3_256, kdfs::u0>, LabelMlKey768Rsa2048HmacSha256>, U32>;

    #[cfg(all(feature="rustcrypto-ml-kem", feature="rustcrypto-rsa", feature="rustcrypto-sha2", feature="rustcrypto-sha3"))]
    pub type HybridKemMlkem768Rsa3072HmacSha256 = crate::hybrid::HybridKem::<crate::ml_kem::MlKemWrapper<ml_kem::MlKem768>,
        //crate::rsakem::RsaOaepKem2<U384,typenum::U32,sha2_old::Sha256,sha2_old::Sha256,hybrid_array2::sizes::U1792>,
        crate::rsakem::RsaOaepKem2<U384,U32,sha2::Sha256,sha2::Sha256>,
        //crate::hybrid::QsfCombiner<kdfs::rfc5869_hkdf::HkdfExtract<hmac::HmacReset<sha2::Sha256>>, LabelMlKey768Rsa3072HmacSha256>, typenum::U32>;
        crate::hybrid::QsfCombiner<kdfs::iso11770_6::Okdf3::<sha3::Sha3_256, kdfs::u0>, LabelMlKey768Rsa3072HmacSha256>, U32>;

    pub type U1793 = UInt<UInt<UInt<UInt<UInt<UInt<UInt<UInt<UInt<UInt<UInt<UTerm, B1>, B1>, B1>, B0>, B0>, B0>, B0>, B0>, B0>, B0>, B1>;
    pub type U1766 = UInt<UInt<UInt<UInt<UInt<UInt<UInt<UInt<UInt<UInt<UInt<UTerm, B1>, B1>, B0>, B1>, B1>, B1>, B0>, B0>, B1>, B1>, B0>;
    #[cfg(all(feature="rustcrypto-ml-kem", feature="rustcrypto-rsa", feature="rustcrypto-sha2", feature="rustcrypto-sha3"))]
    pub type HybridKemMlkem1024Rsa3072HmacSha512 = crate::hybrid::HybridKem::<crate::ml_kem::MlKemWrapper<ml_kem::MlKem1024>,
        //crate::rsakem::RsaOaepKem2<U384,typenum::U32,sha2_old::Sha256,sha2_old::Sha256,U1793>,
        crate::rsakem::RsaOaepKem2<U384,U32,sha2::Sha256,sha2::Sha256>,
        //crate::hybrid::QsfCombiner<kdfs::rfc5869_hkdf::HkdfExtract<hmac::HmacReset<sha2::Sha512>>, LabelMlKey1024Rsa3072HmacSha512>, typenum::U32>;
        crate::hybrid::QsfCombiner<kdfs::iso11770_6::Okdf3::<sha3::Sha3_256, kdfs::u0>, LabelMlKey1024Rsa3072HmacSha512>, U32>;

    //pub type U1218 = UInt<UInt<UInt<UInt<UInt<UInt<UInt<UInt<UInt<UInt<UInt<UTerm, B1>, B0>, B0>, B1>, B1>, B0>, B0>, B0>, B0>, B1>, B0>;
    //pub type U2373 = UInt<UInt<UInt<UInt<UInt<UInt<UInt<UInt<UInt<UInt<UInt<UInt<UTerm, B1>, B0>, B0>, B1>, B0>, B1>, B0>, B0>, B0>, B1>, B0>, B1>;
    pub type U2346 = UInt<UInt<UInt<UInt<UInt<UInt<UInt<UInt<UInt<UInt<UInt<UInt<UTerm, B1>, B0>, B0>, B1>, B0>, B0>, B1>, B0>, B1>, B1>, B0>, B0>;
    #[cfg(all(feature="rustcrypto-ml-kem", feature="rustcrypto-rsa", feature="rustcrypto-sha2", feature="rustcrypto-sha3"))]
    pub type HybridKemMlkem768Rsa4096HmacSha256 = crate::hybrid::HybridKem::<crate::ml_kem::MlKemWrapper<ml_kem::MlKem768>,
        //crate::rsakem::RsaOaepKem2<U512,typenum::U32,sha2_old::Sha256,sha2_old::Sha256,U2373>,
        //crate::rsakem::RsaOaepKem2<U512,typenum::U32,sha2_old::Sha256,sha2_old::Sha256,U2373>,
        crate::rsakem::RsaOaepKem2<U512,U32,sha2::Sha256,sha2::Sha256>,
        //crate::hybrid::QsfCombiner<kdfs::rfc5869_hkdf::HkdfExtract<hmac::HmacReset<sha2::Sha256>>, LabelMlKey768Rsa4096HmacSha256>, typenum::U32>;
        crate::hybrid::QsfCombiner<kdfs::iso11770_6::Okdf3::<sha3::Sha3_256, kdfs::u0>, LabelMlKey768Rsa4096HmacSha256>, U32>;
    
    
    //#[derive(Debug)]
    // pub struct LabelMlKey768X25519Sha3_256; //id-MLKEM768-X25519-SHA3-256
    // impl super::Label for LabelMlKey768X25519Sha3_256{
    //     //const LABEL: &'static[u8] = &hex!("060B6086480186FA6B50050235"); // oid for this hybrid
    //     //const LABEL: &'static[u8] = b"MLKEM768-X25519";
    //     const LABEL: &'static[u8] = &hex!("5c2e2f2f5e5c");
    //}
    #[cfg(all(feature="rustcrypto-ml-kem", feature="rustcrypto-x25519", feature="rustcrypto-sha3"))]
    type LabelMlKey768X25519Sha3_256 = crate::xwing::LabelXWing;


    pub struct LabelMlKem768P256Sha3_256;
    impl super::Label for LabelMlKem768P256Sha3_256{
        //const LABEL: &'static[u8] = &hex!("060B6086480186FA6B5005024E"); // oid for this hybrid
        const LABEL: &'static[u8] = b"MLKEM768-P256";
        //const LABEL: &'static[u8] = const_oid::ObjectIdentifier::new_unwrap("2.16.840.1.114027.80.5.2.78").as_bytes();
    }

    // #[derive(Debug)]
    // pub struct LabelMlKey768EcdhP256HmacSha256; //id-MLKEM768-X25519-SHA3-256
    // impl super::Label for LabelMlKey768EcdhP256HmacSha256{
    //     //const LABEL: &'static[u8] = &hex!("060B6086480186FA6B50050236"); // oid for this hybrid
    //     const LABEL: &'static[u8] = b"MLKEM768-P256"; // oid for this hybrid
    // }

    #[derive(Debug)]
    pub struct LabelMlKey768Rsa2048HmacSha256; //id-MLKEM768-X25519-SHA3-256
    impl super::Label for LabelMlKey768Rsa2048HmacSha256{
        //const LABEL: &'static[u8] = &hex!("060B6086480186FA6B50050232"); // oid for this hybrid
        const LABEL: &'static[u8] = b"MLKEM768-RSAOAEP2048";
    }
    #[derive(Debug)]
    pub struct LabelMlKey768Rsa3072HmacSha256; //id-MLKEM768-X25519-SHA3-256
    impl super::Label for LabelMlKey768Rsa3072HmacSha256{
        //const LABEL: &'static[u8] = &hex!("060B6086480186FA6B50050233"); // oid for this hybrid
        const LABEL: &'static[u8] = b"MLKEM768-RSAOAEP3072";
    }
    #[derive(Debug)]
    pub struct LabelMlKey768Rsa4096HmacSha256; //id-MLKEM768-X25519-SHA3-256
    impl super::Label for LabelMlKey768Rsa4096HmacSha256{
        //const LABEL: &'static[u8] = &hex!("060B6086480186FA6B50050234"); // oid for this hybrid
        const LABEL: &'static[u8] = b"MLKEM768-RSAOAEP4096";
    }

    #[derive(Debug)]
    pub struct LabelMlKey768EcdhP384Sha3_256; //id-MLKEM768-X25519-SHA3-256
    impl super::Label for LabelMlKey768EcdhP384Sha3_256{
        //const LABEL: &'static[u8] = &hex!("060B6086480186FA6B50050237"); // oid for this hybrid
        const LABEL: &'static[u8] = b"MLKEM768-P384";
    }   
    //pub type QsfMlKem768P256PublicKey = QsfKemMlKemEccPublicKey<ml_kem::MlKem1024, p384::NistP384, LabelMlKem1024P384>;


    #[derive(Debug)]
    pub struct LabelMlKey1024Rsa3072HmacSha512; //id-MLKEM768-X25519-SHA3-256
    impl super::Label for LabelMlKey1024Rsa3072HmacSha512{
        //const LABEL: &'static[u8] = &hex!("060B6086480186FA6B5005023D"); // oid for this hybrid
        const LABEL: &'static[u8] = b"MLKEM1024-RSAOAEP3072";
    }   
    

    #[derive(Debug)]
    pub struct LabelMlKey1024EcdhP384Sha3_256; //id-MLKEM768-X25519-SHA3-256
    impl super::Label for LabelMlKey1024EcdhP384Sha3_256{
        //const LABEL: &'static[u8] = &hex!("060B6086480186FA6B50050239"); // oid for this hybrid
        const LABEL: &'static[u8] = b"MLKEM1024-P384";
    }   

    #[derive(Debug)]
    pub struct LabelMlKey1024X448Sha3_256; //id-MLKEM768-X25519-SHA3-256
    impl super::Label for LabelMlKey1024X448Sha3_256{
        //const LABEL: &'static[u8] = &hex!("060B6086480186FA6B5005023B"); // oid for this hybrid
        const LABEL: &'static[u8] = b"MLKEM1024-X448";
    }   

    #[derive(Debug)]
    pub struct LabelMlKey1024EcdhP521Sha3_256; //id-MLKEM768-X25519-SHA3-256
    impl super::Label for LabelMlKey1024EcdhP521Sha3_256{
        //const LABEL: &'static[u8] = &hex!("060B6086480186FA6B5005023C"); // oid for this hybrid
        const LABEL: &'static[u8] = b"MLKEM1024-P521";
    }   

}

// pub mod draft_ietf_lamps_cms_composite_kem
// {
//     use hex_literal::hex;
//     use p256::U32;
//     use crate::ml_kem::MlKemWrapper;

//      #[cfg(all(feature="rustcrypto-ml-kem", feature="rustcrypto-sha2", feature="rustcrypto-p256", feature="rustcrypto-hmac"))]
//     pub type HybridCmsKemMlKem768P256Sha3_256 = crate::hybrid::HybridKem::<MlKemWrapper<ml_kem::MlKem768>,
//         crate::eckem::EcdhKem<p256::NistP256, crate::eckem::EcUncompressedEncoder<p256::NistP256>>,
//         crate::hybrid::QsfCombiner<kdfs::iso11770_6::Okdf3::<sha3::Sha3_256, kdfs::u0>,
//         LabelCmsMlKem768P256Sha3_256>, U32>;

//     pub struct LabelCmsMlKem768P256Sha3_256;
//     impl super::Label for LabelCmsMlKem768P256Sha3_256{
//         //const LABEL: &'static[u8] = &hex!("060B6086480186FA6B5005024E"); // oid for this hybrid
//         const LABEL: &'static[u8] = &hex!("3010300b060960864801650304012d020120");
//         //const LABEL: &'static[u8] = const_oid::ObjectIdentifier::new_unwrap("2.16.840.1.114027.80.5.2.78").as_bytes();
//     }
// }


/// Xwing Kem defines in a draft RFC. Uses MlKem768, X25519 and a kdf based on Sha3 with a specific label
#[cfg(all(feature="rustcrypto-ml-kem", feature="rustcrypto-x25519", feature="rustcrypto-sha3"))]
pub mod xwing {
    use crate::hybrid::HybridKem;
    use crate::ml_kem::{MlKemWrapper};
    use crate::x25519kem::X25519Capsulator;
    use crate::eckem::{SeedAsScalar};
    use crate::hybrid::{QsfCombiner,ExpandSeed};
    use super::U32;
    // pub type XwingMlKem768X25519 = crate::hybrid::HybridKem::<crate::ml_kem::MlKemWithAddKeyDer::<ml_kem::MlKem768>,
    //      crate::x25519kem::X25519Capsulator<crate::eckem::EcCombinerNoPubKeys<key_derivation::misc::PassThroughKdf>, elliptic_curve::consts::U32>,
    //      crate::hybrid::KemCombiner<key_derivation::iso11770_6::Okdf3::<sha3::Sha3_256, key_derivation::u0>, LabelXWing>>;
    
    pub type XwingMlKem768X25519 = HybridKem::<
            MlKemWrapper<ml_kem::MlKem768>,
            //X25519Capsulator<EcCombinerNoPubKeys<PassThroughKdf>, U32, SeedAsScalar>,
            X25519Capsulator<SeedAsScalar>,
            QsfCombiner<kdfs::iso11770_6::Okdf3::<sha3::Sha3_256, kdfs::u0>, LabelXWing>, 
            ExpandSeed<U32, shake::Shake256>>;
    


    
    #[derive(Debug)]
    pub struct LabelXWing; //id-MLKEM768-X25519-SHA3-256
    impl super::Label for LabelXWing{
        // The label is ascii art for an X-wing which looks a bit odd with escape sequences...5c2e2f2f5e5c
        const LABEL: &'static[u8] = b"\\./\
                                       /^\\";
    }
}


#[cfg(all(feature="rustcrypto-ml-kem"))]
pub mod draft_irtf_cfrg_concrete_hybrid_kems
{
    use crate::hybrid::HybridKem;
    #[cfg(all(feature="rustcrypto-ml-kem"))]
    use crate::ml_kem::{MlKemWrapper};
    use crate::eckem::{EcdhKemUncompressed, SeedAsScalar};
    use crate::hybrid::{QsfCombiner,ExpandSeed};
    use super::{U32};
    #[cfg(all(feature="rustcrypto-sha3"))]
    use shake::Shake256;
    #[cfg(all(feature="rustcrypto-p384"))]
    use p384::NistP384;

    pub struct LabelMlKem768P256;
    impl super::Label for LabelMlKem768P256 {
        const LABEL: &'static[u8] = b"MLKEM768-P256"; // https://datatracker.ietf.org/doc/draft-irtf-cfrg-concrete-hybrid-kems/
    }
    pub struct LabelMlKem1024P384;
    impl super::Label for LabelMlKem1024P384 {
        const LABEL: &'static[u8] = b"MLKEM1024-P384"; 
    }

    #[cfg(all(feature="rustcrypto-ml-kem", feature="rustcrypto-p256", feature="rustcrypto-sha3"))]
    pub type ConcreteMlKem768P256 = HybridKem::<
            MlKemWrapper<ml_kem::MlKem768>,
            EcdhKemUncompressed<p256::NistP256,SeedAsScalar>,
            QsfCombiner<kdfs::iso11770_6::Okdf3::<sha3::Sha3_256, kdfs::u0>, LabelMlKem768P256>, 
            ExpandSeed<U32, Shake256> >;

    // pub type ConcreteMlKem768P256_2 = HybridKem::<
    //         MlKemWrapper<ml_kem::MlKem768>,
    //         EcdhKemUncompressed<p256::NistP256,SeedAsScalar>,
    //         QsfCombiner<kdfs::iso11770_6::Okdf3::<sha3::Sha3_256, kdfs::u0>, LabelMlKem768P256>, 
    //         ExpandSeed<U32, Shake256> >;

    #[cfg(all(feature="rustcrypto-ml-kem", feature="rustcrypto-p384", feature="rustcrypto-sha3"))]
    pub type ConcreteMlKem1024P384 = HybridKem::<
            MlKemWrapper<ml_kem::MlKem1024>,
            EcdhKemUncompressed<NistP384,SeedAsScalar>,
            QsfCombiner<kdfs::iso11770_6::Okdf3::<sha3::Sha3_256, kdfs::u0>, LabelMlKem1024P384>, 
            ExpandSeed<U32, Shake256> >;

}


#[cfg(all(feature="rustcrypto-sha2", any(feature="rustcrypto-p256", feature="rustcrypto-p384")))]
pub mod jwe {

    use crate::{eckem::{EcdhKemUncompressed, SeedAsScalar}, kem_with_kdf::{CombinerNoKeys, KemWithKdf}};
    use crate::kem_with_kdf::JwaKdf;

    #[cfg(all(feature="rustcrypto-p256"))]
    pub type JweKemP256Sha256<'a,N> = KemWithKdf::<EcdhKemUncompressed::<p256::NistP256, SeedAsScalar>, CombinerNoKeys, JwaKdf<'a,kdfs::nistsp800_56::ConcatKdf<sha2::Sha256>,true>,N>;
    #[cfg(all(feature="rustcrypto-p384"))]
    pub type JweKemP384Sha256<'a,N> = KemWithKdf::<EcdhKemUncompressed::<p384::NistP384, SeedAsScalar>, CombinerNoKeys, JwaKdf<'a,kdfs::nistsp800_56::ConcatKdf<sha2::Sha256>, true>,N>;
}
