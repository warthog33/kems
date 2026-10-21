//! This crate provides mplementations of Key Encapsulation Mechanism as defined in various standards.
//! 
//! Many of the standards describe similar KEMs, so heavy use is made of generics and type aliases.
//! The root of the crate contains traits and common structures, whilst specific implementations are
//! included in the sub modules
//! 
use std::fmt::Debug;

#[allow(unused)]
use std::{array::TryFromSliceError, ops::{Add, Rem}};
#[cfg(feature="rustcrypto-aeskw")]
use cipher::typenum::{NonZero, Zero, Sum};
#[allow(unused)]
use cipher::{BlockCipherDecrypt, BlockCipherEncrypt, KeyInit, KeySizeUser};
#[allow(unused)]
use cipher::consts::{U8, U16, U32, U384, U256, U512};
pub use kem::{Kem, Ciphertext, SharedKey, TryDecapsulate, Encapsulate, TryKeyInit, InvalidKey};

use crate::kem_with_kdf::{CombinerCiphertext, KemWithKdf};


#[cfg(all(feature="rustcrypto-ml-kem", feature="rustcrypto-x25519", feature="rustcrypto-sha3"))]
use crate::{hybrid::QsfCombiner2, x25519kem::X25519Kem};

#[allow(unused)]
use kdfs::iso11770_6::Okdf3;

#[cfg(all(feature="rustcrypto-sha3"))]
use sha3::Sha3_256;

#[cfg(all(feature="rustcrypto-ml-kem"))]
use crate::hybrid::{QsfCombiner,HybridKem};

use crate::eckem::{EcdhKemUncompressed};
#[cfg(all(feature="rustcrypto-rsa", feature="rustcrypto-sha2"))]
use crate::rsakem::RsaOaepKem;
#[cfg(all(feature="rustcrypto-x448"))]
use crate::{x448kem::X448Kem};
#[cfg(all(feature="rustcrypto-x25519"))]
use crate::xwing::XwingMlKem768X25519;
#[allow(unused)]
#[cfg(all(feature="oid"))]
use const_oid::{AssociatedOid,ObjectIdentifier};
use kdfs::Label;

#[cfg(all(feature="rustcrypto-p256"))]
use p256::NistP256;
#[cfg(all(feature="rustcrypto-p384"))]
use p384::NistP384;
#[cfg(all(feature="rustcrypto-p521"))]
use p521::NistP521;
#[cfg(all(feature="rustcrypto-sha2"))]
use sha2::Sha256;




#[allow(unused)]
use elliptic_curve::{point::PointCompression, CurveArithmetic};
#[allow(unused)]
use kdfs::ansi_x9_63::X963Kdf;
#[cfg(feature="rustcrypto-sha1")]
use sha1::Sha1;
#[cfg(feature="rustcrypto-sha2")]
use sha2::{Sha224, Sha384, Sha512};
#[allow(unused)]
use crate::kem_with_kdf::{CombinerNoKeys, KemAuthWithKdf};
    

use crate::eckem::EcdhKemCompressed;
#[cfg(feature="rustcrypto-rsa")]
use crate::rsakem::{RsaOrigKem};

use eckem::{EcdhAuthKemUncompressed};

use kdfs::{nistsp800_56::ConcatKdf};
use kdfs::iso18033_2::{Kdf1, Kdf2};

pub use kdfs::hybrid_array::{Array, ArraySize};
pub use rand_core::{CryptoRngCore, CryptoRng, RngCore, OsRng};

pub mod kem_with_kdf;

#[cfg(feature="rustcrypto-rsa")]
pub mod rsakem;
pub mod eckem;
#[cfg(feature="rustcrypto-x25519")]
pub mod x25519kem;

#[cfg(feature="rustcrypto-x448")]
pub mod x448kem;

// #[cfg(feature="rustcrypto-ml-kem")]
// pub mod ml_kem;

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

/// Trait used for auth decapsulators and auth encapsulators which need a private key and a public key to be specified
pub trait FromKeys {
    type PrivateKey;
    type PublicKey;
    fn from_keys ( pub_key: Self::PublicKey, priv_key: Self::PrivateKey ) -> Self;
}

// pub trait EncapsulateDeterministic2<EK, SS> {
//     /// Encapsulation error
//     type Error;
//     /// Nominal seed size, but not strictly requirement
//     type SeedSize: ArraySize;

//     /// Encapsulates a fresh shared secret
//     //fn encapsulate_deterministic(&self, seed: &Array<u8, Self::SeedSize>) -> Result<(EK, SS), Self::Error>;
//     fn encapsulate_deterministic(&self, seed: &[u8]) -> Result<(EK, SS), Self::Error>;
// }

pub trait EncapsulateDeterministic: Encapsulate {

    //type Kem: kem::Kem;
    type SeedSize: ArraySize;
    
    //fn encapsulate_deterministic(&self, seed: &Array<u8, Self::SeedSize>) -> Result<(EK, SS), Self::Error>;
    fn encapsulate_deterministic(&self, seed: &[u8]) -> (Ciphertext<Self::Kem>, SharedKey<Self::Kem>);
}

/// Trait for getting the encapsulator from a public key, this is used for the test vectors to verify that the public key encodes to the correct byte array
// pub trait GetEncapsulator {
//     /// The type of the encapsulator, this is used for the test vectors to verify that the public key encodes to the correct byte array
//     type Encapsulator;
//     /// Returns a reference to the underlying encapsulator, this is used for the test vectors to verify that the public key encodes to the correct byte array
//     fn encapsulation_key_old(&self) -> Self::Encapsulator;
// }

/// Trait for setting the KDF
pub trait SetKdf {
    /// The type of the KDF
    type Kdf;
    /// Sets the KDF
    fn set_kdf(&mut self, kdf: Self::Kdf);
}



///
/// Label is used as a pseudo const generic for strings, allow for the type 
/// to be included in a new type definition
/// 
macro_rules! define_label {
    ($name:ident, $label_bytes:literal) => {
        #[derive(Debug)]
        pub struct $name;

        impl Label for $name {
            const LABEL: &'static [u8] = $label_bytes;
        }
    };
}

define_label!(LabelXWing, b"\\.//^\\");
define_label!(LabelMlKem1024P384, b"MLKEM1024-P384");// https://datatracker.ietf.org/doc/html/draft-ietf-lamps-pq-composite-kem-19
define_label!(LabelMlKem1024EcdhP521, b"MLKEM1024-P521"); // https://datatracker.ietf.org/doc/html/draft-ietf-lamps-pq-composite-kem-19
define_label!(LabelMlKem1024X448, b"MLKEM1024-X448"); // https://datatracker.ietf.org/doc/html/draft-ietf-lamps-pq-composite-kem-19
define_label!(LabelMlKem768P256, b"MLKEM768-P256"); // https://datatracker.ietf.org/doc/html/draft-ietf-lamps-pq-composite-kem-19
define_label!(LabelMlKey768EcdhP384, b"MLKEM768-P384"); // https://datatracker.ietf.org/doc/html/draft-ietf-lamps-pq-composite-kem-19
define_label!(LabelMlKey768Rsa2048HmacSha256, b"MLKEM768-RSAOAEP2048"); // https://datatracker.ietf.org/doc/html/draft-ietf-lamps-pq-composite-kem-19
define_label!(LabelMlKey768Rsa3072HmacSha256, b"MLKEM768-RSAOAEP3072"); // https://datatracker.ietf.org/doc/html/draft-ietf-lamps-pq-composite-kem-19
define_label!(LabelMlKey1024Rsa3072HmacSha512, b"MLKEM1024-RSAOAEP3072"); // https://datatracker.ietf.org/doc/html/draft-ietf-lamps-pq-composite-kem-19
define_label!(LabelMlKey768Rsa4096HmacSha256, b"MLKEM768-RSAOAEP4096"); // https://datatracker.ietf.org/doc/html/draft-ietf-lamps-pq-composite-kem-19
define_label!(LabelMlkem768BP256r1Sha3_256, b"MLKEM768-BP256"); // https://datatracker.ietf.org/doc/html/draft-ietf-lamps-pq-composite-kem-19
define_label!(LabelMlkem1024BP384r1Sha3_256, b"MLKEM1024-BP384"); // https://datatracker.ietf.org/doc/html/draft-ietf-lamps-pq-composite-kem-19

define_label!(QsfLabelMlKem768P256, b"QSF-KEM(ML-KEM-768,P-256)-XOF(SHAKE256)-KDF(SHA3-256)");
define_label!(QsfLabelMlKem1024P384, b"QSF-KEM(ML-KEM-1024,P-384)-XOF(SHAKE256)-KDF(SHA3-256)");
define_label!(UniversalCombinerLabelMlKem768P256, b"KitchenSink-KEM(ML-KEM-768,P-256)-XOF(SHAKE256)-KDF(HKDF-SHA-256)");
define_label!(UniversalCombinerLabelMlKem768X25519, b"KitchenSink-KEM(ML-KEM-768,X25519)-XOF(SHAKE256)-KDF(HKDF-SHA-256)");



/// An object that knows what size it is
/// Similar to the trait from ML-KEM except is uses Generic Array in place of Hybrid Array because
/// hybrid arrays only support a subset of all sizes
// pub trait EncodedSizeUser2 {
//     /// The size of an encoded object
//     type EncodedSize: ArrayLength; //<u8>;

//     /// Parse an object from its encoded form
//     fn from_bytes(enc: &Encoded<Self>) -> Self;

//     /// Serialize an object to its encoded form
//     fn as_bytes(&self) -> Encoded<Self>;
// }
// /// A byte array encoding a value the indicated size
//pub type Encoded<T> = GenericArray<u8, <T as EncodedSizeUser2>::EncodedSize>;






/// Inverse function which accepts a fixed length byte array and returns a public key
// pub trait DecodeArray<P> {
//     type EncodedLen: ArraySize; //<u8>;
//     type Error;
//     fn decode(encoded_bytes: &Array<u8, Self::EncodedLen>) -> Result<P, Self::Error>;
// }

/// Used for encoding a public key of the sender to a byte array
// pub trait GetSenderPublicKeyBytes {
//     type EncodedLen: ArraySize; //<u8>;
//     fn get_sender_public_key_bytes(&self) -> Array<u8, Self::EncodedLen>;
// }

/// Used for encoding a public key of the recipient to a byte array
// pub trait GetRecipientPublicKeyBytes {
//     type EncodedLen: ArraySize; //<u8>;
//     //fn get_recipient_public_key_bytes(&self) -> GenericArray<u8, Self::EncodedLen>;
//     fn get_recipient_public_key_bytes<'a>(&'a self) -> Cow<'a, [u8]>;
// }




/// Used for encoding a secret key to a byte array, this is used for the test vectors to verify that the private key encodes to the correct byte array
// pub trait EncodeSeed {
//     /// The size of an encoded object
//     type EncodedSize: ArraySize;

//     /// Parse an object from its encoded form
//     fn from_seed_bytes(enc: &Array::<u8, Self::EncodedSize>) -> Self;

//     /// Serialize an object to its encoded form
//     fn as_seed_bytes(&self) -> Option<Array::<u8, Self::EncodedSize>>;
// }

pub trait WrappedCek<KW, SS2>  {
    /// Size of the unwrapped subject key
    type CekSize: ArraySize;
    /// Size of the wrapped subject key
    type WrappedCekSize: ArraySize;
    /// Size of the wrapping key
    type KekSize: ArraySize;

    type Error;

    fn wrap(&self, kek: &Array<u8, Self::KekSize>, cek: &Array<u8, Self::CekSize>) -> Array<u8, Self::WrappedCekSize>;
    fn unwrap(&self, kek: &Array<u8, Self::KekSize>, wrapped_key: &Array<u8, Self::WrappedCekSize>) -> Result<Array<u8, Self::CekSize>, Self::Error/*aes_kw::IntegrityCheckFailed*/>;
}

/// Trait for encapsulators which support key wrapping, this is used for the test vectors to verify that the encapsulator can wrap a key correctly
pub trait EncapsulateWithKeyWrap<KW, SS2> : Encapsulate + WrappedCek<KW, SS2>{
    
    //type WrappedCekSize: ArraySize;
    
    //type CekSize: ArraySize;
    /// Encapsulates a fresh shared secret and wraps a key, the shared secret is used to derive a wrapping key which is used to wrap the key, the encapsulated key and the wrapped key are returned
    //fn encapsulate_and_wrap(&self, key: &Array<u8, Self::LK>) -> Result<(EK, Array<u8, Self::LW>), ()>;
    fn encapsulate_and_wrap(&self, key: &Array<u8, Self::CekSize>) -> Result<(Ciphertext<Self::Kem>, Array<u8, Self::WrappedCekSize>), ()>;
}

//type WrappedCek<KW, SS2> = Array<u8, <KW as KeySizeUser>::KeySize>;

/// Trait for encapsulators which support deterministic key wrapping, this is used for the test vectors to verify that the encapsulator can wrap a key correctly using a deterministic seed, this is used for the test vectors to verify that the encapsulator can wrap a key correctly using a deterministic seed
pub trait EncapsulateWithKeyWrapDeterministic<KW, SS2> : EncapsulateDeterministic + WrappedCek<KW, SS2>{ //2<EK,SS1>{
    /// Size of the wrapping key
    //type WrappedCekSize: ArraySize;
    /// Size of the wrapped key
    //type CekSize: ArraySize;
    /// Encapsulates a fresh shared secret and wraps a key using a deterministic seed, the shared secret is used to derive a wrapping key which is used to wrap the key, the encapsulated key and the wrapped key are returned
    fn encapsulate_and_wrap_deterministic(&self, seed: &[u8], key: &Array<u8, Self::CekSize>) -> Result<(Ciphertext<Self::Kem>, Array<u8, Self::WrappedCekSize>), ()>;
}

/// Trait for decapsulators which support key unwrapping, this is used for the test vectors to verify that the decapsulator can unwrap a key correctly
pub trait TryDecapsulateWithKeyWrap<KW, SS2> : TryDecapsulate + WrappedCek<KW, SS2>//DecapsulateOld<EK,SS1>
{
    type Error;
    /// Size of the wrapping key
    //type WrappedCekSize: ArraySize;
    /// Size of the wrapped key
    //type CekSize: ArraySize;
    /// Decapsulates a shared secret and unwraps a key, the shared secret is used to derive a wrapping key which is used to unwrap the key, the unwrapped key is returned
    fn decapsulate_and_unwrap(&self, encapsulated_key: &Ciphertext<Self::Kem>, wrapped_key: &Array<u8, Self::WrappedCekSize>) -> Result<Array<u8, Self::CekSize>, <Self as TryDecapsulateWithKeyWrap<KW, SS2>>::Error>;
}


#[cfg(feature="rustcrypto-aeskw")]
impl<T,A,SSL> WrappedCek<aes_kw::AesKw<A>, SSL> for T
where SSL: ArraySize + Add<U8> + Rem<U8> + NonZero,
    Sum<SSL, U8>: ArraySize,
    <SSL as Rem<U8>>::Output: Zero,
    A: KeySizeUser + KeyInit + BlockCipherEncrypt<BlockSize = U16> + BlockCipherDecrypt<BlockSize = U16>
{
    type CekSize = SSL;
    type WrappedCekSize = Sum<SSL, U8>;
    type KekSize = A::KeySize;
    type Error = aes_kw::IntegrityCheckFailed;

    fn wrap(&self, kek: &Array<u8, Self::KekSize>, cek: &Array<u8, Self::CekSize>) -> Array<u8, Self::WrappedCekSize> {
        let wrapping_key = aes_kw::AesKw::<A>::new(kek);
        wrapping_key.wrap_fixed_key(cek)
    }
    
    fn unwrap(&self, kek: &Array<u8, Self::KekSize>, wrapped_key: &Array<u8, Self::WrappedCekSize>) -> Result<Array<u8, Self::CekSize>, aes_kw::IntegrityCheckFailed> {
        let wrapping_key = aes_kw::AesKw::<A>::new(kek);
        wrapping_key.unwrap_fixed_key(wrapped_key)
    }
}



#[cfg(feature="rustcrypto-aeskw")]
impl<T,A,SSL> TryDecapsulateWithKeyWrap<aes_kw::AesKw<A>, SSL> for T
where 
    T: TryDecapsulate,
    T::Kem: Kem<SharedKeySize=A::KeySize>,
    SSL: ArraySize + Add<U8> + NonZero + Rem<U8>,
    <SSL as Add<U8>>::Output: ArraySize,
    <SSL as Rem<U8>>::Output: Zero,
    A: BlockCipherDecrypt<BlockSize = U16> + KeyInit + BlockCipherEncrypt<BlockSize = U16>,
{
    type Error = aes_kw::IntegrityCheckFailed;
    // type WrappedCekSize = Sum<SSL, U8>;
    // type CekSize = SSL;
    
    fn decapsulate_and_unwrap(&self, encapsulated_key: &Ciphertext<Self::Kem>, wrapped_key: &Array<u8, Self::WrappedCekSize>) 
    -> Result<Array<u8, SSL>, <Self as TryDecapsulateWithKeyWrap<aes_kw::AesKw<A>, SSL>>::Error> 
    {
        let shared_secret = self.try_decapsulate(encapsulated_key).map_err(|_| aes_kw::IntegrityCheckFailed)?;
        // let wrapping_key = aes_kw::AesKw::<A>::new(&shared_secret);
        // wrapping_key.unwrap_fixed_key(wrapped_key)
        WrappedCek::<aes_kw::AesKw<A>, SSL>::unwrap(self, &shared_secret, wrapped_key)
    }
}



#[cfg(feature="rustcrypto-aeskw")]
impl<T,A,SSL> EncapsulateWithKeyWrap<aes_kw::AesKw<A>, SSL> for T
where 
    T: Encapsulate,
    T::Kem: Kem<SharedKeySize = A::KeySize>,
    SSL: ArraySize + Add<U8> + NonZero + Rem<U8>,
    <SSL as Add<U8>>::Output: ArraySize,
    <SSL as Rem<U8>>::Output: Zero,
    A: BlockCipherEncrypt<BlockSize = U16> + KeyInit + BlockCipherDecrypt<BlockSize = U16>,
{
    fn encapsulate_and_wrap(&self, key: &Array<u8, Self::CekSize>) -> Result<(Ciphertext<Self::Kem>, Array<u8, Self::WrappedCekSize>), ()> {
        let (ek, shared_secret) = self.encapsulate();
        let wrapped_cek = WrappedCek::<aes_kw::AesKw<A>, SSL>::wrap(self, &shared_secret, key);
        // let wrapping_key = aes_kw::AesKw::<A>::new(&shared_secret);
        // Ok((ek, wrapping_key.wrap_fixed_key(&key)))
        Ok((ek, wrapped_cek))
    }
}

#[cfg(feature="rustcrypto-aeskw")]
impl<T,A,SSL> EncapsulateWithKeyWrapDeterministic<aes_kw::AesKw<A>, SSL> for T
where 
    T: EncapsulateDeterministic,
    T::Kem: Kem<SharedKeySize = A::KeySize>,
    SSL: ArraySize + Add<U8> + NonZero + Rem<U8>,
    <SSL as Add<U8>>::Output: ArraySize,
    <SSL as Rem<U8>>::Output: Zero,
    A: BlockCipherEncrypt<BlockSize = U16> + KeyInit + BlockCipherDecrypt<BlockSize = U16>,
{
    
    fn encapsulate_and_wrap_deterministic(&self, seed: &[u8], key: &Array<u8, Self::CekSize>) -> Result<(Ciphertext<Self::Kem>, Array<u8, Self::WrappedCekSize>), ()> {
        let (ek, shared_secret2) = self.encapsulate_deterministic(seed);

        let wrapped_cek = WrappedCek::<aes_kw::AesKw<A>, SSL>::wrap(self, &shared_secret2, key);
        // let wrapping_key = aes_kw::AesKw::<A>::new(&shared_secret2);
        // Ok((ek, wrapping_key.wrap_fixed_key(&key)))
        Ok((ek, wrapped_cek))
    }
}



pub trait KemExtensions : Kem {

    fn from_public_key (public_key: <Self::EncapsulationKey as FromKey>::Key) -> Self::EncapsulationKey
        where Self::EncapsulationKey: FromKey
    {
        return Self::EncapsulationKey::from_key(public_key);
    }
  
    fn from_private_key (priv_key: <Self::DecapsulationKey as FromKey>::Key) -> Self::DecapsulationKey
        where Self::DecapsulationKey: FromKey
    {
        return Self::DecapsulationKey::from_key(priv_key);
    }

    fn from_bytes_encap ( bytes: &Array::<u8, <Self::EncapsulationKey as KeySizeUser>::KeySize> ) -> Self::EncapsulationKey
    where Self::EncapsulationKey: KeyInit,
    {
        <Self::EncapsulationKey as KeyInit>::new(bytes)
    }
    fn try_from_bytes_encap ( bytes: &Array::<u8, <Self::EncapsulationKey as KeySizeUser>::KeySize> ) -> Result<Self::EncapsulationKey, InvalidKey>
    where Self::EncapsulationKey: TryKeyInit,
    {
        Self::EncapsulationKey::new(bytes)
    }
    fn try_from_slice_encap ( bytes: &[u8] ) -> Result<Self::EncapsulationKey, InvalidKey>
    where Self::EncapsulationKey: TryKeyInit
    {
        Self::EncapsulationKey::new_from_slice(bytes)
    }

    fn from_bytes_decap ( bytes: &Array::<u8, <Self::DecapsulationKey as KeySizeUser>::KeySize> ) -> Self::DecapsulationKey
    where Self::DecapsulationKey: KeyInit,
    {
        Self::DecapsulationKey::new(bytes)
    }
    fn try_from_bytes_decap ( bytes: &Array::<u8, <Self::DecapsulationKey as KeySizeUser>::KeySize> ) -> Result<Self::DecapsulationKey, InvalidKey>
    where Self::DecapsulationKey: TryKeyInit,
    {
        Self::DecapsulationKey::new(bytes)
    }
    fn try_from_slice_decap ( bytes: &[u8] ) -> Result<Self::DecapsulationKey, InvalidKey>
    where Self::DecapsulationKey: TryKeyInit
    {
        Self::DecapsulationKey::new_from_slice(bytes)
    }
    fn try_from_slice_decap2 ( bytes: &[u8] ) -> Result<Self::DecapsulationKey, cipher::InvalidLength>
    where Self::DecapsulationKey: KeyInit
    {
        Self::DecapsulationKey::new_from_slice(bytes)
    }
}

impl<T: Kem> KemExtensions for T
{}

/// Ciphertext, a fixed size field representing the encapsulated key
//pub type Ciphertext<C> = Array<u8, <C as Kem>::CiphertextSize>;
/// SharedKey, a fixed size type containing the shared key
//pub type SharedKey<C> = Array<u8, <C as Kem>::SharedKeySize>;

/// Trait for generating an encapsulator and decapsulator from a seed, the seed is not necessarily the same size as the private key, but it should be of a fixed size
// pub trait GenerateDeterministic3 {
//     /// The size of the seed used to generate the encapsulator, this is not necessarily the same as the size of the private key, but it should be of a fixed size
//     type SeedSize: ArraySize;
//     type Public;
//     type Private;
//     type Error;

//     fn generate_deterministic(seed: &Array::<u8, Self::SeedSize>) -> Result<(Self::Public, Self::Private), Self::Error>;
    
// }

/// Trait for deriving a key pair from a seed, the seed is not necessarily the same size as the private key, but it should be of a fixed size
/// <S> is a type of the resultant secret key
// pub trait GenerateDeterministic2<SK> {
//     /// The size of the seed used to derive the key pair, this is not necessarily the same as the size of the private key, but it should be of a fixed size
//     type SeedSize: ArraySize;
//     /// Error type for key derivation
//     type Error;
//     /// Derive a key pair from a seed, the seed is not necessarily the same size as the private key, but it should be of a fixed size
//     fn generate_deterministic2( seed: &[u8]) -> Result<SK, Self::Error>;
// }

// pub trait GenerateDeterministic4 {
//     type SeedSize: ArraySize;
//     type Error;
//     fn generate_deterministic(seed: &Array::<u8, Self::SeedSize>) -> Result<Self, Self::Error> where Self: Sized;

// }


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
    use crate::{eckem::EcMqvAuthKemUncompressed, *};
    /// NIST describes key agreement using ECC in SP800-56A, this is option 1 from the document
    //pub type EcCombinerConcat<H> = super::eckem::EcCombinerNoPubKeys<ConcatKdf<H>>; 
    // NIST SP800-56A includes two key derivation methods for using the shared secret, this is option 2 which uses 
    // ASN.1 DER encoding of Algorithm ID, PartyUInfo, PartyVInfo and optionally SuppPubInfo and/or SuppPrivInfo
    
    /// As described in NIST SP 800-56A, 6.2.2.2 (Cofactor) One-Pass Diffie-Hellman Scheme
    pub type EccOnePassDhCapsulator<C,K,L> = KemAuthWithKdf<EcdhKemUncompressed<C>, CombinerNoKeys, K, L>;
        
    /// As described in NIST SP 800-56A, 6.2.1.2 (Cofactor) One-Pass Unified Model Scheme
    pub type EccOnePassUnifiedKem<C,K,L> = KemAuthWithKdf<EcdhAuthKemUncompressed<C>, CombinerNoKeys, K, L>;

    /// As described in NIST SP 800-56A, 6.2.1.4 One-Pass MQV, C(1e, 2s, ECC MQV) Scheme
    pub type EccOnePassMqvKem<C,K,L> = KemAuthWithKdf<EcMqvAuthKemUncompressed<C>, CombinerNoKeys, K,L>;   
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
    
    use crate::*;
    
    /// Type representing the 1-Pass Diffie Helmann Scheme using the NIST SP 800-56 Concat Kdf, as described in ANSI X9.63, 6.2.1 
    /// Shared Data, if used, is passed as the other-info field in the creation of the Kdf object
    pub type EccOnePassDhConcatKdfKem<C,H,L> = KemWithKdf<super::eckem::EcdhKemUncompressed<C>, CombinerNoKeys, ConcatKdf<H>, L>;
    /// Type representing the 1-Pass Diffie Helmann Scheme using the Kdf defined in X9.63 as described in ANSI X9.63, 6.2.1
    pub type EccOnePassDhX963KdfKem<C,H,L> = KemWithKdf<super::eckem::EcdhKemUncompressed<C>, CombinerNoKeys, X963Kdf<H>, L>;
    /// Type representing the 1-Pass Unified Model Scheme using the Concat KDF from X9.63, 6.5.1 
    pub type EccOnePassUnifiedConcatKdfKem<C,H,L> = KemAuthWithKdf<super::eckem::EcdhAuthKemCompressed<C>, CombinerNoKeys, ConcatKdf<H>,L>;
    /// Type representing the 1-Pass Unified Model Scheme using the X9.63 KDF from X9.63, 6.5.1 
    pub type EccOnePassUnifiedX963KdfKem<C,H,L> = KemAuthWithKdf<super::eckem::EcdhAuthKemCompressed<C>, CombinerNoKeys, X963Kdf<H>, L>;
    /// Type representing the 1-Pass MQV Scheme using the Concat KDF from X9.63, 6.9.1
    pub type EccOnePassMqvConcatKdfKem<C,H,L> = KemAuthWithKdf<super::eckem::EcMqvAuthKemUncompressed<C>, CombinerNoKeys, ConcatKdf<H>,L>;
    /// Type representing the 1-Pass MQV Scheme using the X9.63 KDF from X9.63, 6.9.1 
    pub type EccOnePassMqvX963KdfKem<C,H,L> = KemAuthWithKdf<super::eckem::EcMqvAuthKemUncompressed<C>, CombinerNoKeys, X963Kdf<H>,L>;
}

/// Key Encapsulation Mechanisms specified in ISO 18033-2
pub mod iso18033_2 {
    use crate::*;
    
    /// Implementation of the ECIES-KEM function as described in ISO 18033-2, 10.2.3. 
    /// This type uses compressed encoding, as defined in the SEC1 specification
    pub type EciesKemCompressed<C,K,L> = KemWithKdf<EcdhKemCompressed<C>, CombinerCiphertext, K, L>;
    
    /// Implementation of the ECIES-KEM function as described in ISO 18033-2, 10.2.3. using Kdf1
    pub type EciesKemCompressedKdf1<C,H,L> = KemWithKdf::<EcdhKemCompressed::<C>, CombinerCiphertext, Kdf1<H>, L>;
    
    /// Implementation of the ECIES-KEM function as described in ISO 18033-2, 10.2.3. using Kdf2
    pub type EciesKemCompressedKdf2<C,H,L> = KemWithKdf::<EcdhKemCompressed::<C>, CombinerCiphertext, Kdf2<H>, L>;

    /// Implementation of the ECIES-KEM function as described in ISO 18033-2, 10.2.3. 
    /// This type uses uncompressed encoding, as defined in the SEC1 specification
    pub type EciesKemUncompressed<C,K,L> = KemWithKdf::<EcdhKemUncompressed<C>, CombinerCiphertext, K, L>;
    
    /// Implementation of the ECIES-KEM function as described in ISO 18033-2, 10.2.3. using Kdf1 and raw encoding
    pub type EciesKemUncompressedKdf1<C,H,L> = KemWithKdf::<EcdhKemUncompressed::<C>, CombinerCiphertext, Kdf1<H>, L>;

    /// Implementation of the ECIES-KEM function as described in ISO 18033-2, 10.2.3. using Kdf2 and uncompressed encoding
    pub type EciesKemUncompressedKdf2<C,H,L> = KemWithKdf::<EcdhKemUncompressed::<C>, CombinerCiphertext, Kdf2<H>, L>;
    
    /// Implementation of the RSA-KEM.Encryption and Decryption function as described in ISO 18033-2, 11.5.3. & 4.
    /// LE is the modulus length, LK is the output key length and K is the key derivation function
    #[cfg(feature="rustcrypto-rsa")]
    pub type RsaKem<LE,LK,K> = RsaOrigKem<LE,LK,K>;
    
    /// Implementation of the RSA-KEM.Encryption and Decryption function as described in ISO 18033-2, 11.5.3. & 4 using Kdf1
    #[cfg(feature="rustcrypto-rsa")]
    pub type RsaKemKdf1<LE,LK,H> = RsaOrigKem<LE,LK,Kdf1<H>>;
    
    /// Implementation of the RSA-KEM.Encryption and Decryption function as described in ISO 18033-2, 11.5.3. & 4 using Kdf2
    #[cfg(feature="rustcrypto-rsa")]
    pub type RsaKemKdf2<LE,LK,H> = RsaOrigKem<LE,LK,Kdf2<H>>;

    /// Implementation of the REM1 Encode and Decode function as described in ISO 18033-2, 11.3.2.2
    /// LE is the modulus length, LK is the key length, D is the digest to use in the OAEP label hash function and F is digest to use in the OAEP mask generation
    #[cfg(feature="rustcrypto-rsa")]
    pub type Rem1Kem<LE,LK,D,F> = RsaOaepKem<LE,LK,D,F>;
}




/// Types and OIDs from RFC 5753: Use of Elliptic Curve Cryptography (ECC) Algorithms in Cryptographic Message Syntax (CMS)
pub mod rfc5753 {
    use crate::*;
    #[cfg(feature="rustcrypto-sha1")]
    use const_oid::db::rfc5753::{DH_SINGLE_PASS_COFACTOR_DH_SHA_1_KDF_SCHEME, DH_SINGLE_PASS_STD_DH_SHA_1_KDF_SCHEME, MQV_SINGLE_PASS_SHA_1_KDF_SCHEME};
    #[cfg(feature="rustcrypto-sha2")]
    use const_oid::db::rfc5753::{DH_SINGLE_PASS_COFACTOR_DH_SHA_224_KDF_SCHEME, DH_SINGLE_PASS_COFACTOR_DH_SHA_256_KDF_SCHEME, DH_SINGLE_PASS_COFACTOR_DH_SHA_384_KDF_SCHEME, DH_SINGLE_PASS_COFACTOR_DH_SHA_512_KDF_SCHEME, DH_SINGLE_PASS_STD_DH_SHA_224_KDF_SCHEME, DH_SINGLE_PASS_STD_DH_SHA_256_KDF_SCHEME, DH_SINGLE_PASS_STD_DH_SHA_384_KDF_SCHEME, DH_SINGLE_PASS_STD_DH_SHA_512_KDF_SCHEME, MQV_SINGLE_PASS_SHA_224_KDF_SCHEME, MQV_SINGLE_PASS_SHA_256_KDF_SCHEME, MQV_SINGLE_PASS_SHA_384_KDF_SCHEME, MQV_SINGLE_PASS_SHA_512_KDF_SCHEME};

    #[allow(unused)]
    use crate::eckem::EcMqvAuthKemCompressed;
    
    /// All these have OIDs from RFC5753
    #[cfg(feature="rustcrypto-sha1")]
    pub type DhSinglePassStdDhSha1KdfScheme<C,L>   = KemWithKdf::<EcdhKemUncompressed<C>, CombinerNoKeys, X963Kdf<Sha1>,L>;
    #[cfg(feature="rustcrypto-sha2")]
    pub type DhSinglePassStdDhSha224KdfScheme<C,L> = KemWithKdf::<EcdhKemUncompressed<C>, CombinerNoKeys, X963Kdf<Sha224>,L>;
    #[cfg(feature="rustcrypto-sha2")]
    pub type DhSinglePassStdDhSha256KdfScheme<C,L> = KemWithKdf::<EcdhKemUncompressed<C>, CombinerNoKeys, X963Kdf<Sha256>,L>;
    #[cfg(feature="rustcrypto-sha2")]
    pub type DhSinglePassStdDhSha384KdfScheme<C,L> = KemWithKdf::<EcdhKemUncompressed<C>, CombinerNoKeys, X963Kdf<Sha384>,L>;
    #[cfg(feature="rustcrypto-sha2")]
    pub type DhSinglePassStdDhSha512KdfScheme<C,L> = KemWithKdf::<EcdhKemUncompressed<C>, CombinerNoKeys, X963Kdf<Sha512>,L>;

    // The Cofactor types have a different OID, but the same generics, use compressed as a hack to seperate
    #[cfg(feature="rustcrypto-sha1")]
    pub type DhSinglePassCofactorDhSha1KdfScheme<C,L> = KemWithKdf::<EcdhKemCompressed<C>, CombinerNoKeys, X963Kdf<Sha1>,L>;
    #[cfg(feature="rustcrypto-sha2")]
    pub type DhSinglePassCofactorDhSha224KdfScheme<C,L> = KemWithKdf::<EcdhKemCompressed<C>, CombinerNoKeys, X963Kdf<Sha224>,L>;
    #[cfg(feature="rustcrypto-sha2")]
    pub type DhSinglePassCofactorDhSha256KdfScheme<C,L> = KemWithKdf::<EcdhKemCompressed<C>, CombinerNoKeys, X963Kdf<Sha256>,L>;
    #[cfg(feature="rustcrypto-sha2")]
    pub type DhSinglePassCofactorDhSha384KdfScheme<C,L> = KemWithKdf::<EcdhKemCompressed<C>, CombinerNoKeys, X963Kdf<Sha384>,L>;
    #[cfg(feature="rustcrypto-sha2")]
    pub type DhSinglePassCofactorDhSha512KdfScheme<C,L> = KemWithKdf::<EcdhKemCompressed<C>, CombinerNoKeys, X963Kdf<Sha512>,L>;

    #[cfg(feature="rustcrypto-sha1")]
    pub type MqvSinglePassSha1KdfScheme<C,L> = KemAuthWithKdf<EcMqvAuthKemCompressed<C>, CombinerNoKeys, kdfs::ansi_x9_63::X963Kdf<Sha1>, L>;
    #[cfg(feature="rustcrypto-sha2")]
    pub type MqvSinglePassSha224KdfScheme<C,L> = KemAuthWithKdf<EcMqvAuthKemCompressed<C>, CombinerNoKeys, kdfs::ansi_x9_63::X963Kdf<Sha224>, L>;
    #[cfg(feature="rustcrypto-sha2")]
    pub type MqvSinglePassSha256KdfScheme<C,L> = KemAuthWithKdf<EcMqvAuthKemCompressed<C>, CombinerNoKeys, kdfs::ansi_x9_63::X963Kdf<Sha256>, L>;
    #[cfg(feature="rustcrypto-sha2")]
    pub type MqvSinglePassSha384KdfScheme<C,L> = KemAuthWithKdf<EcMqvAuthKemCompressed<C>, CombinerNoKeys, kdfs::ansi_x9_63::X963Kdf<Sha384>, L>;
    #[cfg(feature="rustcrypto-sha2")]
    pub type MqvSinglePassSha512KdfScheme<C,L> = KemAuthWithKdf<EcMqvAuthKemCompressed<C>, CombinerNoKeys, kdfs::ansi_x9_63::X963Kdf<Sha512>, L>;

    
    #[cfg(feature="rustcrypto-sha1")]
    impl<C, L> AssociatedOid for DhSinglePassStdDhSha1KdfScheme<C,L>
    {   //OBJECT IDENTIFIER ::= {x9-63-scheme 2 }
        const OID: ObjectIdentifier = DH_SINGLE_PASS_STD_DH_SHA_1_KDF_SCHEME; //ObjectIdentifier::new_unwrap("1.3.133.16.840.63.0.2");
    }
    #[cfg(feature="rustcrypto-sha2")]
    impl<C, L> AssociatedOid for DhSinglePassStdDhSha224KdfScheme<C,L> 
    {   //OBJECT IDENTIFIER ::= {secg-scheme 11 0 }
        const OID: ObjectIdentifier = DH_SINGLE_PASS_STD_DH_SHA_224_KDF_SCHEME; //ObjectIdentifier::new_unwrap("1.3.132.1.11.0");
    }
    #[cfg(feature="rustcrypto-sha2")]
    impl<C, L> AssociatedOid for DhSinglePassStdDhSha256KdfScheme<C,L> 
    {   //OBJECT IDENTIFIER ::= {secg-scheme 11 1 }
        const OID: ObjectIdentifier = DH_SINGLE_PASS_STD_DH_SHA_256_KDF_SCHEME; //ObjectIdentifier::new_unwrap("1.3.132.1.11.1");
    }
    #[cfg(feature="rustcrypto-sha2")]
    impl<C, L> AssociatedOid for DhSinglePassStdDhSha384KdfScheme<C,L> 
    {   //OBJECT IDENTIFIER ::= {secg-scheme 11 2 }
        const OID: ObjectIdentifier = DH_SINGLE_PASS_STD_DH_SHA_384_KDF_SCHEME; //ObjectIdentifier::new_unwrap("1.3.132.1.11.2");
    }
    #[cfg(feature="rustcrypto-sha2")]
    impl<C, L> AssociatedOid for DhSinglePassStdDhSha512KdfScheme<C,L> 
    {   //OBJECT IDENTIFIER ::= {secg-scheme 11 3 }
        const OID: ObjectIdentifier = DH_SINGLE_PASS_STD_DH_SHA_512_KDF_SCHEME; //ObjectIdentifier::new_unwrap("1.3.132.1.11.3");
    }
    #[cfg(feature="rustcrypto-sha1")]
    impl<C, L> AssociatedOid for DhSinglePassCofactorDhSha1KdfScheme<C,L> 
    {   //OBJECT IDENTIFIER ::= {x9-63-scheme 3 }
        const OID: ObjectIdentifier = DH_SINGLE_PASS_COFACTOR_DH_SHA_1_KDF_SCHEME; //ObjectIdentifier::new_unwrap("1.3.133.16.840.63.0.3");
    }
    #[cfg(feature="rustcrypto-sha2")]
    impl<C, L> AssociatedOid for DhSinglePassCofactorDhSha224KdfScheme<C,L> 
    {   //OBJECT IDENTIFIER ::= {secg-scheme 14 0 }
        const OID: ObjectIdentifier = DH_SINGLE_PASS_COFACTOR_DH_SHA_224_KDF_SCHEME; //ObjectIdentifier::new_unwrap("1.3.132.1.14.0");
    }
    #[cfg(feature="rustcrypto-sha2")]
    impl<C, L> AssociatedOid for DhSinglePassCofactorDhSha256KdfScheme<C,L> 
    {   //OBJECT IDENTIFIER ::= {secg-scheme 14 1 }
        const OID: ObjectIdentifier = DH_SINGLE_PASS_COFACTOR_DH_SHA_256_KDF_SCHEME; //ObjectIdentifier::new_unwrap("1.3.132.1.14.1");
    }
    #[cfg(feature="rustcrypto-sha2")]
    impl<C, L> AssociatedOid for DhSinglePassCofactorDhSha384KdfScheme<C,L>
    {   //OBJECT IDENTIFIER ::= {secg-scheme 14 2 }
        const OID: ObjectIdentifier = DH_SINGLE_PASS_COFACTOR_DH_SHA_384_KDF_SCHEME; //ObjectIdentifier::new_unwrap("1.3.132.1.14.2");
    }
    #[cfg(feature="rustcrypto-sha2")]
    impl<C, L> AssociatedOid for DhSinglePassCofactorDhSha512KdfScheme<C,L>
    {   //OBJECT IDENTIFIER ::= {secg-scheme 14 3 }
        const OID: ObjectIdentifier = DH_SINGLE_PASS_COFACTOR_DH_SHA_512_KDF_SCHEME; //ObjectIdentifier::new_unwrap("1.3.132.1.14.3");
    }
    #[cfg(feature="rustcrypto-sha1")]
    impl<C, L> AssociatedOid for MqvSinglePassSha1KdfScheme<C,L> 
    {   //OBJECT IDENTIFIER ::= {x9-63-scheme 16 }
        const OID: ObjectIdentifier = MQV_SINGLE_PASS_SHA_1_KDF_SCHEME; //ObjectIdentifier::new_unwrap("1.3.133.16.840.63.0.16");
    }
    #[cfg(feature="rustcrypto-sha2")]
    impl<C, L> AssociatedOid for MqvSinglePassSha224KdfScheme<C,L>
    {   //OBJECT IDENTIFIER ::= {secg-scheme 15 0 }
        const OID: ObjectIdentifier = MQV_SINGLE_PASS_SHA_224_KDF_SCHEME; //ObjectIdentifier::new_unwrap("1.3.132.1.15.0");
    }
    #[cfg(feature="rustcrypto-sha2")]
    impl<C, L> AssociatedOid for MqvSinglePassSha256KdfScheme<C,L>
    {   //OBJECT IDENTIFIER ::= {secg-scheme 15 1 }
        const OID: ObjectIdentifier = MQV_SINGLE_PASS_SHA_256_KDF_SCHEME; //ObjectIdentifier::new_unwrap("1.3.132.1.15.1");
    }
    #[cfg(feature="rustcrypto-sha2")]
    impl<C, L> AssociatedOid for MqvSinglePassSha384KdfScheme<C,L>
    {   //OBJECT IDENTIFIER ::= {secg-scheme 15 2 }
        const OID: ObjectIdentifier = MQV_SINGLE_PASS_SHA_384_KDF_SCHEME; //ObjectIdentifier::new_unwrap("1.3.132.1.15.2");
    }
    #[cfg(feature="rustcrypto-sha2")]
    impl<C, L> AssociatedOid for MqvSinglePassSha512KdfScheme<C,L> 
    {   // OBJECT IDENTIFIER ::= {secg-scheme 15 3 }
        const OID: ObjectIdentifier = MQV_SINGLE_PASS_SHA_512_KDF_SCHEME; //ObjectIdentifier::new_unwrap("1.3.132.1.15.3");
    }
}


/// ML-KEM extensions to support deterministic encapsulation using the trait defined in this module
#[cfg(all(feature="rustcrypto-ml-kem", feature="rustcrypto-sha3"))]
pub mod fips204 {
    use crate::*;
    use kem::{Ciphertext, SharedKey};
    use kem::consts::{U16, U32};
    use ml_kem::{MlKem512, MlKem768, MlKem1024};

    impl EncapsulateDeterministic for ml_kem::EncapsulationKey<MlKem512>
    {
        type SeedSize = U32;

        fn encapsulate_deterministic(&self, seed: &[u8]) -> (Ciphertext<Self::Kem>, SharedKey<Self::Kem>) {
            let Ok(seed_as_array): Result<ml_kem::B32,_> = seed.try_into() else { panic!("DDDSFDS")};
            self.encapsulate_deterministic(&seed_as_array)
        }
    }
    impl EncapsulateDeterministic for ml_kem::EncapsulationKey<MlKem768>
    {
        type SeedSize = U32;

        fn encapsulate_deterministic(&self, seed: &[u8]) -> (Ciphertext<Self::Kem>, SharedKey<Self::Kem>) {
            let Ok(seed_as_array): Result<ml_kem::B32,_> = seed.try_into() else { panic!("DDDSFDS")};
            self.encapsulate_deterministic(&seed_as_array)
        }
    }
    impl EncapsulateDeterministic for ml_kem::EncapsulationKey<MlKem1024>
    {
        type SeedSize = U32;

        fn encapsulate_deterministic(&self, seed: &[u8]) -> (Ciphertext<Self::Kem>, SharedKey<Self::Kem>) {
            let Ok(seed_as_array): Result<ml_kem::B32,_> = seed.try_into() else { panic!("DDDSFDS")};
            self.encapsulate_deterministic(&seed_as_array)
        }
    }

    ///
    /// Type representing ML-KEM with a separate key derivation applied to the output
    /// 
    pub type MlKem768WithX963KdfU16 = KemWithKdf<MlKem768, CombinerNoKeys, kdfs::ansi_x9_63::X963Kdf<sha3::Sha3_256>, U16>;

}


/// Key Encasulation Mechanisms from RFC 9936 applicable to CMS, uses ML-KEM but adds an additional key derivation step
#[cfg(all(feature="rustcrypto-ml-kem", feature="rustcrypto-sha3", feature="rustcrypto-sha2", feature="rustcrypto-hmac"))]
pub mod rfc9936 {
    use crate::*;
    use ::ml_kem::{MlKem512, MlKem768, MlKem1024};
    
    // ML-KEM 512 with HKDF as defined in RFC9936
    pub type MlKem512Hkdf256<L> = KemWithKdf<MlKem512, CombinerNoKeys, kdfs::rfc5869_hkdf::Hkdf::<sha2::Sha256>, L>;
    // ML-KEM 768 with HKDF as defined in RFC9936
    pub type MlKem768Hkdf256<L> = KemWithKdf<MlKem768, CombinerNoKeys, kdfs::rfc5869_hkdf::Hkdf::<sha2::Sha256>, L>;
    // ML-KEM 1024 with HKDF as defined in RFC9936
    pub type MlKem1024Hkdf256<L> = KemWithKdf<MlKem1024, CombinerNoKeys, kdfs::rfc5869_hkdf::Hkdf::<sha2::Sha256>, L>;
}


/// Kem combining ML-KEM and a traditional KEM as per draft RFC
pub mod draft_irtf_cfrg_hybrid_kems {
    #[cfg(all(feature="rustcrypto-ml-kem", feature="rustcrypto-p256", feature="rustcrypto-sha3"))]
    use ::ml_kem::MlKem768;
    use crate::*;
    
    
  

    // #[cfg(all(feature="rustcrypto-ml-kem", feature="rustcrypto-p256", feature="rustcrypto-sha3"))]
    // pub type HybridKemQsfMlKem768P256 = super::hybrid::HybridKem::<
    //         MlKem768, //WrappedMlKem768,
    //         super::eckem::EcdhKem<p256::NistP256, super::eckem::EcCompressedEncoder<p256::NistP256>,crate::eckem::ReduceSeed>, 
    //         //super::eckem::EcdhKem<p256::NistP256, super::eckem::EcCompressedEncoder<p256::NistP256>,crate::eckem::SeedAsScalar>, 
    //         super::hybrid::QsfCombiner<Okdf3::<sha3::Sha3_256, kdfs::u0>, QsfLabelMlKem768P256>,
    //         crate::hybrid::ExpandSeed<super::U32, shake::Shake256>>;
 

    #[cfg(all(feature="rustcrypto-ml-kem", feature="rustcrypto-p256", feature="rustcrypto-sha3", feature="rustcrypto-hmac"))]
    pub type HybridCapsulatorKitchenSinkMlKem768P256 = super::hybrid::HybridKem::<
            MlKem768,
            super::eckem::EcdhKem<p256::NistP256, super::eckem::EcCompressedEncoder<p256::NistP256>>, 
            super::hybrid::KitchenSinkCombiner<kdfs::rfc5869_hkdf::Hkdf::<sha2::Sha256>,UniversalCombinerLabelMlKem768P256>,
        >;
            
    #[cfg(all(feature="rustcrypto-ml-kem", feature="rustcrypto-x25519", feature="rustcrypto-sha2", feature="rustcrypto-sha3", feature="rustcrypto-hmac"))]
    pub type HybridCapsulatorKitchenSinkMlKem768X25519 = super::hybrid::HybridKem::<
            MlKem768,
            crate::x25519kem::X25519Kem,
            super::hybrid::KitchenSinkCombiner<kdfs::rfc5869_hkdf::Hkdf::<sha2::Sha256>,UniversalCombinerLabelMlKem768X25519>,
        >;
   
}


/// Composite KEMs as describe in a draft RFC. 
/// 
/// Combines ML-KEM with an Elliptic Curve or RSA based KEM to create a new KEM
/// Currently based on versio 19 of the spec
#[cfg(all(feature="rustcrypto-ml-kem", feature="rustcrypto-sha3"))]
pub mod draft_ietf_lamps_pq_composite_kem
{
    use crate::*;
    use ::ml_kem::{MlKem768,MlKem1024};
    #[cfg(all(feature="rustcrypto-bp256"))]
    use bp256::BrainpoolP256r1;
    #[cfg(all(feature="rustcrypto-bp384"))]
    use bp384::BrainpoolP384r1;

    pub const ID_MLKEM768_RSA2048_SHA3_256:ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.6.55");
    pub const ID_MLKEM768_RSA3072_SHA3_256:ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.6.56");
    pub const ID_MLKEM768_RSA4096_SHA3_256:ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.6.57");
    pub const ID_MLKEM768_X25519_SHA3_256:ObjectIdentifier  = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.6.58");
    pub const ID_MLKEM768_ECDH_P256_SHA3_256:ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.6.59");
    pub const ID_MLKEM768_ECDH_P384_SHA3_256:ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.6.60");
    pub const ID_MLKEM768_ECDH_BRAINPOOL_P256R1_SHA3_256:ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.6.61");
    pub const ID_MLKEM1024_RSA3072_SHA3_256:ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.6.62");
    pub const ID_MLKEM1024_ECDH_P384_SHA3_256:ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.6.63");
    pub const ID_MLKEM1024_ECDH_BRAINPOOL_P384R1_SHA3_256:ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.6.64");
    pub const ID_MLKEM1024_X448_SHA3_256:ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.6.65");
    pub const ID_MLKEM1024_ECDH_P521_SHA3_256:ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.6.66");

    /// Adopted name of Xwing hybrid kem, which combines ML-KEM 768 with X25519 and an X-wing shaped ascii label
    #[cfg(all(feature="rustcrypto-x25519"))]
    pub type HybridKemMlKem768X25519Sha3_256 = XwingMlKem768X25519;
    /// Assigned OID for hybrid KEM which combines X25519 and ML-KEM 768 with a SHA3-256 based KDF    
    #[cfg(all(feature="rustcrypto-x25519"))]
    impl AssociatedOid for HybridKemMlKem768X25519Sha3_256 { const OID: ObjectIdentifier = ID_MLKEM768_X25519_SHA3_256; }
        

    /// Hybrid KEM which combines ML-KEM 768 with ECDH P-256 and SHA3-256 as the KDF
    #[cfg(all(feature="rustcrypto-p256"))]
    pub type HybridKemMlKem768P256Sha3_256 = crate::hybrid::HybridKem::<
        MlKem768,
        EcdhKemUncompressed<NistP256>,
        QsfCombiner<Okdf3::<Sha3_256, kdfs::u0>, LabelMlKem768P256>, 
    >;
    /// Assigned OID for hybrid KEM which combines ML-KEM 768 with ECDH P-256 and SHA3-256 as the KDF
    #[cfg(all(feature="rustcrypto-p256"))]
    impl AssociatedOid for HybridKemMlKem768P256Sha3_256 { const OID: ObjectIdentifier = ID_MLKEM768_ECDH_P256_SHA3_256; }

    
    /// Hybrid KEM which combines ML-KEM 768 with ECDH P-384 and SHA3-256 as the KDF
    #[cfg(all(feature="rustcrypto-p384"))]
    pub type HybridKemMlKem768P384Sha3_256 = HybridKem::<
        MlKem768,
        EcdhKemUncompressed<NistP384>,
        QsfCombiner<Okdf3::<Sha3_256, kdfs::u0>,LabelMlKey768EcdhP384>, 
    >;
    /// Assigned OID for hybrid KEM which combines ML-KEM 768 and ECDH P-384 and SHA3-256 as the KDF
    #[cfg(all(feature="rustcrypto-p384"))]
    impl AssociatedOid for HybridKemMlKem768P384Sha3_256 { const OID: ObjectIdentifier = ID_MLKEM768_ECDH_P384_SHA3_256; }


    /// Hybrid KEM which combines ML-KEM 1024 with ECDH P-384 and SHA-3-256 as the KDF
    #[cfg(all(feature="rustcrypto-p384"))]
    pub type HybridKemMlKem1024P384Sha3_256 = HybridKem::<
        MlKem1024,
        EcdhKemUncompressed<NistP384>,
        QsfCombiner<Okdf3::<Sha3_256, kdfs::u0>,LabelMlKem1024P384>, 
    >;
    /// Assigned OID for the Hybrid KEM with combines ML-KEM 1024 with ECDH-P384 and SHA-3-256 as the KDF
    #[cfg(all(feature="rustcrypto-p384"))]
    impl AssociatedOid for HybridKemMlKem1024P384Sha3_256 { const OID: ObjectIdentifier = ID_MLKEM1024_ECDH_P384_SHA3_256; }
    

    /// Hybrid KEM which combines ML-KEM 1024 with X448 and SHA-3-256 as the KDF
    #[cfg(all(feature="rustcrypto-x448"))]
    pub type HybridKemMlKem1024X448Sha3_256 = HybridKem::<
        MlKem1024,
        X448Kem,
        QsfCombiner<Okdf3::<Sha3_256, kdfs::u0>, LabelMlKem1024X448>, 
    >;
    /// Assigned OID for the Hybrid KEM which combines ML-KEM 1024 with X448 and SHA3-256 as the KDF
    #[cfg(all(feature="rustcrypto-x448"))]
    impl AssociatedOid for HybridKemMlKem1024X448Sha3_256 { const OID: ObjectIdentifier = ID_MLKEM1024_X448_SHA3_256; }


    /// Hybrid KEM which combines ML-KEM 1024 with ECDH P-521 and SHA3-256 as the KDF
    #[cfg(all(feature="rustcrypto-p521"))]
    pub type HybridKemMlKem1024P521Sha3_256 = HybridKem::<
        MlKem1024,
        EcdhKemUncompressed<NistP521>,
        QsfCombiner<Okdf3::<Sha3_256, kdfs::u0>, LabelMlKem1024EcdhP521>, 
    >;
    /// Assigned OID for the Hybrid KEM which combines ML-KEM 1024 with ECDH P-521 and SHA3-256 as the KDF
    #[cfg(all(feature="rustcrypto-p521"))]
    impl AssociatedOid for HybridKemMlKem1024P521Sha3_256 { const OID: ObjectIdentifier = ID_MLKEM1024_ECDH_P521_SHA3_256; }


    /// Hybrid KEM which combines ML-KEM 768 with RSA 2048 and SHA3-256 as the KDF
    #[cfg(all(feature="rustcrypto-rsa", feature="rustcrypto-sha2"))]
    pub type HybridKemMlkem768Rsa2048HmacSha256 = HybridKem::<
        MlKem768,
        RsaOaepKem<U256,U32,Sha256,Sha256>,
        QsfCombiner<Okdf3<Sha3_256, kdfs::u0>, LabelMlKey768Rsa2048HmacSha256>, 
    >;
    /// Assigned OID for the Hybrid KEM which combines ML-KEM 768 with RSA 2048 and SHA3-256 as the KDF
    #[cfg(all(feature="rustcrypto-rsa", feature="rustcrypto-sha2"))]
    impl AssociatedOid for HybridKemMlkem768Rsa2048HmacSha256 { const OID: ObjectIdentifier = ID_MLKEM768_RSA2048_SHA3_256; }


    /// Hybrid KEM which combines ML-KEM 768 with RSA 3072 and SHA3-256 as the KDF
    #[cfg(all(feature="rustcrypto-rsa", feature="rustcrypto-sha2"))]
    pub type HybridKemMlkem768Rsa3072HmacSha256 = HybridKem::<
        MlKem768,
        RsaOaepKem<U384,U32,Sha256,Sha256>,
        QsfCombiner<Okdf3::<Sha3_256, kdfs::u0>, LabelMlKey768Rsa3072HmacSha256>, 
    >;
    /// Assigned OID for the Hybrid KEM which combines ML-KEM 768 with RSA 3072 and SHA3-256 as the KDF
    #[cfg(all(feature="rustcrypto-rsa", feature="rustcrypto-sha2"))]
    impl AssociatedOid for HybridKemMlkem768Rsa3072HmacSha256 { const OID: ObjectIdentifier = ID_MLKEM768_RSA3072_SHA3_256; }


    /// Hybrid KEM which combines ML-KEM 1024 with RSA 3072 and SHA3-256 as the KDF
    #[cfg(all(feature="rustcrypto-rsa", feature="rustcrypto-sha2"))]
    pub type HybridKemMlkem1024Rsa3072HmacSha512 = HybridKem::<
        MlKem1024,
        RsaOaepKem<U384,U32,Sha256,Sha256>,
        QsfCombiner<Okdf3<Sha3_256, kdfs::u0>, LabelMlKey1024Rsa3072HmacSha512>, 
    >;
    /// Assigned OID for the Hybrid KEM which combines ML-KEM 1024 with RSA 3072 and SHA3-256 as the KDF
    #[cfg(all(feature="rustcrypto-rsa", feature="rustcrypto-sha2"))]
    impl AssociatedOid for HybridKemMlkem1024Rsa3072HmacSha512 { const OID: ObjectIdentifier = ID_MLKEM1024_RSA3072_SHA3_256; }


    /// Hybrid KEM which combines ML-KEM 768 with RSA 4096 and SHA3-256 as the KDF
    #[cfg(all(feature="rustcrypto-rsa", feature="rustcrypto-sha2"))]
    pub type HybridKemMlkem768Rsa4096HmacSha256 = HybridKem::<
        MlKem768,
        RsaOaepKem<U512,U32,Sha256,Sha256>,
        QsfCombiner<Okdf3<Sha3_256, kdfs::u0>, LabelMlKey768Rsa4096HmacSha256>,
    >;
    /// Assigned OID for the Hybrid KEM which combines ML-KEM 768 with RSA 4096 and SHA3-256 as the KDF
    #[cfg(all(feature="rustcrypto-rsa", feature="rustcrypto-sha2"))]
    impl AssociatedOid for HybridKemMlkem768Rsa4096HmacSha256 { const OID: ObjectIdentifier = ID_MLKEM768_RSA4096_SHA3_256;  }
    

    // pub type U2346 = UInt<UInt<UInt<UInt<UInt<UInt<UInt<UInt<UInt<UInt<UInt<UInt<UTerm, B1>, B0>, B0>, B1>, B0>, B0>, B1>, B0>, B1>, B1>, B0>, B0>;
    /// Hybrid KEM which combines ML-KEM 768 with BrainpoolP256r1 and SHA3-256 as the KDF
    #[cfg(all(feature="rustcrypto-bp256", feature="rustcrypto-sha2"))]
    pub type HybridKemMlkem768BP256r1Sha3_256 = HybridKem::<
        MlKem768,
        EcdhKemUncompressed<BrainpoolP256r1>,
        QsfCombiner<Okdf3<Sha3_256, kdfs::u0>, LabelMlkem768BP256r1Sha3_256>, 
    >;
    /// Assigned OID for the Hybrid KEM which combines ML-KEM 768 with BrainpoolP256r1 and SHA3-256 as the KDF
    #[cfg(all(feature="rustcrypto-bp256", feature="rustcrypto-sha2"))]
    impl AssociatedOid for HybridKemMlkem768BP256r1Sha3_256 { const OID: ObjectIdentifier = ID_MLKEM768_ECDH_BRAINPOOL_P256R1_SHA3_256; }
    
    // pub type U2346 = UInt<UInt<UInt<UInt<UInt<UInt<UInt<UInt<UInt<UInt<UInt<UInt<UTerm, B1>, B0>, B0>, B1>, B0>, B0>, B1>, B0>, B1>, B1>, B0>, B0>;
    /// Hybrid KEM which combines ML-KEM 1024 with BrainpoolP384r1 and SHA3-256 as the KDF
    #[cfg(all(feature="rustcrypto-bp384", feature="rustcrypto-sha2"))]
    pub type HybridKemMlkem1024BP384r1Sha3_256 = HybridKem::<
        MlKem1024,
        EcdhKemUncompressed<BrainpoolP384r1>,
        QsfCombiner<Okdf3<Sha3_256, kdfs::u0>, LabelMlkem1024BP384r1Sha3_256>, 
    >;
    /// Assigned OID for the Hybrid KEM which combines ML-KEM 1024 with BrainpoolP384r1 and SHA3-256 as the KDF
    #[cfg(all(feature="rustcrypto-bp384", feature="rustcrypto-sha2"))]
    impl AssociatedOid for HybridKemMlkem1024BP384r1Sha3_256 { const OID: ObjectIdentifier = ID_MLKEM1024_ECDH_BRAINPOOL_P384R1_SHA3_256; }

}


/// Xwing Kem defines in a draft RFC. Uses MlKem768, X25519 and a kdf based on Sha3 with a specific label
#[cfg(all(feature="rustcrypto-ml-kem", feature="rustcrypto-x25519", feature="rustcrypto-sha3"))]
pub mod xwing {
    use crate::*;
    use ::ml_kem::MlKem768;

    pub type XwingMlKem768X25519 = HybridKem::<
            MlKem768,
            X25519Kem,
            QsfCombiner<Okdf3<Sha3_256, kdfs::u0>, LabelXWing>, 
    >;
}


#[cfg(all(feature="rustcrypto-ml-kem"))]
pub mod draft_irtf_cfrg_concrete_hybrid_kems
{
    use crate::*;
    use ::ml_kem::{MlKem768,MlKem1024};

    #[cfg(all(feature="rustcrypto-p256"))]
    pub type ConcreteMlKem768P256 = HybridKem::<
            MlKem768,
            EcdhKemUncompressed<NistP256>,  
            QsfCombiner<Okdf3<Sha3_256, kdfs::u0>, LabelMlKem768P256>, 
    >;

    #[cfg(all(feature="rustcrypto-p384"))]
    pub type ConcreteMlKem1024P384 = HybridKem::<
            MlKem1024,
            EcdhKemUncompressed<NistP384>,
            QsfCombiner<Okdf3<Sha3_256, kdfs::u0>, LabelMlKem1024P384>, 
    >;
}




#[cfg(all(feature="rustcrypto-sha2", any(feature="rustcrypto-p256", feature="rustcrypto-p384")))]
pub mod jwe {
    use crate::*;
    use crate::eckem::{EcdhKemRaw2};
    use crate::kem_with_kdf::{JwaKdf};

    pub type JweKemEcSha256<C,N> = KemWithKdf::<EcdhKemRaw2::<C>, CombinerNoKeys, JwaKdf<ConcatKdf<Sha256>,true>,N>;

    #[cfg(all(feature="rustcrypto-p256"))]
    pub type JweKemP256Sha256<N> = JweKemEcSha256<NistP256,N>;
    #[cfg(all(feature="rustcrypto-p384"))]
    pub type JweKemP384Sha256<N> = JweKemEcSha256<NistP384,N>;
    #[cfg(all(feature="rustcrypto-p521"))]
    pub type JweKemP521Sha256<N> = JweKemEcSha256<NistP521,N>;
    
}


#[cfg(all(feature="rustcrypto-x448", any(feature="rustcrypto-ml-kem", feature="rustcrypto-sha3")))]
pub mod pgp {
    use kdfs::Label;
    use crate::x448kem::X448Kem;
    use crate::x25519kem::X25519Kem;
    use ml_kem::{MlKem768, MlKem1024};

    pub struct OpenPgpLabelMlKem1025X448;
    impl Label for OpenPgpLabelMlKem1025X448 {
        const LABEL: &'static[u8] = &hex_literal::hex!("24 4F 70 65 6E 50 47 50 43 6F 6D 70 6F 73 69 74 65 4B 44 46 76 31 15");
    }

    pub type HybridCapsulatorOpenPgpMlKem1024X448 = crate::hybrid::HybridKem::<
            X448Kem,
            MlKem1024,
            crate::hybrid::QsfCombiner2<kdfs::iso11770_6::Okdf1<sha3::Sha3_256>,OpenPgpLabelMlKem1025X448>,
        >;

    pub struct OpenPgpLabelMlKem768X25519;
    impl Label for OpenPgpLabelMlKem768X25519 {
        const LABEL: &'static[u8] = &hex_literal::hex!("23 4F 70 65 6E 50 47 50 43 6F 6D 70 6F 73 69 74 65 4B 44 46 76 31 15");
    }

   pub type HybridCapsulatorOpenPgpMlKem768X25519 = crate::hybrid::HybridKem::<
            X25519Kem,
            MlKem768,
            crate::hybrid::QsfCombiner2<kdfs::iso11770_6::Okdf1<sha3::Sha3_256>,OpenPgpLabelMlKem768X25519>,
         >;

}