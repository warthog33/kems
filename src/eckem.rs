//!
//! Key exchange mechanism using EC cryptography as per ISO 18033-3. 
//! Traits from the elliptic_curve crate are used to make the mechanism generic over a curve.
//! 
//! This module implements functionality required by both a sender and a recipient.
//! The sender obtains the public key of the recipient and uses it to encrypt a randomly generated secret.
//! The encrypted value is sent to the recipient, which uses its private key to decrypt the message and recover the secret.
//! Both sender and recipient pass the secret through a key derivation function to calculate the shared secret usable as a cryptographic key
//!  
//! # Example 
//! ```
//! use elliptic_curve::consts::*;
//! use elliptic_curve::sec1::UncompressedPointSize;
//! use p256::{SecretKey, NistP256, elliptic_curve::Generate};
//! use sha2::Sha256;
//! use kems::KemExtensions;
//! use kems::eckem::{EcdhKemCompressed, EcdhDecapsulatorCompressed, EcdhDecapsulator, EcCompressedEncoder};
//! use kdfs::ansi_x9_63::X963KdfSha256;
//! use kems::kem_with_kdf::{KemWithKdf, CombinerNoKeys};
//! use kems::{FromKey};
//! use kem::{Encapsulate, TryDecapsulate};
//! 
//! 
//! let recipient_secret_key = SecretKey::generate();
//! let recipient_public_key = recipient_secret_key.public_key();
//! 
//! type EcdhX963Sha256<C> = KemWithKdf<EcdhKemCompressed<C>, CombinerNoKeys, X963KdfSha256, U32>;
//! let encapsulator = EcdhX963Sha256::from_public_key(recipient_public_key);
//! let (ct, k_send) = encapsulator.encapsulate();
//! 
//! let decapsulator = EcdhX963Sha256::from_private_key(recipient_secret_key);
//! let k_recv = decapsulator.try_decapsulate(&ct).unwrap();
//! assert! ( k_send == k_recv);
//! ```
  
use std::marker::PhantomData;
use std::fmt::Debug;
use std::ops::{Add, Sub};
use cipher::{KeySizeUser};
use cipher::common::KeyExport;
#[allow(unused)]
use cipher::consts::{U1,U2};
#[allow(unused)]
use cipher::typenum::{Diff, Quot, Sum};
use cipher::typenum::Unsigned;
use const_oid::AssociatedOid;
use elliptic_curve::{AffinePoint, Curve, CurveArithmetic, FieldBytesSize, Generate, NonZeroScalar, PrimeCurve, ProjectivePoint, PublicKey, Scalar, ScalarValue, SecretKey};
use elliptic_curve::bigint::Encoding;
use elliptic_curve::sec1::{CompressedPointSize, FromSec1Point, ModulusSize, ToSec1Point, UncompressedPointSize, ValidatePublicKey};
#[allow(unused)]
use elliptic_curve::point::{AffineCoordinates, PointCompression,DecompactPoint};
#[allow(unused)]
use elliptic_curve::bigint::ArrayEncoding;

use kdfs::hybrid_array::{Array, ArraySize};
use kem::{Ciphertext, Decapsulate, DecapsulationKey, Decapsulator, Encapsulate, EncapsulationKey, FromSeed, InvalidKey, Kem, Key, Seed, SharedKey, TryDecapsulate, TryKeyInit};

use crate::{EncapsulateDeterministic};
use crate::{FromKey, FromKeys};

pub type UntaggedPointSize<C> = <FieldBytesSize<C> as ModulusSize>::UntaggedPointSize;


/// Used for encoding a public key or shared secret to a byte array
pub trait EcEncode<C: CurveArithmetic> {
    type Error: Debug;
    type PublicKeyLen: ArraySize;
    type SharedSecretLen: ArraySize;
    
    fn encode_public_key(source: &PublicKey<C>) -> Array<u8, Self::PublicKeyLen>;
    fn decode_public_key(encoded_bytes: &[u8]) -> Result<PublicKey<C>, Self::Error>;
    fn encode_shared_secret ( point: &AffinePoint<C> ) -> Array<u8, Self::SharedSecretLen>;
}


///
/// Encodes by outputing the X coordinate as a big endian byte array
/// 
pub struct EcCompactEncoder<C: Curve>(PhantomData<C>);

impl<C> EcEncode<C> for EcCompactEncoder<C>
where   C: CurveArithmetic + PointCompression, 
        C::AffinePoint: FromSec1Point<C> + ToSec1Point<C> + DecompactPoint<C>,
        C::FieldBytesSize: ModulusSize,
{
    type Error = elliptic_curve::Error;
    type PublicKeyLen = C::FieldBytesSize;
    type SharedSecretLen = C::FieldBytesSize;

    fn encode_public_key(public_key: &PublicKey<C>) -> Array<u8, Self::PublicKeyLen> {
        public_key.as_affine().x()
    }
        
    fn decode_public_key(encoded_bytes: &[u8]) -> Result<PublicKey<C>, Self::Error> {
        let point = AffinePoint::<C>::decompact(encoded_bytes.try_into()?).into_option().ok_or(elliptic_curve::Error)?;
        PublicKey::<C>::from_affine(point)
    }
    
    fn encode_shared_secret ( point: &AffinePoint<C> ) -> Array<u8, Self::SharedSecretLen> {
        point.x()
    }
}


///
/// Encodes or Decodes according to SEC1 compressed format, ie a single byte is_odd followed by the x-coordinate
///
pub struct EcCompressedEncoder<C> ( PhantomData<C>);


impl<C> EcEncode<C> for EcCompressedEncoder<C>
where C: CurveArithmetic,
    C::FieldBytesSize: ModulusSize,
    C::AffinePoint: FromSec1Point<C> + ToSec1Point<C>
{
    type Error = elliptic_curve::Error;
    type PublicKeyLen = CompressedPointSize<C>;
    type SharedSecretLen = FieldBytesSize<C>;
        
    fn encode_public_key(public_key: &PublicKey<C>) -> Array<u8, Self::PublicKeyLen> {
        public_key.to_compressed_point()
    }
    fn decode_public_key(encoded_bytes: &[u8]) -> Result<PublicKey<C>, Self::Error> {
        PublicKey::<C>::from_sec1_bytes(encoded_bytes)
    }
    fn encode_shared_secret ( point: &AffinePoint<C> ) -> Array<u8, Self::SharedSecretLen> {
        point.x()
    }
}


///
/// Encodes or Decodes according to SEC1 uncompressed format, ie a single byte identifier followed by the x-coordinate and y-coordinates
///
pub struct EcUncompressedEncoder<C> ( PhantomData<C>);

impl<C> EcEncode<C> for EcUncompressedEncoder<C>
where   C: CurveArithmetic+PointCompression, 
        C::FieldBytesSize: ModulusSize,
        C::AffinePoint: FromSec1Point<C> + ToSec1Point<C>,
{
    type Error = elliptic_curve::Error;
    type PublicKeyLen = UncompressedPointSize<C>;
    type SharedSecretLen = FieldBytesSize<C>;
    
    fn encode_public_key(public_key: &PublicKey<C>) -> Array<u8, Self::PublicKeyLen> {
        public_key.to_uncompressed_point()
    }
    fn decode_public_key(encoded_bytes: &[u8]) -> Result<PublicKey<C>, Self::Error> {
        PublicKey::<C>::from_sec1_bytes(encoded_bytes)
    }
    fn encode_shared_secret ( point: &AffinePoint<C> ) -> Array<u8, Self::SharedSecretLen> {
        point.x()
    }
}




///
/// Format consisting of x-coordinate || y-coordinate as byte arrays for both the public key and the shared secret. 
/// 
pub struct EcRawEncoder<C> ( PhantomData<C>);

impl<C> EcEncode<C> for EcRawEncoder<C>
    where   C: CurveArithmetic, 
        <C::FieldBytesSize as Add>::Output: ArraySize,
        <C::FieldBytesSize as Add>::Output: Sub<C::FieldBytesSize, Output=C::FieldBytesSize>,
{
    type Error = elliptic_curve::Error;
    type PublicKeyLen = Sum<C::FieldBytesSize, C::FieldBytesSize>;
    type SharedSecretLen = Sum<C::FieldBytesSize, C::FieldBytesSize>;

    // returns the untagged byte array, x || y
    fn encode_public_key(public_key: &PublicKey<C>) -> Array<u8, Self::PublicKeyLen> {
        public_key.as_affine().x().concat(public_key.as_affine().y())   
    }
    fn decode_public_key(encoded_bytes: &[u8]) -> Result<PublicKey<C>, Self::Error> {
        let xy = Array::<u8, Sum<C::FieldBytesSize, C::FieldBytesSize>>::slice_as_array(encoded_bytes).ok_or(elliptic_curve::Error)?;
        let (x,y) = Array::split_ref::<C::FieldBytesSize>(xy);
        
        // let x = Array::<u8, C::FieldBytesSize>::slice_as_array(&encoded_bytes[..C::FieldBytesSize::USIZE]).ok_or(elliptic_curve::Error)?;
        // let y = Array::<u8, C::FieldBytesSize>::slice_as_array(&encoded_bytes[C::FieldBytesSize::USIZE..]).ok_or(elliptic_curve::Error)?;

        let p = AffinePoint::<C>::from_coordinates(x, y).into_option().ok_or(elliptic_curve::Error)?;
        PublicKey::<C>::from_affine(p)

    }
    fn encode_shared_secret ( point: &AffinePoint<C> ) -> Array<u8, Self::SharedSecretLen> {
        point.x().concat(point.y())
    }
}

///
/// Format consisting of x-coordinate || y-coordinate as byte arrays for the public key, the shared secret is simply the x coordinate as a byte array. 
/// Reuses most of the functions from EcRawEncoder, but overrides the encode_shared_secret function to only return the x coordinate
///
pub struct EcRaw2Encoder<C> ( PhantomData<C>);

impl<C> EcEncode<C> for EcRaw2Encoder<C>
where   C: CurveArithmetic, 
        <C::FieldBytesSize as Add>::Output: ArraySize,
        <C::FieldBytesSize as Add>::Output: Sub<C::FieldBytesSize, Output=C::FieldBytesSize>,
{
    type Error = <EcRawEncoder<C> as EcEncode<C>>::Error;
    type PublicKeyLen = <EcRawEncoder<C> as EcEncode<C>>::PublicKeyLen;
    type SharedSecretLen = FieldBytesSize<C>;
    
    fn encode_public_key(public_key: &PublicKey<C>) -> Array<u8, Self::PublicKeyLen> {
        EcRawEncoder::encode_public_key(public_key)
    }
    fn decode_public_key(encoded_bytes: &[u8]) -> Result<PublicKey<C>, Self::Error> {
        EcRawEncoder::decode_public_key(encoded_bytes)
    }
    fn encode_shared_secret ( point: &AffinePoint<C> ) -> Array<u8, Self::SharedSecretLen> {
        point.x()
    }
}



///
/// Factory struct to create encapsulators and decapsulators using one-way Diffie-Hellman
/// with Elliptic Curves implementing the RustCryoto CurveArithmetic traits
/// 
pub struct EcdhKem<C,DE> (PhantomData<C>, PhantomData<DE>);

/// Unauthenticated KEM using elliptic curve Diffie Hellman and x-only encoding of the ciphertext, public keys and shared secret
pub type EcdhKemCompact<C> = EcdhKem<C, EcCompactEncoder<C>>;

/// Unauthenticated KEM using elliptic curve Diffie Hellman and SEC1 compressed encoding of the ciphertext and public keys, x-only shared secret
pub type EcdhKemCompressed<C> = EcdhKem<C, EcCompressedEncoder<C>>;

/// Unauthenticated KEM using elliptic curve Diffie Hellman and SEC1 uncompressed encoding of the ciphertext and public keys, x-only shared secret
pub type EcdhKemUncompressed<C> = EcdhKem<C, EcUncompressedEncoder<C>>;

/// Unauthenticated KEM using ellipitic curve Diffie Helman with raw x,y public key format of the ciphertext, public keys and shared secret
pub type EcdhKemRaw<C> = EcdhKem<C, EcRawEncoder<C>>;

/// Unauthenticated KEM using ellipitic curve Diffie Helman with raw x,y public key format of the ciphertext and public key, and x-only encoding of the shared secret
pub type EcdhKemRaw2<C> = EcdhKem<C, EcRaw2Encoder<C>>;


impl<C, E> Kem for EcdhKem<C,E>
where C: Sync + Send,
    C: CurveArithmetic+PointCompression,
    C::FieldBytesSize: ModulusSize,
    C::AffinePoint: FromSec1Point<C> + ToSec1Point<C>,
    E: EcEncode<C> + Sync + Send + 'static,
    <E as EcEncode<C>>::Error: std::error::Error
{
    type EncapsulationKey = EcdhEncapsulator<C,E>;
    type DecapsulationKey = EcdhDecapsulator<C,E>;
    type CiphertextSize = E::PublicKeyLen;
    type SharedKeySize = E::SharedSecretLen;

    fn generate_keypair_from_rng<R: rand::prelude::CryptoRng>(rng: &mut R ) -> (DecapsulationKey<Self>, EncapsulationKey<Self>)
    {
        let private = SecretKey::try_generate_from_rng(rng).unwrap();
        let public = private.public_key();
        (EcdhDecapsulator::from_key(private), EcdhEncapsulator::from_key(public))
    }
}



impl<C,E> FromSeed for EcdhKem<C,E>
where C: Sync + Send,
    C: CurveArithmetic+PointCompression,
    C::FieldBytesSize: ModulusSize,
    C::AffinePoint: FromSec1Point<C> + ToSec1Point<C>,
    E: EcEncode<C> + Sync + Send + 'static,
    <E as EcEncode<C>>::Error: std::error::Error
{
    type SeedSize = C::FieldBytesSize;

    fn from_seed(seed: &Seed<Self>) -> (DecapsulationKey<Self>, EncapsulationKey<Self>) 
    {    
        let Ok(priv_key) = SecretKey::from_bytes(seed) else { panic!("DFSDFSD") };
        let decapsulator = Self::DecapsulationKey::from_key(priv_key);
        let encapsulator = decapsulator.encapsulation_key().clone();
        (decapsulator, encapsulator)
    }
}



impl<C, DE> Ord for EcdhKem<C,DE>
{
    fn cmp(&self, _other: &Self) -> std::cmp::Ordering {
        todo!()
    }
}
impl<C, DE> PartialOrd for EcdhKem<C,DE>
{
    fn partial_cmp(&self, _other: &Self) -> Option<std::cmp::Ordering> {
        todo!()
    }
}
impl<C, DE> PartialEq for EcdhKem<C,DE>
{
    fn eq(&self, _other: &Self) -> bool {
        todo!()
    }
}
impl<C, DE> Eq for EcdhKem<C,DE>
{
}
impl<C, DE> Default for EcdhKem<C,DE>
{
    fn default() -> Self {
        Self(Default::default(), Default::default())
    }
}
impl<C, DE> Debug for EcdhKem<C,DE>
{
    fn fmt(&self, _f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        todo!()
    }
}
impl<C, DE> Copy for EcdhKem<C,DE>
{
}
impl<C, DE> Clone for EcdhKem<C,DE>
{
    fn clone(&self) -> Self {
        *self
    }
}


















///
/// Allows for the encapsulation of a key using Elliptic-Curve Diffie-Hellman
/// 

pub struct EcdhEncapsulator <C: CurveArithmetic+PointCompression, E>
{
    pub recipient_public: PublicKey<C>,
    phantom: PhantomData<E>,
}

/// Encapsulation key used for elliptic curve Diffie Hellman based KEM with SEC1 compressed encoding of the ciphertext
pub type EcdhEncapsulatorCompressed<C> = EcdhEncapsulator<C, EcCompressedEncoder<C>>;
/// Encapsulation key used for elliptic curve Diffie Hellman based KEM with SEC1 uncompressed encoding of the ciphertext
pub type EcdhEncapsulatorUncompressed<C> = EcdhEncapsulator<C, EcUncompressedEncoder<C>>;
/// Encapsulation key used for elliptic curve Diffie Hellman based KEM with raw encoding of the ciphertext and keys.
/// Points are encoded as x followed by y, where each field is a sequence of big endian bytes 
pub type EcdhEncapsulatorRaw<C> = EcdhEncapsulator<C, EcRawEncoder<C>>;



impl<C: CurveArithmetic+PointCompression, E> KeySizeUser for EcdhEncapsulator<C,E>
where E: EcEncode<C>,
{
    type KeySize = E::PublicKeyLen;
}

impl<C: CurveArithmetic+PointCompression, E> KeyExport for EcdhEncapsulator<C,E>
where E: EcEncode<C>,
{
    fn to_bytes(&self) -> cipher::Key<Self> {
        E::encode_public_key(&self.recipient_public).into()
    }
}

impl<C, E> TryKeyInit for EcdhEncapsulator<C,E>
where C: CurveArithmetic + PointCompression,
    E: EcEncode<C>,
{
    fn new(key: &cipher::Key<Self>) -> Result<Self, InvalidKey> {
        E::decode_public_key(key).map_err(|_|InvalidKey).map(|k|Self::from_key(k))
    }
}

impl<C,E> FromKey for EcdhEncapsulator<C,E> 
where   C: CurveArithmetic + PointCompression, 
{
    type Key = PublicKey<C>;
    fn from_key(value: PublicKey<C>) -> Self {
        EcdhEncapsulator {  recipient_public: value, phantom: PhantomData }
    }
}


impl<C: CurveArithmetic+PointCompression, E> EcdhEncapsulator <C, E>
where   C: CurveArithmetic + PointCompression,
        C::AffinePoint: ToSec1Point<C> + FromSec1Point<C>,
        FieldBytesSize<C>: ModulusSize,
        E: EcEncode<C>,
{
    fn encapsulate_deterministic_key(&self, ephemeral_prv: &SecretKey<C> ) -> Result<(Array<u8,E::PublicKeyLen>, Array<u8,E::SharedSecretLen>), ()> {
        
        let ephemeral_pub = ephemeral_prv.public_key();
        
        // perform the diffie-hellman action by multiplying the public and private keys
        let raw_shared_secret = self.recipient_public.to_projective() * *ephemeral_prv.to_nonzero_scalar();
        let raw_shared_secret = elliptic_curve::group::Curve::to_affine(&raw_shared_secret);
        
        let raw_encoded_shared_secret = E::encode_shared_secret(&raw_shared_secret);
        
        Ok((E::encode_public_key(&ephemeral_pub), raw_encoded_shared_secret))
    }
}






///
/// Factory struct to create encapsulators and decapsulators using one-way Diffie-Hellman with sender
/// authentication suitable for use 
/// with Elliptic Curves implementing the RustCryoto CurveArithmetic traits
/// 
//pub struct EcdhAuthCapsulator<C,K,L,DE> (PhantomData<C>, PhantomData<K>, PhantomData<L>, PhantomData<DE>);
pub struct EcdhAuthCapsulator<C,E> (PhantomData<C>, PhantomData<E>);

impl<C, DE> EcdhAuthCapsulator<C,DE>
where DE: EcEncode<C>, // + DecodeKey<SecretKey<C>> + EncodeKey<SecretKey<C>>, 
    C: CurveArithmetic+PointCompression, 
    C::FieldBytesSize: ModulusSize,
    C::AffinePoint: ToSec1Point<C> + FromSec1Point<C>, 
{    
    pub fn from_bytes_decap ( priv_bytes: &Array::<u8, C::FieldBytesSize>, pub_bytes: &Array<u8, <DE as EcEncode<C>>::PublicKeyLen> ) -> EcdhAuthDecapsulator<C, DE>
    {
        let priv_key = SecretKey::<C>::from_bytes(priv_bytes).unwrap(); //<DE as DecodeKey<SecretKey<C>>>::decode(priv_bytes).unwrap();
        let pub_key = <DE as EcEncode<C>>::decode_public_key(pub_bytes).unwrap();
        EcdhAuthDecapsulator::from_keys(pub_key, priv_key)
    }
    pub fn decap_from_keys ( recipient_private:SecretKey<C>, sender_public:PublicKey<C> ) -> EcdhAuthDecapsulator<C, DE>
    {
        EcdhAuthDecapsulator::from_keys(sender_public, recipient_private)
    }
    pub fn encap_from_keys ( recipient_public:PublicKey<C>, sender_private:SecretKey<C> ) -> EcdhAuthEncapsulator<C, DE>
    {
        EcdhAuthEncapsulator::from_keys(recipient_public, sender_private)
    }
}



/// Authenticated KEM based upon Elliptic Curve Diffie Hellman with SEC1 compressed encoding of the ciphertext
pub type EcdhAuthKemCompressed<C> = EcdhAuthCapsulator<C, EcCompressedEncoder<C>>;
/// Authenticated KEM based upon Elliptic Curve Diffie Hellman with SEC1 uncompressed encoding of the ciphertext
pub type EcdhAuthKemUncompressed<C> = EcdhAuthCapsulator<C, EcUncompressedEncoder<C>>;
/// Authenticated KEM based upon Elliptic Curve Diffie Hellman with raw x||y encoding of the ciphertext
pub type EcdhAuthKemRaw<C> = EcdhAuthCapsulator<C, EcRawEncoder<C>>;



///
/// Struct for creating authenticating encapsulated keys using diffie-hellman
/// 
//pub struct EcdhAuthEncapsulator <C: CurveArithmetic+PointCompression, K: EcdhAuthCombiner, L: ArrayLength<u8>, DE>
pub struct EcdhAuthEncapsulator <C: CurveArithmetic+PointCompression, DE>
{
    recipient_public: PublicKey<C>,
    sender_private: Option<SecretKey<C>>,
    sender_public: PublicKey<C>,
    phantom: PhantomData<DE>,
}

/// Specialization of EcdhAuthEncapsulator using a compressed form of public key and without public keys being used in the key derivation function
//pub type EcdhAuthEncapsulatorCompressed<C> = EcdhAuthEncapsulator<C,EcCompressedEncoder<C>>;
/// Specialization of EcdhAuthEncapsulator using an uncompressed form of public key and without public keys being used in the key derivation function
pub type EcdhAuthEncapsulatorUncompressed<C> = EcdhAuthEncapsulator<C,EcUncompressedEncoder<C>>;


impl<C,DE> FromKeys for EcdhAuthEncapsulator<C,DE> 
where   C: CurveArithmetic+PointCompression,
{
    type PrivateKey = SecretKey<C>;
    type PublicKey = PublicKey<C>;

    fn from_keys ( pub_key: Self::PublicKey, priv_key: Self::PrivateKey ) -> Self {
        let sender_public = PublicKey::from(&priv_key);
        Self { sender_private: Some(priv_key), sender_public, recipient_public: pub_key, phantom: PhantomData}
    }
}


impl<C,E> EcdhAuthEncapsulator<C,E>
where   E: EcEncode<C>,
        C: CurveArithmetic + PointCompression,
        <C::FieldBytesSize as Add>::Output: ArraySize,
{
    fn encapsulate_from_key(&self, ephemeral_prv: &SecretKey<C>) -> Result<(Array<u8,E::PublicKeyLen>, Array<u8,Sum<C::FieldBytesSize, C::FieldBytesSize>>), ()>
    {
        let encoded_ephemeral_public_key = E::encode_public_key(&ephemeral_prv.public_key());
        let public_point = self.recipient_public.to_projective();

        let raw_shared_secret_1 = public_point * *ephemeral_prv.to_nonzero_scalar();
        let Some(sender_private) = &self.sender_private else { return Err(()); };
        let raw_shared_secret_2 = public_point * *sender_private.to_nonzero_scalar();
        
        let raw_shared_secret_1 = elliptic_curve::group::Curve::to_affine(&raw_shared_secret_1);
        let raw_shared_secret_2 = elliptic_curve::group::Curve::to_affine(&raw_shared_secret_2);
        
        let raw_shared_secret_1: Array<u8, C::FieldBytesSize> = raw_shared_secret_1.x();
        let raw_shared_secret_2: Array<u8, C::FieldBytesSize> = raw_shared_secret_2.x();
        let raw_shared_secret = raw_shared_secret_1.concat(raw_shared_secret_2);

        Ok((encoded_ephemeral_public_key, raw_shared_secret))
    }
}






///
/// This struct implements the key encapsulation mechanism for ECIES as specified in ISO 18033-2.
/// It implements the Encapsulator trait defined in KEM from RustCrypto and uses the traits from the 
/// Elliptic Curve crate
/// C is a curve to use
/// L indicates the target output size, acceptable values are `CompressedPointSize<C>` or `UncompressedPointSize<C>`
///

///
/// Encapsulated Key for ECIES. Contains a fixed size byte array which represents an encoded public key
///  C is a curve type, for example NistP256 or NistP521
///  L is the length of the shared secret output from the encap function which may be different size to the raw secret due to it being passed through a KDF, 
///  E is the length of the encoded output, either `CompressedPointSize<C>` or `UncompressedPointSize<C>`
/// 
///
/// Struct enabling receipt of a EciesEncapKey and recovery of the shared secret
/// 
pub struct EcdhDecapsulator <C: CurveArithmetic+PointCompression, E>
{
    pub recipient_private: SecretKey<C>,
    encapsulation_key: EcdhEncapsulator<C,E>,
    phantom: PhantomData<E>,
}


impl<C: CurveArithmetic + PointCompression, DE> FromKey for EcdhDecapsulator<C,DE> {
    type Key = SecretKey<C>;
    /// Create a Decapsulator from a private key and kdf, which must match the recipient public key and kdf used 
    /// during the encapsulation phase
    fn from_key (recipient_private: SecretKey<C>) -> Self {
        let encapsulation_key = EcdhEncapsulator{ recipient_public: recipient_private.public_key(), phantom: PhantomData };
        Self { recipient_private, encapsulation_key, phantom: PhantomData }
    }
}



/// Encapsulation key used for elliptic curve Diffie Hellman based KEM with SEC1 compressed encoding of the ciphertext
pub type EcdhDecapsulatorCompressed<C> = EcdhDecapsulator<C, EcCompressedEncoder<C>>;
/// Encapsulation key used for elliptic curve Diffie Hellman based KEM with SEC1 uncompressed encoding of the ciphertext
pub type EcdhDecapsulatorUncompressed<C> = EcdhDecapsulator<C, EcUncompressedEncoder<C>>;
/// Encapsulation key used for elliptic curve Diffie Hellman based KEM with raw encoding of the ciphertext and keys.
/// Raw encoding means the private key is a sequence of big endian bytes representing the scalar
/// Points are encoded as x followed by y, where each field is a sequence of big endian bytes 
pub type EcdhDecapsulatorRaw<C> = EcdhDecapsulator<C,EcRawEncoder<C>>;


impl<C, E> KeySizeUser for EcdhDecapsulator<C,E>
where C: CurveArithmetic+PointCompression,
{
    type KeySize = C::FieldBytesSize;
}

impl<C, ED> KeyExport for EcdhDecapsulator<C,ED>
where C: CurveArithmetic+PointCompression,
{
    fn to_bytes(&self) -> cipher::Key<Self> {
        self.recipient_private.to_bytes()
    }
}
impl<C, E> TryKeyInit for EcdhDecapsulator<C,E>
where C: CurveArithmetic+PointCompression + AssociatedOid + Curve + ValidatePublicKey,
    FieldBytesSize<C>: ModulusSize,
{
    fn new(key: &cipher::Key<Self>) -> Result<EcdhDecapsulator<C, E>, InvalidKey> {
        let secret_key = SecretKey::<C>::from_bytes(key).map_err(|_|InvalidKey)?;
        Ok(Self::from_key(secret_key))
    }
    fn new_from_slice(key: &[u8]) -> Result<Self, InvalidKey> {
        let recipient_private = if key.len() == C::FieldBytesSize::USIZE
        {
            SecretKey::<C>::from_slice(key).map_err(|_| InvalidKey)?
        }
        else {
            SecretKey::<C>::from_sec1_der(key).map_err(|_| InvalidKey)?
        };
        let encapsulation_key = EcdhEncapsulator::<C,E>{recipient_public: recipient_private.public_key(), phantom: PhantomData};
        Ok(Self{recipient_private, encapsulation_key,phantom: PhantomData})
    }
}



///
/// Struct enabling receipt of a EciesEncapKey and recovery of the shared secret
/// 
pub struct EcdhAuthDecapsulator <C: CurveArithmetic+PointCompression, E>
{
    recipient_private: SecretKey<C>,
    encapsulation_key: EcdhAuthEncapsulator<C,E>,
}

impl<C: CurveArithmetic + PointCompression, E> FromKeys for EcdhAuthDecapsulator<C, E>
{
    type PrivateKey = SecretKey<C>;
    type PublicKey = PublicKey<C>;

    fn from_keys ( pub_key: Self::PublicKey, priv_key: Self::PrivateKey ) -> Self {
        let recipient_public = PublicKey::from(&priv_key);
        Self { recipient_private: priv_key, encapsulation_key: EcdhAuthEncapsulator { recipient_public, sender_private: None, sender_public: pub_key, phantom: PhantomData }}
    }
}


///
/// Factory struct to create encapsulators and decapsulators using MQV
/// with Elliptic Curves implementing the RustCryoto CurveArithmetic traits
/// 
//pub struct EcMqvAuthCapsulator<C,K,L,ED> (PhantomData<C>, PhantomData<K>, PhantomData<L>, PhantomData<ED>);
pub struct EcMqvAuthKem<C,ED> (PhantomData<C>, PhantomData<ED>);

/// Authenticed KEM using Elliptic Curve MQV and compressed SEC1 encoding for the ciphertext 
pub type EcMqvAuthKemCompressed<C> = EcMqvAuthKem<C, EcCompressedEncoder<C>>;
/// Authenticed KEM using Elliptic Curve MQV and uncompressed SEC1 encoding for the ciphertext
pub type EcMqvAuthKemUncompressed<C> = EcMqvAuthKem<C, EcUncompressedEncoder<C>>;


///
/// Struct for creating authenticated encapsulated keys using the MQV primitive
/// 
pub struct EcMqvAuthEncapsulator <C: CurveArithmetic+PointCompression, E>
{
    sender_private: Option<SecretKey<C>>,
    sender_public: PublicKey<C>,
    recipient_public: PublicKey<C>,
    phantom: PhantomData<E>
}

/// Encapsulator using the MQV primitive and a compressed public key in the output
pub type EcMqvAuthEncapsulatorCompressed<C> = EcMqvAuthEncapsulator<C, EcCompressedEncoder<C>>;
/// Encapsulator using the MQV primitive and an uncompressed public key in the output
pub type EcMqvAuthEncapsulatorUncompressed<C> = EcMqvAuthEncapsulator<C, EcUncompressedEncoder<C>>;


//impl<C,K,L,E,DE> FromKeys for EcMqvAuthEncapsulator<C,K,L,E,DE>
impl<C,E> FromKeys for EcMqvAuthEncapsulator<C,E>
where   C: CurveArithmetic+PointCompression, 
{
    type PrivateKey = SecretKey<C>;
    type PublicKey = PublicKey<C>;

    fn from_keys ( recipient_public: Self::PublicKey, sender_private: Self::PrivateKey ) -> Self {
        let sender_public = PublicKey::from(&sender_private);
        Self { sender_private: Some(sender_private), recipient_public, sender_public, phantom: PhantomData }
    }
}




///
/// Struct enabling receipt of a EciesEncapKey and recovery of the shared secret
/// 
pub struct EcMqvAuthDecapsulator <C: CurveArithmetic+PointCompression, E>
{
    recipient_private: SecretKey<C>,
    encapsulation_key: EcMqvAuthEncapsulator<C, E>,
}

impl<C: CurveArithmetic + PointCompression, E> FromKeys for EcMqvAuthDecapsulator<C,E> 
{
    type PrivateKey = SecretKey<C>;
    type PublicKey = PublicKey<C>;
    
    fn from_keys ( sender_public: Self::PublicKey, recipient_private: Self::PrivateKey ) -> Self {
        let recipient_public = PublicKey::from(&recipient_private);
        Self { recipient_private, encapsulation_key: EcMqvAuthEncapsulator { sender_private: None, recipient_public, sender_public, phantom: PhantomData } }
    }
}



///
/// Function used as part of MQV
/// 
pub fn avf2<C:CurveArithmetic> ( pk: &PublicKey<C> ) -> NonZeroScalar::<C>
{
    let mut x = pk.as_affine().x();

    let l = x.len();
    let pos: usize;

    let n = C::ORDER;
    //let na = n.encode_field_bytes();
    let na = n.to_be_bytes();
    let na = na.as_ref();

    if na[0] == 1 || (na[0] == 0 && na[6] == 1) { // Only bottom bit set...
        pos = l/2;
        x[pos] &= 0x1F;
        x[pos] |= 0x20;
    }
    else
    {
        pos = l/2-1;
        x[pos] = 0x1; // Assume top bit of modulus is set
        
    }
    
    //let f = 384/2;
    for i in 0..pos {
       x[i] = 0;
    }
   
    return NonZeroScalar::<C>::from_repr(x).unwrap();
    
    //return rc;
}


///
/// MQV primitive for use with MQV Key Agreement
/// 
pub fn  mqv2<C> ( sk1: &SecretKey<C>, sk2: &SecretKey<C>, pk1: &PublicKey<C>, pk2: &PublicKey<C> ) -> ProjectivePoint<C>
    where C: Curve + CurveArithmetic + PrimeCurve,
{
    let temp_1 = avf2(&sk2.public_key()) * sk1.to_nonzero_scalar(); // ScalarPrimitive doesn't have a multiply function, convert to NonZeroScalar instead
    //let temp_1a: elliptic_curve::ScalarPrimitive<C> = Into::<elliptic_curve::ScalarPrimitive<C>>::into(temp_1);
    let temp_1a : ScalarValue<C> = Into::<elliptic_curve::ScalarValue<C>>::into(temp_1);
    //let temp_2: elliptic_curve::ScalarPrimitive<C> = sk2.to_nonzero_scalar().into();
    let temp_2: ScalarValue<C> = sk2.to_nonzero_scalar().into();
    //let implicit_sig_a = temp_1a + temp_2;  // NonZeroScalar doesn't have an add function, convern to ScalarPrimitive instead
    let implicit_sig_a = temp_1a + temp_2; //sk2.to_nonzero_scalar();

    let implicit_sig_ab: Scalar<C> = implicit_sig_a.into();

    //let temp_6: elliptic_curve::ScalarPrimitive<C> = avf2(&pk2).into();
    let temp_6: ScalarValue<C> = avf2(&pk2).into();
    let temp_66: Scalar<C> = temp_6.into();

    let p = ( pk2.to_projective() + pk1.to_projective() * temp_66) * implicit_sig_ab;
    p
}






impl<C, E> Eq for EcdhEncapsulator<C,E>
where C: CurveArithmetic+PointCompression,
{

}
impl<C, E> PartialEq for EcdhEncapsulator<C,E>
where C: CurveArithmetic+PointCompression,
{
    fn eq(&self, _other: &Self) -> bool {
        todo!()
    }
    
}
impl<C, E> Debug for EcdhEncapsulator<C,E>
where C: CurveArithmetic+PointCompression,
{
    fn fmt(&self, _f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        todo!()
    }
}
impl<C, E> Clone for EcdhEncapsulator<C,E>
where C: CurveArithmetic+PointCompression,
{
    fn clone(&self) -> Self {
        Self { recipient_public: self.recipient_public.clone(), phantom: PhantomData }
    }
}
impl<C, E> Encapsulate for EcdhEncapsulator<C,E>
where C: Sync + Send,
    C: CurveArithmetic+PointCompression,
    C::FieldBytesSize: ModulusSize,
    C::AffinePoint: FromSec1Point<C> + ToSec1Point<C>,
    E: EcEncode<C> + Sync + Send + 'static,
    <E as EcEncode<C>>::Error: std::error::Error
{
    type Kem = EcdhKem<C,E>;

    fn encapsulate_with_rng<R>(&self, rng: &mut R) -> (Ciphertext<Self::Kem>, SharedKey<Self::Kem>)
    where
        R: rand::CryptoRng + ?Sized {
        
        let ephemeral_prv = SecretKey::generate_from_rng(rng);
        self.encapsulate_deterministic_key(&ephemeral_prv).unwrap()
    }
}



impl<C, E> Generate for EcdhDecapsulator<C,E>
where C: Sync + Send,
    C: CurveArithmetic+PointCompression,
{
    fn try_generate_from_rng<R: rand::TryCryptoRng + ?Sized>(_rng: &mut R) -> Result<Self, R::Error> {
        todo!()
    }
}

// impl<C, E> Decapsulate for EcdhDecapsulator<C,E>
// where C: Sync + Send,
//     C: CurveArithmetic+PointCompression,
//     C::FieldBytesSize: ModulusSize,
//     C::AffinePoint: FromSec1Point<C> + ToSec1Point<C>,
//     E: Sync + Send + 'static + EcEncode<C>, 
// {
//     fn decapsulate(&self, ct: &Ciphertext<Self::Kem>) -> SharedKey<Self::Kem> {
//         let encapped_key : PublicKey<C> = E::decode_public_key(&ct).unwrap();

//         let public_point = ProjectivePoint::<C>::from(*encapped_key.as_affine());
        
//         let raw_shared_secret = public_point * *self.recipient_private.to_nonzero_scalar();
//         let raw_shared_secret = elliptic_curve::group::Curve::to_affine(&raw_shared_secret);

//         E::encode_shared_secret(&raw_shared_secret)
//     }
// }

impl<C, E> TryDecapsulate for EcdhDecapsulator<C,E>
where C: Sync + Send,
    C: CurveArithmetic+PointCompression,
    C::FieldBytesSize: ModulusSize,
    C::AffinePoint: FromSec1Point<C> + ToSec1Point<C>,
    E: Sync + Send + 'static + EcEncode<C>, 
    <E as EcEncode<C>>::Error: std::error::Error,
{
    type Error = <E as EcEncode<C>>::Error;
    fn try_decapsulate(&self, ct: &Ciphertext<Self::Kem>) -> Result<SharedKey<Self::Kem>, Self::Error> {
        let encapped_key : PublicKey<C> = E::decode_public_key(&ct)?;

        let public_point = ProjectivePoint::<C>::from(*encapped_key.as_affine());
        
        let raw_shared_secret = public_point * *self.recipient_private.to_nonzero_scalar();
        let raw_shared_secret = elliptic_curve::group::Curve::to_affine(&raw_shared_secret);

        Ok(E::encode_shared_secret(&raw_shared_secret))
    }
}


impl<C, E> Decapsulator for EcdhDecapsulator<C,E>
where C: Sync + Send,
    C: CurveArithmetic+PointCompression,
    C::FieldBytesSize: ModulusSize,
    C::AffinePoint: FromSec1Point<C> + ToSec1Point<C>,
    
    E: EcEncode<C> + Sync + Send + 'static,
    <E as EcEncode<C>>::Error: std::error::Error
{
    type Kem = EcdhKem<C,E>;

    fn encapsulation_key(&self) -> &EncapsulationKey<Self::Kem> {
        &self.encapsulation_key
    }
}



impl<C: CurveArithmetic+PointCompression, E> EncapsulateDeterministic for EcdhEncapsulator <C, E>
where   C: CurveArithmetic + PointCompression,
        C::AffinePoint: ToSec1Point<C> + FromSec1Point<C>,
        FieldBytesSize<C>: ModulusSize,
        E: EcEncode<C> + 'static + Send + Sync,
        <E as EcEncode<C>>::Error: std::error::Error
{
    //type Kem = EcdhKem<C,E>;
    type SeedSize = FieldBytesSize<C>;
    
    fn encapsulate_deterministic(&self, seed: &[u8]) -> (Ciphertext<Self::Kem>, SharedKey<Self::Kem>) {
        let Ok(ephemeral_prv) = SecretKey::from_bytes(seed.try_into().unwrap()) else { panic!("DFSDFSD") };
        let (ek, shared_key) = self.encapsulate_deterministic_key(&ephemeral_prv).unwrap();
        (ek, shared_key)

    }
}
















impl<C, E> Kem for EcdhAuthCapsulator<C,E>
where 
    E: EcEncode<C> + Sync + Send +'static, 
    C: CurveArithmetic+PointCompression,
    C::FieldBytesSize: ModulusSize,
    C::AffinePoint: ToSec1Point<C> + FromSec1Point<C>, 
    <C::FieldBytesSize as Add>::Output: ArraySize,

    E::PublicKeyLen: Add<E::PublicKeyLen>,
    Sum<E::PublicKeyLen, E::PublicKeyLen>: ArraySize,
{
    type EncapsulationKey = EcdhAuthEncapsulator<C,E>;
    type DecapsulationKey = EcdhAuthDecapsulator<C,E>;
    type CiphertextSize = E::PublicKeyLen;
    type SharedKeySize = Sum<C::FieldBytesSize, C::FieldBytesSize>;

}

impl<C,E> Decapsulator for EcdhAuthDecapsulator<C,E>
where E: EcEncode<C> + Sync + Send +'static, //+ DecodeKey<SecretKey<C>> + EncodeKey<SecretKey<C>> ,  
    <E as EcEncode<C>>::PublicKeyLen: ArraySize,  
    C: CurveArithmetic+PointCompression,
    C::FieldBytesSize: ModulusSize,
    C::AffinePoint: ToSec1Point<C> + FromSec1Point<C>, 
    <C::FieldBytesSize as Add>::Output: ArraySize,    
    E::PublicKeyLen: Add<E::PublicKeyLen>,
    Sum<E::PublicKeyLen, E::PublicKeyLen>: ArraySize,
{
    type Kem = EcdhAuthCapsulator<C,E>;

    fn encapsulation_key(&self) -> &EncapsulationKey<Self::Kem> {
        &self.encapsulation_key
    }
}
impl<C,E> Decapsulate for EcdhAuthDecapsulator<C,E>
where E: EcEncode<C> + Sync + Send +'static, //+ DecodeKey<SecretKey<C>> + EncodeKey<SecretKey<C>> ,  
    C: CurveArithmetic+PointCompression,
    C::FieldBytesSize: ModulusSize,
    C::AffinePoint: ToSec1Point<C> + FromSec1Point<C>, 
    <C::FieldBytesSize as Add>::Output: ArraySize,
    E::PublicKeyLen: Add<E::PublicKeyLen>,
    Sum<E::PublicKeyLen, E::PublicKeyLen>: ArraySize,
{
    fn decapsulate(&self, ct: &Ciphertext<Self::Kem>) -> SharedKey<Self::Kem> {
        let encapped_key = PublicKey::<C>::from_sec1_bytes(&ct).unwrap();
        let public_point_1 = ProjectivePoint::<C>::from(*encapped_key.as_affine());
        let public_point_2 = ProjectivePoint::<C>::from(*self.encapsulation_key.sender_public.as_affine());

        let raw_shared_secret_1 = public_point_1 * *self.recipient_private.to_nonzero_scalar();
        let raw_shared_secret_2 = public_point_2 * *self.recipient_private.to_nonzero_scalar();
        
        let raw_shared_secret_1 = elliptic_curve::group::Curve::to_affine(&raw_shared_secret_1).x();
        let raw_shared_secret_2 = elliptic_curve::group::Curve::to_affine(&raw_shared_secret_2).x();

        raw_shared_secret_1.concat::<C::FieldBytesSize>(raw_shared_secret_2)
    }
}
impl<C,DE> Generate for EcdhAuthDecapsulator<C,DE>
where C: CurveArithmetic+PointCompression,
{
    fn try_generate_from_rng<R: rand::TryCryptoRng + ?Sized>(_srng: &mut R) -> Result<Self, R::Error> {
        panic! ( "EcdhAuthDecapsulator cannot be generated from a single call to an RNG, instead call the from_keys member");
    }
}

impl<C,E> EncapsulateDeterministic for EcdhAuthEncapsulator<C,E>
where E: EcEncode<C> + Sync + Send +'static, //+ DecodeKey<SecretKey<C>> + EncodeKey<SecretKey<C>> ,  
    C: CurveArithmetic+PointCompression,
    C::FieldBytesSize: ModulusSize,
    C::AffinePoint: ToSec1Point<C> + FromSec1Point<C>, 
    <C::FieldBytesSize as Add>::Output: ArraySize,
    E::PublicKeyLen: Add<E::PublicKeyLen>,
    Sum<E::PublicKeyLen, E::PublicKeyLen>: ArraySize,
{
    //type Kem = EcdhAuthCapsulator<C,E>;
    type SeedSize = C::FieldBytesSize;

    fn encapsulate_deterministic(&self, seed: &[u8]) -> (Ciphertext<Self::Kem>, SharedKey<Self::Kem>) {
        let Ok(ephemeral_prv) = SecretKey::from_bytes(seed.try_into().unwrap()) else { panic!("DFSDFSD") };
        let (ct, ss) = self.encapsulate_from_key ( &ephemeral_prv ).unwrap();
        (ct.as_slice().try_into().unwrap(), ss)

    }
}

impl<C,E> Encapsulate for EcdhAuthEncapsulator<C,E>
where E: EcEncode<C> + Sync + Send +'static,
    C: CurveArithmetic+PointCompression,
    C::FieldBytesSize: ModulusSize,
    C::AffinePoint: ToSec1Point<C> + FromSec1Point<C>, 
    <C::FieldBytesSize as Add>::Output: ArraySize,
    E::PublicKeyLen: Add<E::PublicKeyLen>,
    Sum<E::PublicKeyLen, E::PublicKeyLen>: ArraySize,
{
    type Kem = EcdhAuthCapsulator<C,E>;

    fn encapsulate_with_rng<R>(&self, _rng: &mut R) -> (Ciphertext<Self::Kem>, SharedKey<Self::Kem>)
    where R: rand::prelude::CryptoRng + ?Sized 
    {
        let ephemeral_prv = SecretKey::generate_from_rng(_rng);
        self.encapsulate_from_key(&ephemeral_prv).unwrap()
    }
}
impl<C,E> KeyExport for EcdhAuthEncapsulator<C,E>
where C: CurveArithmetic+PointCompression,
    E: EcEncode<C>,
    E::PublicKeyLen: Add<E::PublicKeyLen>,
    Sum<E::PublicKeyLen, E::PublicKeyLen>: ArraySize,

{
    fn to_bytes(&self) -> Key<Self> {
        let first = E::encode_public_key(&self.recipient_public);
        let second = E::encode_public_key(&self.sender_public);
        first.concat(second)
    }
}
impl<C,E> TryKeyInit for EcdhAuthEncapsulator<C,E>
where C: CurveArithmetic+PointCompression,
    E: EcEncode<C>,
    E::PublicKeyLen: Add<E::PublicKeyLen>,
    Sum<E::PublicKeyLen, E::PublicKeyLen>: ArraySize,
{
    fn new(_key: &Key<Self>) -> Result<Self, InvalidKey> {
        panic! ( "TryKeyInit cannot be used to create an EcdhAuthEncapsulator, use from_keys instead")
    }
}
impl<C,E> KeySizeUser for EcdhAuthEncapsulator<C,E>
where C: CurveArithmetic+PointCompression,
    E: EcEncode<C>,
    E::PublicKeyLen: Add<E::PublicKeyLen>,
    Sum<E::PublicKeyLen, E::PublicKeyLen>: ArraySize,
{
    type KeySize = Sum<E::PublicKeyLen, E::PublicKeyLen>;
    
}
impl<C,DE> Clone for EcdhAuthEncapsulator<C,DE>
where C: CurveArithmetic+PointCompression,
{
    fn clone(&self) -> Self {
        Self { recipient_public: self.recipient_public.clone(), sender_private: self.sender_private.clone(), sender_public: self.sender_public.clone(), phantom: self.phantom.clone() }
    }
}
impl<C,E> Debug for EcdhAuthEncapsulator<C,E>
where C: CurveArithmetic+PointCompression
{
    fn fmt(&self, _sf: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        todo!()
    }
}

impl<C,E> Eq for EcdhAuthEncapsulator<C,E>
where C: CurveArithmetic+PointCompression,
{}
impl<C,DE> PartialEq for EcdhAuthEncapsulator<C,DE>
where C: CurveArithmetic+PointCompression,
{
    fn eq(&self, _other: &Self) -> bool {
        todo!()
    }
}



impl<C,E> Copy for EcdhAuthCapsulator<C,E>
{}
impl<C,DE> Clone for EcdhAuthCapsulator<C,DE>
{
    fn clone(&self) -> Self {
        todo!()
    }
}
impl<C,DE> Ord for EcdhAuthCapsulator<C,DE>
{
    fn cmp(&self, _other: &Self) -> std::cmp::Ordering {
        todo!()
    }
}
impl<C,DE> Eq for EcdhAuthCapsulator<C,DE>
{
    
}
impl<C,DE> Debug for EcdhAuthCapsulator<C,DE>
{
    fn fmt(&self, _f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        todo!()
    }
}
impl<C,DE> Default for EcdhAuthCapsulator<C,DE>
{
    fn default() -> Self {
        Self(Default::default(), Default::default())
    }
}
impl<C,DE> PartialOrd for EcdhAuthCapsulator<C,DE>
{
    fn partial_cmp(&self, _other: &Self) -> Option<std::cmp::Ordering> {
        todo!()
    }
}
impl<C,DE> PartialEq for EcdhAuthCapsulator<C,DE>
{
    fn eq(&self, _other: &Self) -> bool {
        todo!()
    }
}














impl<C, DE> Kem for EcMqvAuthKem<C,DE>
where 
    DE: EcEncode<C>  + Send + Sync + 'static,
    C: CurveArithmetic+PointCompression + PrimeCurve,
    C::FieldBytesSize: ModulusSize,
    C::AffinePoint: ToSec1Point<C> + FromSec1Point<C>,    
{
    type EncapsulationKey = EcMqvAuthEncapsulator<C,DE>;
    type DecapsulationKey = EcMqvAuthDecapsulator<C,DE>;
    type CiphertextSize = <DE as EcEncode<C>>::PublicKeyLen;
    type SharedKeySize = C::FieldBytesSize;
}


impl<C, DE> Encapsulate for EcMqvAuthEncapsulator<C,DE> 
where C: CurveArithmetic + PointCompression,
    DE: EcEncode<C> + Send + Sync + 'static,
    C: CurveArithmetic+PointCompression + PrimeCurve,
    C::FieldBytesSize: ModulusSize,
    C::AffinePoint: ToSec1Point<C> + FromSec1Point<C>,   
{
    type Kem = EcMqvAuthKem<C,DE>;

    fn encapsulate_with_rng<R>(&self, _rng: &mut R) -> (Ciphertext<Self::Kem>, SharedKey<Self::Kem>)
    where
        R: rand::prelude::CryptoRng + ?Sized {
        todo!()
    }
}
impl<C, DE> Decapsulator for EcMqvAuthDecapsulator<C,DE> 
where  DE: EcEncode<C> + Send + Sync + 'static,
    C: CurveArithmetic+PointCompression + PrimeCurve,
    C::FieldBytesSize: ModulusSize,
    C::AffinePoint: ToSec1Point<C> + FromSec1Point<C>, 
{
    type Kem = EcMqvAuthKem<C,DE>;

    fn encapsulation_key(&self) -> &EncapsulationKey<Self::Kem> {
        &self.encapsulation_key
    }
}
impl<C, DE> Decapsulate for EcMqvAuthDecapsulator<C,DE> 
where DE: EcEncode<C>  + Send + Sync + 'static,
    C: CurveArithmetic+PointCompression + PrimeCurve,
    C::FieldBytesSize: ModulusSize,
    C::AffinePoint: ToSec1Point<C> + FromSec1Point<C>, 
{
    fn decapsulate(&self, ct: &Ciphertext<Self::Kem>) -> SharedKey<Self::Kem> {
        let encapped_key = PublicKey::<C>::from_sec1_bytes(&ct.as_slice()).unwrap();
        
        let raw_shared_secret = elliptic_curve::group::Curve::to_affine(&mqv2 ( &self.recipient_private, &self.recipient_private, &self.encapsulation_key.sender_public, &encapped_key ));
        raw_shared_secret.x()
    }
}
impl<C, DE> Generate for EcMqvAuthDecapsulator<C,DE> 
where C: CurveArithmetic + PointCompression,
{
    fn try_generate_from_rng<R: rand::TryCryptoRng + ?Sized>(_rng: &mut R) -> Result<Self, R::Error> {
        todo!()
    }
}

impl<C, E> KeySizeUser for EcMqvAuthEncapsulator<C,E> 
where C: CurveArithmetic + PointCompression,
    E: EcEncode<C>
{
    type KeySize = E::PublicKeyLen;
}
impl<C, E> KeyExport for EcMqvAuthEncapsulator<C,E> 
where C: CurveArithmetic + PointCompression,
    E: EcEncode<C>,
{
    fn to_bytes(&self) -> Key<Self> {
        todo!()
    }
}
impl<C, E> TryKeyInit for EcMqvAuthEncapsulator<C,E> 
where C: CurveArithmetic + PointCompression,
    E: EcEncode<C>,
{
    fn new(_key: &Key<Self>) -> Result<Self, InvalidKey> {
        todo!()
    }
}

impl<C, E> Clone for EcMqvAuthEncapsulator<C,E> 
where C: CurveArithmetic + PointCompression
{
    fn clone(&self) -> Self {
        Self { sender_private: self.sender_private.clone(), recipient_public: self.recipient_public.clone(), sender_public: self.sender_public.clone(), phantom: self.phantom.clone() }
    }
}
impl<C, DE> Debug for EcMqvAuthEncapsulator<C,DE> 
where C: CurveArithmetic + PointCompression
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EcMqvAuthEncapsulator").field("sender_private", &self.sender_private).field("recipient_public", &self.recipient_public).field("phantom", &self.phantom).finish()
    }
}
impl<C, E> EncapsulateDeterministic for EcMqvAuthEncapsulator<C,E> 
where E: EcEncode<C> + Send + Sync + 'static,
    C: CurveArithmetic+PointCompression + PrimeCurve,
    C::FieldBytesSize: ModulusSize,
    C::AffinePoint: ToSec1Point<C> + FromSec1Point<C>,    
{
    //type Kem = EcMqvAuthKem<C,E>;
    type SeedSize = C::FieldBytesSize;

    fn encapsulate_deterministic(&self, seed: &[u8]) -> (Ciphertext<Self::Kem>, SharedKey<Self::Kem>) {
        let seed = Array::slice_as_array(seed).unwrap();
        let ephemeral_prv = SecretKey::<C>::from_bytes(&seed).unwrap();
        let ephemeral_pub = ephemeral_prv.public_key();

        let raw_shared_secret = mqv2 ( &self.sender_private.as_ref().unwrap(), &ephemeral_prv, &self.recipient_public, &self.recipient_public);
        let raw_shared_secret = elliptic_curve::group::Curve::to_affine(&raw_shared_secret);
        
        let encapsulated_key = E::encode_public_key(&ephemeral_pub);

        (encapsulated_key.try_into().unwrap(), raw_shared_secret.x())
    }
}

impl<C, E> Ord for EcMqvAuthEncapsulator<C,E> 
where C: CurveArithmetic + PointCompression
{
    fn cmp(&self, _other: &Self) -> std::cmp::Ordering {
        todo!()
    }
}
impl<C, DE> PartialOrd for EcMqvAuthEncapsulator<C,DE> 
where C: CurveArithmetic + PointCompression
{
    fn partial_cmp(&self, _other: &Self) -> Option<std::cmp::Ordering> {
        todo!()
    }
}
impl<C, DE> Eq for EcMqvAuthEncapsulator<C,DE> 
where C: CurveArithmetic + PointCompression
{}
impl<C, DE> PartialEq for EcMqvAuthEncapsulator<C,DE> 
where C: CurveArithmetic + PointCompression
{
    fn eq(&self, other: &Self) -> bool {
        self.sender_private == other.sender_private && self.recipient_public == other.recipient_public && self.phantom == other.phantom
    }
}


impl<C, DE> Ord for EcMqvAuthKem<C,DE> {
    fn cmp(&self, _other: &Self) -> std::cmp::Ordering {
        todo!()
    }
}
impl<C, DE> PartialOrd for EcMqvAuthKem<C,DE> {
    fn partial_cmp(&self, _other: &Self) -> Option<std::cmp::Ordering> {
        todo!()
    }
}
impl<C, DE> Eq for EcMqvAuthKem<C,DE> {}
impl<C, DE> Copy for EcMqvAuthKem<C,DE> {}
impl<C, DE> Clone for EcMqvAuthKem<C,DE> {
    fn clone(&self) -> Self {
        Self(self.0.clone(), self.1.clone())
    }
}
impl<C, DE> Default for EcMqvAuthKem<C,DE> {
    fn default() -> Self {
        Self(Default::default(), Default::default())
    }
}
impl<C, DE> std::fmt::Debug for EcMqvAuthKem<C,DE> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("EcMqvAuthCapsulator").field(&self.0).field(&self.1).finish()
    }
}
impl<C, DE> PartialEq for EcMqvAuthKem<C,DE> {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0 && self.1 == other.1
    }
}
