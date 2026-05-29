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
//! use kems::eckem::{EcdhKemCompressed2, EcdhDecapsulatorCompressed, EcdhDecapsulator, EcCompressedEncoder};
//! use kdfs::ansi_x9_63::X963KdfSha256;
//! use kems::kem_with_kdf::{KemWithKdf, CombinerNoKeys};
//! use kems::{Capsulator, FromKey, Encapsulate, Decapsulate};
//! use rand_core::OsRng;
//! 
//! 
//! let recipient_secret_key = SecretKey::generate();
//! let recipient_public_key = recipient_secret_key.public_key();
//! 
//! type EcdhX963Sha256<C> = KemWithKdf<EcdhKemCompressed2<C>, CombinerNoKeys, X963KdfSha256, U32>;
//! //let encapsulator = EcdhEncapsulatorCompressed::<_,EcCombinerX963<Sha256>,U32>::from_key(recipient_public_key);
//! let encapsulator = EcdhX963Sha256::new_encapsulator(recipient_public_key);
//! let (ct, k_send) = encapsulator.encapsulate(&mut OsRng).unwrap();
//! 
//! //let decapsulator = EcdhDecapsulatorCompressed::<_,EcCombinerX963<Sha256>,U32>::from_key(recipient_secret_key);
//! let decapsulator = EcdhX963Sha256::new_decapsulator(recipient_secret_key);
//! let k_recv = decapsulator.decapsulate(&ct).unwrap();
//! assert! ( k_send == k_recv);
//! ```
  

use std::array::TryFromSliceError;
use std::marker::PhantomData;
use std::fmt::Debug;
use std::ops::{Add, Sub};
#[allow(unused)]
use cipher::consts::{U1,U2};
#[allow(unused)]
use cipher::typenum::{Diff, Quot, Sum};
use elliptic_curve::{AffinePoint, Curve, CurveArithmetic, FieldBytesEncoding, FieldBytesSize, Generate, NonZeroScalar, PrimeCurve, ProjectivePoint, PublicKey, Scalar, ScalarValue, SecretKey};
use elliptic_curve::sec1::{CompressedPointSize, FromSec1Point, ModulusSize, Sec1Point, ToSec1Point, UncompressedPointSize};
#[allow(unused)]
use elliptic_curve::point::{AffineCoordinates, PointCompression};
#[allow(unused)]
use elliptic_curve::bigint::ArrayEncoding;
use generic_array::{ArrayLength, GenericArray};
use generic_array::typenum::Unsigned;
use kdfs::hybrid_array::{Array, ArraySize};

use crate::{Capsulator, CryptoRngCore, Decapsulate, DecodeSlice, DeriveKeyPairFromSeed, Encapsulate, EncapsulateDeterministic2, EncodeGenericArray, EncodeHybridArray};
use crate::{EncodedSizeUser2, FromKey, FromKeys, GenerateCapsulatorFromSeed, GetRecipientPublicKeyBytes, GetSenderPublicKeyBytes};


#[cfg(feature="rustcrypto-p256")]
use p256::NistP256;
#[cfg(feature="rustcrypto-p384")]
use p384::NistP384;

// pub trait SecretPointToBytes<C: CurveArithmetic> {
//     type EncodedLen: ArraySize;
//     fn encode ( point: &AffinePoint<C> ) -> Array<u8, Self::EncodedLen>;
// }

// pub trait Encode2<T> {
//     type EncodedLen: ArraySize;
//     fn encode ( point: &T ) -> Array<u8, Self::EncodedLen>;
// }


// Structure implementing the encoding of X and Y coordinates only
//pub struct XandY<C: Curve>(C);

// impl<C> SecretPointToBytes<C> for Xonly<C>
// where C: CurveArithmetic
// {
//     type EncodedLen = C::FieldBytesSize;

//     fn encode ( point: &AffinePoint<C> ) -> Array<u8, Self::EncodedLen> {
//         point.x()
//     }
// }

///
/// Encodes by outputing the X coordinate as a big endian byte array
/// 
pub struct EcXonlyEncoder<C: Curve>(C);


impl<C: CurveArithmetic> EncodeHybridArray<AffinePoint<C>> for EcXonlyEncoder<C>
{
    type EncodedLen = <C as elliptic_curve::Curve>::FieldBytesSize;

    fn encode ( point: &AffinePoint<C> ) -> Array<u8, Self::EncodedLen> {
        point.x()
    }
}



///
/// Encodes or Decodes according to SEC1 compressed format, ie a single byte is_odd followed by the x-coordinate
///
pub struct EcCompressedEncoder<C> ( PhantomData<C>);

impl<C> EncodeGenericArray<PublicKey<C>> for EcCompressedEncoder<C>
where   C: CurveArithmetic + PointCompression, 
        C::AffinePoint: FromSec1Point<C> + ToSec1Point<C>,
        C::FieldBytesSize: ModulusSize,
        <C::FieldBytesSize as ModulusSize>::CompressedPointSize: ArrayLength, //<u8>,
{
    type EncodedLen = CompressedPointSize<C>;
    fn encode(public_key: &PublicKey<C>) -> GenericArray<u8, Self::EncodedLen> {
        let ephemeral_public_encoded = ToSec1Point::to_sec1_point(public_key, true);
        GenericArray::from_slice(ephemeral_public_encoded.as_bytes()).clone()
    }
}

impl<C> DecodeSlice<PublicKey<C>> for EcCompressedEncoder<C>
where C: CurveArithmetic,
    C::FieldBytesSize: ModulusSize,
    C::AffinePoint: FromSec1Point<C> + ToSec1Point<C>
{
    type Error = elliptic_curve::Error;
    fn decode(encoded_bytes: &[u8]) -> Result<PublicKey<C>, Self::Error> {
        PublicKey::<C>::from_sec1_bytes(encoded_bytes)
    }
}



///
/// Encodes or Decodes according to SEC1 uncompressed format, ie a single byte identifier followed by the x-coordinate and y-coordinates
///
pub struct EcUncompressedEncoder<C> ( PhantomData<C>);

impl<C> EncodeGenericArray<PublicKey<C>> for EcUncompressedEncoder<C>
where   C: CurveArithmetic+PointCompression, 
        C::FieldBytesSize: ModulusSize,
        C::AffinePoint: FromSec1Point<C> + ToSec1Point<C>,
        <C::FieldBytesSize as ModulusSize>::UncompressedPointSize: ArrayLength, //<u8>
{
    type EncodedLen = UncompressedPointSize<C>;
    fn encode(public_key: &PublicKey<C>) -> GenericArray<u8, Self::EncodedLen> {
        GenericArray::from_slice(ToSec1Point::to_sec1_point(public_key, false).as_bytes()).clone()
    }
}

impl<C> DecodeSlice<PublicKey<C>> for EcUncompressedEncoder<C>
where C: CurveArithmetic,
    C::FieldBytesSize: ModulusSize,
    C::AffinePoint: FromSec1Point<C> + ToSec1Point<C>
{
    type Error = elliptic_curve::Error;
    fn decode(encoded_bytes: &[u8]) -> Result<PublicKey<C>, Self::Error> {
        PublicKey::<C>::from_sec1_bytes(encoded_bytes)
    }
}




///
/// Format consisting of x-coordinate || y-coordinate as byte arrays 
/// 
pub struct EcRawEncoder<C> ( PhantomData<C>);

impl<C> EncodeGenericArray<PublicKey<C>> for EcRawEncoder<C>
    where   C: CurveArithmetic+PointCompression, 
        C::FieldBytesSize: ModulusSize,
        C::AffinePoint: FromSec1Point<C> + ToSec1Point<C>,
        <C::FieldBytesSize as ModulusSize>::UntaggedPointSize: ArrayLength, //<u8>
{
    type EncodedLen = <FieldBytesSize<C> as ModulusSize>::UntaggedPointSize;

    // returns the untagged byte array, x || y
    fn encode(public_key: &PublicKey<C>) -> GenericArray<u8, Self::EncodedLen> {
        let ephemeral_public_encoded = ToSec1Point::to_sec1_point(public_key, false);
        GenericArray::from_slice(&ephemeral_public_encoded.as_bytes()[1..]).clone()
    }
}
impl<C> DecodeSlice<PublicKey<C>> for EcRawEncoder<C>
where C: CurveArithmetic,
    C::FieldBytesSize: ModulusSize,
    C::AffinePoint: FromSec1Point<C> + ToSec1Point<C>
{
    type Error = elliptic_curve::Error;
    fn decode(encoded_bytes: &[u8]) -> Result<PublicKey<C>, Self::Error> {
        let encoded_point = Sec1Point::<C>::from_untagged_bytes(&Array::try_from(encoded_bytes)?);
        PublicKey::<C>::from_sec1_point(&encoded_point).into_option().ok_or(elliptic_curve::Error)
    }
}
impl<C: CurveArithmetic> EncodeHybridArray<AffinePoint<C>> for EcRawEncoder<C>
where C::AffinePoint: ToSec1Point<C>,
    C::FieldBytesSize: ModulusSize + Debug,
    <C::FieldBytesSize as ModulusSize>::UncompressedPointSize: Sub<U1>,
    <<C::FieldBytesSize as ModulusSize>::UncompressedPointSize as Sub<U1>>::Output: ArraySize,
{
    //type EncodedLen = <C as elliptic_curve::Curve>::FieldBytesSize;
    type EncodedLen = Diff<<C::FieldBytesSize as ModulusSize>::UncompressedPointSize, U1>;

    fn encode ( point: &AffinePoint<C> ) -> Array<u8, Self::EncodedLen> {
        let encoded_point = point.to_uncompressed_point(); //to_sec1_point(false);
        let (_, payload) = encoded_point.split::<U1>();
        payload
    }
}


/// Blanket implementations for secret keys, which is the scalar as a sequence of bytes
impl<C,T> EncodeGenericArray<SecretKey<C>> for T
where   C: Curve,
        C::FieldBytesSize: ModulusSize + ArrayLength, //<u8>,
{
    type EncodedLen = FieldBytesSize<C>;
    fn encode(key: &SecretKey<C>) -> GenericArray<u8, Self::EncodedLen> {
        //GenericArray::clone_from_slice(&key.to_bytes())
        GenericArray::from_slice(&key.to_bytes()).clone()
    }
}

// Blanket implementation as all encoding formats have the same private key - a series of bytes representing the scalar private key
impl<C,T> DecodeSlice<SecretKey<C>> for T
where C: Curve,
{
    type Error = elliptic_curve::Error;
    fn decode(encoded_bytes: &[u8]) -> Result<SecretKey<C>, Self::Error> {
        SecretKey::<C>::from_slice(encoded_bytes)
    }
}


// impl<C> SecretPointToBytes<C> for XandY<C>
// where C: CurveArithmetic,
//     C::AffinePoint: ToSec1Point<C>,
//     C::FieldBytesSize: ModulusSize + Debug,
//     <C::FieldBytesSize as ModulusSize>::UncompressedPointSize: Sub<U1>,
//     <<C::FieldBytesSize as ModulusSize>::UncompressedPointSize as Sub<U1>>::Output: ArraySize,
// {
//     type EncodedLen = Diff<<C::FieldBytesSize as ModulusSize>::UncompressedPointSize, U1>;
    
//     fn encode ( point: &AffinePoint<C> ) -> Array<u8, Self::EncodedLen> {
//         let encoded_point = point.to_uncompressed_point(); //to_sec1_point(false);
//         let (_, payload) = encoded_point.split::<U1>();
//         payload
//     }
// }

// impl<C: CurveArithmetic> Encode5<AffinePoint<C>> for XandY<C>
// where C::AffinePoint: ToSec1Point<C>,
//     C::FieldBytesSize: ModulusSize + Debug,
//     <C::FieldBytesSize as ModulusSize>::UncompressedPointSize: Sub<U1>,
//     <<C::FieldBytesSize as ModulusSize>::UncompressedPointSize as Sub<U1>>::Output: ArraySize,
// {
//     //type EncodedLen = <C as elliptic_curve::Curve>::FieldBytesSize;
//     type EncodedLen = Diff<<C::FieldBytesSize as ModulusSize>::UncompressedPointSize, U1>;

//     fn encode ( point: &AffinePoint<C> ) -> Array<u8, Self::EncodedLen> {
//         let encoded_point = point.to_uncompressed_point(); //to_sec1_point(false);
//         let (_, payload) = encoded_point.split::<U1>();
//         payload
//     }
// }



// Wrapper structure for making different RNG traits interoperable
mod wrapper {
    
    use elliptic_curve::rand_core::{TryCryptoRng, TryRng}; //, TryRngCore};

    // RSA uses an new version of Rng. Wrap it so we can use the same Encapsulator trait
    pub struct RngWrapper<'a, R: super::CryptoRngCore> {
        core: &'a mut R,
    }
    impl<'a, R: super::CryptoRngCore> From<&'a mut R> for RngWrapper<'a, R> {
        fn from(v: &'a mut R) -> Self {
            Self { core: v}
        }
    }

    impl<'a, R: super::CryptoRngCore> TryCryptoRng for RngWrapper<'a, R> {}

    impl<'a, R: super::CryptoRngCore> TryRng for RngWrapper<'a, R> {
        type Error = elliptic_curve::Error;
        
        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            Ok(self.core.next_u32())
        }
        
        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            Ok(self.core.next_u64())
        }
        
        fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
            Ok(self.core.fill_bytes(dst))
        }
    }
}








///
/// Allows for the encapsulation of a key using Elliptic-Curve Diffie-Hellman
/// 

pub struct EcdhEncapsulator <C: CurveArithmetic+PointCompression, ED, S,G>
{
    pub recipient_public: PublicKey<C>,
    _phantom2: PhantomData<S>,
    _phantom5: PhantomData<ED>,
    _phantom6: PhantomData<G>,
}

/// Encapsulation key used for elliptic curve Diffie Hellman based KEM with SEC1 compressed encoding of the ciphertext
pub type EcdhEncapsulatorCompressed<C,G> = EcdhEncapsulator<C, EcCompressedEncoder<C>, EcXonlyEncoder<C>, G>;
/// Encapsulation key used for elliptic curve Diffie Hellman based KEM with SEC1 uncompressed encoding of the ciphertext
pub type EcdhEncapsulatorUncompressed<C,G> = EcdhEncapsulator<C, EcUncompressedEncoder<C>, EcXonlyEncoder<C>, G>;
/// Encapsulation key used for elliptic curve Diffie Hellman based KEM with raw encoding of the ciphertext and keys.
/// Points are encoded as x followed by y, where each field is a sequence of big endian bytes 
pub type EcdhEncapsulatorRaw<C,G> = EcdhEncapsulator<C, EcRawEncoder<C>, EcXonlyEncoder<C>, G>;


impl<C: CurveArithmetic+PointCompression, ED, S, G> EncodedSizeUser2 for EcdhEncapsulator<C,ED, S, G>
where ED: DecodeSlice<PublicKey<C>> + EncodeGenericArray<PublicKey<C>>,
    <ED as DecodeSlice<PublicKey<C>>>::Error: Debug
{
    type EncodedSize = ED::EncodedLen;
    fn as_bytes(&self) -> crate::Encoded<Self> {
        ED::encode(&self.recipient_public)
    }
    fn from_bytes(enc: &crate::Encoded<Self>) -> Self {
        let recipient_public = ED::decode(enc).unwrap();
        //Self { recipient_public, _phantom2: PhantomData, _phantom5: PhantomData, _phantom6: PhantomData}
        Self::from_key(recipient_public)
    }
}

impl<C,DE,S,G> FromKey for EcdhEncapsulator<C,DE,S,G> 
where   C: CurveArithmetic+PointCompression, 
{
    type Key = PublicKey<C>;
    fn from_key(value: PublicKey<C>) -> Self {
        EcdhEncapsulator { _phantom2: PhantomData, _phantom5: PhantomData, recipient_public: value, _phantom6: PhantomData }
    }
}


impl<C: CurveArithmetic+PointCompression, ED, S, G> EcdhEncapsulator <C, ED, S, G>
where   C: CurveArithmetic + PointCompression,
        C::AffinePoint: ToSec1Point<C> + FromSec1Point<C>,
        FieldBytesSize<C>: ModulusSize,
        ED: EncodeGenericArray<PublicKey<C>> , //+ Decode<PublicKey<C>>,
        //S: SecretPointToBytes<C>,
        S: EncodeHybridArray<AffinePoint<C>>
{
    fn encapsulate_deterministic_key(&self, ephemeral_prv: &SecretKey<C> ) -> Result<(GenericArray<u8,ED::EncodedLen>, Array<u8,<S as EncodeHybridArray<AffinePoint<C>>>::EncodedLen>), ()> {
        
        //let ephemeral_prv = elliptic_curve::SecretKey::<C>::from_slice(&seed).map_err(|_|())?;
        let ephemeral_pub = ephemeral_prv.public_key();
        
        // perform the diffie-hellman action by multiplying the public and private keys
        let raw_shared_secret = self.recipient_public.to_projective() * *ephemeral_prv.to_nonzero_scalar();
        let raw_shared_secret = elliptic_curve::group::Curve::to_affine(&raw_shared_secret);
        
        let raw_encoded_shared_secret = S::encode(&raw_shared_secret);
        
        Ok((ED::encode(&ephemeral_pub), raw_encoded_shared_secret))
    }
}


impl<C: CurveArithmetic+PointCompression, ED, S, G> Encapsulate<GenericArray<u8,ED::EncodedLen>, Array<u8,<S as EncodeHybridArray<AffinePoint<C>>>::EncodedLen>> for EcdhEncapsulator <C, ED, S, G>
where   C: CurveArithmetic + PointCompression,
        C::AffinePoint: ToSec1Point<C> + FromSec1Point<C>,
        FieldBytesSize<C>: ModulusSize,
        ED: EncodeGenericArray<PublicKey<C>> + DecodeSlice<PublicKey<C>>,
        //S: SecretPointToBytes<C>,
        S: EncodeHybridArray<AffinePoint<C>>,
{
    type Error = ();
    fn encapsulate(&self, rng: &mut impl CryptoRngCore ) -> Result<(GenericArray<u8,ED::EncodedLen>, Array<u8,<S as EncodeHybridArray<AffinePoint<C>>>::EncodedLen>), Self::Error> {
        
        let mut bytes = Array::default();
        rng.try_fill_bytes(bytes.as_mut_slice()).unwrap();

        let mut ephemeral_prv = SecretKey::<C>::from_bytes(&bytes);

        // Ugly, but it kind of works to ensure the random scalar is smaller than the modulus
        if ephemeral_prv.is_err()
        {
            bytes[0] &= 0x01;
            ephemeral_prv = SecretKey::<C>::from_bytes(&bytes);
        }
        self.encapsulate_deterministic_key(&ephemeral_prv.unwrap())
        // //let ephemeral_prv = elliptic_curve::SecretKey::<C>::from_slice(&seed).map_err(|_|())?;
        // let ephemeral_pub = ephemeral_prv.as_ref().unwrap().public_key();
        
        // // perform the diffie-hellman action by multiplying the public and private keys
        // let raw_shared_secret = self.recipient_public.to_projective() * *ephemeral_prv.unwrap().to_nonzero_scalar();
        // let raw_shared_secret = elliptic_curve::group::Curve::to_affine(&raw_shared_secret);
        
        // //let raw_shared_secret2 = raw_shared_secret.to_encoded_point(false);
        // let raw_shared_secret2 = S::encode(&raw_shared_secret);
        
        // //let derived_shared_secret = self.kdf.combine::<L>(&raw_shared_secret.x(), raw_shared_secret2.y().unwrap(), &ED::encode(&ephemeral_prv.public_key()), &ED::encode(&self.recipient_public));
        // Ok((ED::encode(&ephemeral_pub), raw_shared_secret2))
    }
}

impl<C: CurveArithmetic+PointCompression, ED, S, G> EncapsulateDeterministic2<GenericArray<u8,ED::EncodedLen>, Array<u8,<S as EncodeHybridArray<AffinePoint<C>>>::EncodedLen>> for EcdhEncapsulator <C, ED, S, G>
where   C: CurveArithmetic + PointCompression,
        C::AffinePoint: ToSec1Point<C> + FromSec1Point<C>,
        FieldBytesSize<C>: ModulusSize,
        ED: EncodeGenericArray<PublicKey<C>> + DecodeSlice<PublicKey<C>>,
        //S: SecretPointToBytes<C>,
        S: EncodeHybridArray<AffinePoint<C>>,
        G: DeriveKeyPairFromSeed<SecretKey<C>, PublicKey=PublicKey<C>>,
{
    type Error = ();
    type SeedSize = G::SeedSize;
    fn encapsulate_deterministic(&self, seed: &[u8] ) -> Result<(GenericArray<u8,ED::EncodedLen>, Array<u8,<S as EncodeHybridArray<AffinePoint<C>>>::EncodedLen>), Self::Error> {
        let Ok((ephemeral_prv, _ephemeral_pub)) = G::derive_keypair_from_seed(seed) else { return Err(())};
        self.encapsulate_deterministic_key(&ephemeral_prv)
        // let mut ephemeral_prv = SecretKey::<C>::from_bytes(seed);

        // // Ugly, but it kind of works to ensure the random scalar is smaller than the modulus
        // if ephemeral_prv.is_err()
        // {
        //     let mut seed = seed.clone();
        //     seed[0] &= 0x01;
        //     ephemeral_prv = SecretKey::<C>::from_bytes(&seed);
        // }
        // //let ephemeral_prv = elliptic_curve::SecretKey::<C>::from_slice(&seed).map_err(|_|())?;
        // let ephemeral_pub = ephemeral_prv.as_ref().unwrap().public_key();
        
        // // perform the diffie-hellman action by multiplying the public and private keys
        // let raw_shared_secret = self.recipient_public.to_projective() * *ephemeral_prv.unwrap().to_nonzero_scalar();
        // let raw_shared_secret = elliptic_curve::group::Curve::to_affine(&raw_shared_secret);
        
        // //let raw_shared_secret2 = raw_shared_secret.to_encoded_point(false);
        // let raw_shared_secret2 = S::encode(&raw_shared_secret);
        
        // //let derived_shared_secret = self.kdf.combine::<L>(&raw_shared_secret.x(), raw_shared_secret2.y().unwrap(), &ED::encode(&ephemeral_prv.public_key()), &ED::encode(&self.recipient_public));
        // Ok((ED::encode(&ephemeral_pub), raw_shared_secret2))
    }
}


impl<C: CurveArithmetic+PointCompression, ED, S, G> GetRecipientPublicKeyBytes for EcdhEncapsulator <C, ED, S, G>
where   C: CurveArithmetic + PointCompression,
        C::AffinePoint: ToSec1Point<C> + FromSec1Point<C>,
        FieldBytesSize<C>: ModulusSize,
        ED: EncodeGenericArray<PublicKey<C>> + DecodeSlice<PublicKey<C>>,
{
    type EncodedLen = ED::EncodedLen;

    fn get_recipient_public_key_bytes(&self) -> GenericArray<u8, Self::EncodedLen> {
        ED::encode(&self.recipient_public)
    }
}





///
/// Factory struct to create encapsulators and decapsulators using one-way Diffie-Hellman with sender
/// authentication suitable for use 
/// with Elliptic Curves implementing the RustCryoto CurveArithmetic traits
/// 
//pub struct EcdhAuthCapsulator<C,K,L,DE> (PhantomData<C>, PhantomData<K>, PhantomData<L>, PhantomData<DE>);
pub struct EcdhAuthCapsulator<C,DE,G> (PhantomData<C>, PhantomData<DE>, PhantomData<G>);

impl<C, DE, G> Capsulator for EcdhAuthCapsulator<C,DE, G>
where 
    DE: EncodeGenericArray<PublicKey<C>> + DecodeSlice<PublicKey<C>> + DecodeSlice<SecretKey<C>> + EncodeGenericArray<SecretKey<C>>, 
    <DE as EncodeGenericArray<PublicKey<C>>>::EncodedLen: ArraySize,  
    C: CurveArithmetic+PointCompression,
    C::FieldBytesSize: ModulusSize,
    C::AffinePoint: ToSec1Point<C> + FromSec1Point<C>, 
    <C::FieldBytesSize as Add>::Output: ArraySize,
{
    type Encapsulator = EcdhAuthEncapsulator<C,DE,G>;
    type Decapsulator = EcdhAuthDecapsulator<C,DE>;
    type CiphertextSize = <DE as EncodeGenericArray<PublicKey<C>>>::EncodedLen;
    type SharedKeySize = Sum<C::FieldBytesSize, C::FieldBytesSize>;

    fn generate ( _rng: &mut impl CryptoRngCore ) -> (Self::Encapsulator, Self::Decapsulator) {
        todo!()
    }
}


impl<C, DE, G> EcdhAuthCapsulator<C,DE,G>
where DE: EncodeGenericArray<PublicKey<C>> + DecodeSlice<PublicKey<C>> + DecodeSlice<SecretKey<C>> + EncodeGenericArray<SecretKey<C>>, 
    C: CurveArithmetic+PointCompression, 
    C::FieldBytesSize: ModulusSize,
    C::AffinePoint: ToSec1Point<C> + FromSec1Point<C>, 
    <DE as EncodeGenericArray<PublicKey<C>>>::EncodedLen: ArraySize,  
    <DE as DecodeSlice<PublicKey<C>>>::Error: Debug,
    <DE as DecodeSlice<SecretKey<C>>>::Error: Debug,
{    
    pub fn from_bytes_decap ( priv_bytes: &GenericArray::<u8, <DE as EncodeGenericArray<SecretKey<C>>>::EncodedLen>, 
        pub_bytes: &GenericArray<u8, <DE as EncodeGenericArray<PublicKey<C>>>::EncodedLen> ) -> EcdhAuthDecapsulator<C, DE>
    {
        let priv_key = <DE as DecodeSlice<SecretKey<C>>>::decode(priv_bytes).unwrap();
        let pub_key = <DE as DecodeSlice<PublicKey<C>>>::decode(pub_bytes).unwrap();

        EcdhAuthDecapsulator{ recipient_private: priv_key, sender_public: pub_key, phantom: PhantomData }
    }
    pub fn decap_from_keys ( recipient_private:SecretKey<C>, sender_public:PublicKey<C> ) -> EcdhAuthDecapsulator<C, DE>
    {
        EcdhAuthDecapsulator { recipient_private, sender_public, phantom: PhantomData}
    }
    pub fn encap_from_keys ( recipient_public:PublicKey<C>, sender_private:SecretKey<C> ) -> EcdhAuthEncapsulator<C, DE,G>
    {
        EcdhAuthEncapsulator { recipient_public, sender_private, _phantom5: PhantomData, _phantom6: PhantomData}
    }
}



/// Authenticated KEM based upon Elliptic Curve Diffie Hellman with SEC1 compressed encoding of the ciphertext
pub type EcdhAuthCapsulatorCompressed<C,G> = EcdhAuthCapsulator<C, EcCompressedEncoder<C>, G>;
/// Authenticated KEM based upon Elliptic Curve Diffie Hellman with SEC1 uncompressed encoding of the ciphertext
pub type EcdhAuthCapsulatorUncompressed<C,G> = EcdhAuthCapsulator<C, EcUncompressedEncoder<C>,G>;








///
/// Struct for creating authenticating encapsulated keys using diffie-hellman
/// 
//pub struct EcdhAuthEncapsulator <C: CurveArithmetic+PointCompression, K: EcdhAuthCombiner, L: ArrayLength<u8>, DE>
pub struct EcdhAuthEncapsulator <C: CurveArithmetic+PointCompression, DE,G>
{
    recipient_public: PublicKey<C>,
    sender_private: SecretKey<C>,
    _phantom5: PhantomData<DE>,
    _phantom6: PhantomData<G>,
}

/// Specialization of EcdhAuthEncapsulator using a compressed form of public key and without public keys being used in the key derivation function
pub type EcdhAuthEncapsulatorCompressed<C,G> = EcdhAuthEncapsulator<C,EcCompressedEncoder<C>,G>;
/// Specialization of EcdhAuthEncapsulator using an uncompressed form of public key and without public keys being used in the key derivation function
pub type EcdhAuthEncapsulatorUncompressed<C,G> = EcdhAuthEncapsulator<C,EcUncompressedEncoder<C>,G>;


impl<C,DE,G> FromKeys for EcdhAuthEncapsulator<C,DE,G> 
where   C: CurveArithmetic+PointCompression,
{
    type PrivateKey = SecretKey<C>;
    type PublicKey = PublicKey<C>;

    fn from_keys ( pub_key: Self::PublicKey, priv_key: Self::PrivateKey ) -> Self {
        Self { sender_private: priv_key, recipient_public: pub_key, _phantom5: PhantomData, _phantom6: PhantomData}
    }
}


impl<C,DE,G> Encapsulate<GenericArray<u8,DE::EncodedLen>, Array<u8,Sum<C::FieldBytesSize, C::FieldBytesSize>>> for EcdhAuthEncapsulator<C,DE,G>
where   //FieldBytesSize<C>: ModulusSize,
        DE: EncodeGenericArray<PublicKey<C>> + DecodeSlice<PublicKey<C>>,
        C: CurveArithmetic + PointCompression,
        <C::FieldBytesSize as Add>::Output: ArraySize
{
    type Error = ();

    fn encapsulate(&self, rng: &mut impl CryptoRngCore) -> Result<(GenericArray<u8,DE::EncodedLen>, Array<u8,Sum<C::FieldBytesSize,C::FieldBytesSize>>), Self::Error> 
    {
        // let mut rng = wrapper::RngWrapper::from(rng);

        // let ephemeral_prv = elliptic_curve::SecretKey::<C>::try_from_rng(&mut rng).map_err(|_|())?;
        let mut seed = Array::default();
        rng.fill_bytes(&mut seed);

        //let ephemeral_prv = elliptic_curve::SecretKey::<C>::try_from_rng(&mut rng).map_err(|_|())?;
        let ephemeral_prv = SecretKey::<C>::from_bytes(&seed).map_err(|_|())?;
        self.encapsulate_from_key(&ephemeral_prv)

        // let encoded_ephemeral_public_key = DE::encode(&ephemeral_prv.public_key());
        // let public_point = self.recipient_public.to_projective();

        // let raw_shared_secret_1 = public_point * *ephemeral_prv.to_nonzero_scalar();
        // let raw_shared_secret_2 = public_point * *self.sender_private.to_nonzero_scalar();
        
        // let raw_shared_secret_1 = elliptic_curve::group::Curve::to_affine(&raw_shared_secret_1);
        // let raw_shared_secret_2 = elliptic_curve::group::Curve::to_affine(&raw_shared_secret_2);
        
        // //let derived_shared_secret = self.kdf.combine(&raw_shared_secret_1.x(), &raw_shared_secret_2.x(), &DE::encode(&ephemeral_prv.public_key()), &DE::encode(&self.recipient_public), &DE::encode(&self.sender_private.public_key()));
        // let raw_shared_secret_1: Array<u8, C::FieldBytesSize> = raw_shared_secret_1.x();
        // let raw_shared_secret_2: Array<u8, C::FieldBytesSize> = raw_shared_secret_2.x();
        // // let mut raw_shared_secret: Array<u8, Sum<C::FieldBytesSize, C::FieldBytesSize>> = Array::default(); //raw_shared_secret_1.concat(raw_shared_secret_2);
        // // raw_shared_secret[..C::FieldBytesSize::USIZE].copy_from_slice(&raw_shared_secret_1);
        // // raw_shared_secret[C::FieldBytesSize::USIZE..].copy_from_slice(&raw_shared_secret_2);
        // let raw_shared_secret = raw_shared_secret_1.concat(raw_shared_secret_2);

        // Ok((encoded_ephemeral_public_key, raw_shared_secret))
    }
}





impl<C,DE,G> EncapsulateDeterministic2<GenericArray<u8,DE::EncodedLen>, Array<u8,Sum<C::FieldBytesSize, C::FieldBytesSize>>> for EcdhAuthEncapsulator<C,DE,G>
where   //FieldBytesSize<C>: ModulusSize,
        DE: EncodeGenericArray<PublicKey<C>> + DecodeSlice<PublicKey<C>>,
        C: CurveArithmetic + PointCompression,
        <C::FieldBytesSize as Add>::Output: ArraySize,
        G: DeriveKeyPairFromSeed<SecretKey<C>, PublicKey=PublicKey<C>>,
{
    type Error = ();
    type SeedSize = C::FieldBytesSize;
    fn encapsulate_deterministic(&self, seed: &[u8]) -> Result<(GenericArray<u8,DE::EncodedLen>, Array<u8,Sum<C::FieldBytesSize, C::FieldBytesSize>>), Self::Error>
    {
        // let Ok(seed) = Array::try_from(seed) else { return Err(())};
        // let ephemeral_prv = SecretKey::<C>::from_bytes(&seed).map_err(|_|())?;
        let Ok((ephemeral_prv, _ephemeral_pub)) = G::derive_keypair_from_seed(seed) else { return Err(())};
        self.encapsulate_from_key ( &ephemeral_prv )

        // let encoded_ephemeral_public_key = DE::encode(&ephemeral_prv.public_key());
        // let public_point = self.recipient_public.to_projective();

        // let raw_shared_secret_1 = public_point * *ephemeral_prv.to_nonzero_scalar();
        // let raw_shared_secret_2 = public_point * *self.sender_private.to_nonzero_scalar();
        
        // let raw_shared_secret_1 = elliptic_curve::group::Curve::to_affine(&raw_shared_secret_1);
        // let raw_shared_secret_2 = elliptic_curve::group::Curve::to_affine(&raw_shared_secret_2);
        
        // let raw_shared_secret_1: Array<u8, C::FieldBytesSize> = raw_shared_secret_1.x();
        // let raw_shared_secret_2: Array<u8, C::FieldBytesSize> = raw_shared_secret_2.x();
        // let raw_shared_secret = raw_shared_secret_1.concat(raw_shared_secret_2);

        // Ok((encoded_ephemeral_public_key, raw_shared_secret))
    }
}


impl<C,DE,G> EcdhAuthEncapsulator<C,DE,G>
where   //FieldBytesSize<C>: ModulusSize,
        DE: EncodeGenericArray<PublicKey<C>> + DecodeSlice<PublicKey<C>>,
        C: CurveArithmetic + PointCompression,
        <C::FieldBytesSize as Add>::Output: ArraySize,
{
    
    fn encapsulate_from_key(&self, ephemeral_prv: &SecretKey<C>) -> Result<(GenericArray<u8,DE::EncodedLen>, Array<u8,Sum<C::FieldBytesSize, C::FieldBytesSize>>), ()>
    {
        let encoded_ephemeral_public_key = DE::encode(&ephemeral_prv.public_key());
        let public_point = self.recipient_public.to_projective();

        let raw_shared_secret_1 = public_point * *ephemeral_prv.to_nonzero_scalar();
        let raw_shared_secret_2 = public_point * *self.sender_private.to_nonzero_scalar();
        
        let raw_shared_secret_1 = elliptic_curve::group::Curve::to_affine(&raw_shared_secret_1);
        let raw_shared_secret_2 = elliptic_curve::group::Curve::to_affine(&raw_shared_secret_2);
        
        let raw_shared_secret_1: Array<u8, C::FieldBytesSize> = raw_shared_secret_1.x();
        let raw_shared_secret_2: Array<u8, C::FieldBytesSize> = raw_shared_secret_2.x();
        let raw_shared_secret = raw_shared_secret_1.concat(raw_shared_secret_2);

        Ok((encoded_ephemeral_public_key, raw_shared_secret))
    }
}










impl<C,DE,G> GetSenderPublicKeyBytes for EcdhAuthEncapsulator<C,DE,G>
where C: CurveArithmetic + PointCompression,
    DE: EncodeGenericArray<PublicKey<C>> + DecodeSlice<PublicKey<C>>,
{
    type EncodedLen = <DE as EncodeGenericArray<PublicKey<C>>>::EncodedLen;

    fn get_sender_public_key_bytes(&self) -> GenericArray<u8, Self::EncodedLen> {
        DE::encode(&self.sender_private.public_key())
    }
}
impl<C,DE,G> GetRecipientPublicKeyBytes for EcdhAuthEncapsulator<C,DE,G>
where C: CurveArithmetic + PointCompression,
    DE: EncodeGenericArray<PublicKey<C>> + DecodeSlice<PublicKey<C>>,
{
    type EncodedLen = <DE as EncodeGenericArray<PublicKey<C>>>::EncodedLen;
    fn get_recipient_public_key_bytes(&self) -> GenericArray<u8, Self::EncodedLen> {
        DE::encode(&self.recipient_public)
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
pub struct EcdhDecapsulator <C: CurveArithmetic+PointCompression, ED, S, G>
{
    pub recipient_private: SecretKey<C>,
    phantom: PhantomData<S>,
    phantom1: PhantomData<ED>,
    phantom2: PhantomData<G>
}


impl<C: CurveArithmetic + PointCompression, DE, S, G> FromKey for EcdhDecapsulator<C,DE,S,G> {
    type Key = SecretKey<C>;
    /// Create a Decapsulator from a private key and kdf, which must match the recipient public key and kdf used 
    /// during the encapsulation phase
    fn from_key (private: SecretKey<C>) -> Self {
        Self { recipient_private: private, phantom: PhantomData, phantom1: PhantomData, phantom2: PhantomData }
    }
}



/// Encapsulation key used for elliptic curve Diffie Hellman based KEM with SEC1 compressed encoding of the ciphertext
pub type EcdhDecapsulatorCompressed<C,G> = EcdhDecapsulator<C, EcCompressedEncoder<C>, EcXonlyEncoder<C>,G>;
/// Encapsulation key used for elliptic curve Diffie Hellman based KEM with SEC1 uncompressed encoding of the ciphertext
pub type EcdhDecapsulatorUncompressed<C,G> = EcdhDecapsulator<C, EcUncompressedEncoder<C>, EcXonlyEncoder<C>,G>;
/// Encapsulation key used for elliptic curve Diffie Hellman based KEM with raw encoding of the ciphertext and keys.
/// Raw encoding means the private key is a sequence of big endian bytes representing the scalar
/// Points are encoded as x followed by y, where each field is a sequence of big endian bytes 
pub type EcdhDecapsulatorRaw<C,G> = EcdhDecapsulator<C,EcRawEncoder<C>, EcXonlyEncoder<C>,G>;



impl<C, ED, S,G> Decapsulate<GenericArray<u8, ED::EncodedLen>, Array<u8, S::EncodedLen>> for EcdhDecapsulator<C,ED,S,G>
where 
    ED: EncodeGenericArray<PublicKey<C>> + DecodeSlice<PublicKey<C>>,
    <ED as DecodeSlice<PublicKey<C>>>::Error: Debug,
    C: CurveArithmetic+PointCompression,
    C::FieldBytesSize: ModulusSize,
    C::AffinePoint: ToSec1Point<C>,
    //S: SecretPointToBytes<C>,
    S: EncodeHybridArray<AffinePoint<C>>,
{
    type Error = <ED as DecodeSlice<PublicKey<C>>>::Error;
    fn decapsulate(&self, encapsulated_key: &GenericArray<u8, ED::EncodedLen>) -> Result<Array<u8, S::EncodedLen>, Self::Error> {
        let encapped_key = ED::decode(&encapsulated_key)?;

        let public_point = ProjectivePoint::<C>::from(*encapped_key.as_affine());
        
        let raw_shared_secret = public_point * *self.recipient_private.to_nonzero_scalar();
        let raw_shared_secret = elliptic_curve::group::Curve::to_affine(&raw_shared_secret);

        Ok(S::encode(&raw_shared_secret))
    }
}

impl<C, ED, S, G> EncodedSizeUser2 for EcdhDecapsulator<C,ED,S,G>
where C: CurveArithmetic+PointCompression,
    ED: DecodeSlice<SecretKey<C>> + EncodeGenericArray<SecretKey<C>>,
    <ED as DecodeSlice<SecretKey<C>>>::Error: std::fmt::Debug,
    C::FieldBytesSize: ArrayLength, //<u8>,
{
    type EncodedSize = C::FieldBytesSize;
    fn as_bytes(&self) -> crate::Encoded<Self> {
        GenericArray::from_slice(self.recipient_private.clone().to_bytes().as_slice()).clone()
    }
    fn from_bytes(encoded_key: &crate::Encoded<Self>) -> Self {
        let secret_key = ED::decode(encoded_key).unwrap();
        //Self { recipient_private: secret_key, phantom: PhantomData, phantom1: PhantomData, phantom2: PhantomData}
        Self::from_key(secret_key)
    }
}

// impl<C, ED, S, G> EncodeGenericArraySelf for EcdhDecapsulator<C,ED,S,G>
// where C: CurveArithmetic+PointCompression,
//     ED: Decode<SecretKey<C>> + EncodeGenericArray<SecretKey<C>>,
//     C::FieldBytesSize: ArrayLength<u8>,
// {
//     type EncodedLen = C::FieldBytesSize;
    
//     fn encode(&self) -> GenericArray<u8, Self::EncodedLen> {
//         GenericArray::from_slice(self.recipient_private.to_bytes().as_slice()).clone()
//     }
// }

// impl<C, ED, S, G> DecodeGenericArray<Self> for EcdhDecapsulator<C,ED,S,G>
// where C: CurveArithmetic+PointCompression,
//     ED: Decode<SecretKey<C>> + EncodeGenericArray<SecretKey<C>>,
//     <ED as Decode<SecretKey<C>>>::Error: std::fmt::Debug,
//     C::FieldBytesSize: ArrayLength<u8>,
// {
//     type Error = ();
//     type EncodedLen = C::FieldBytesSize;

//     fn decode(encoded_bytes: &GenericArray<u8, Self::EncodedLen>) -> Result<Self, Self::Error> {
//         let secret_key = ED::decode(encoded_bytes).unwrap();
//         Ok(Self::from_key(secret_key))
//     }
// }


impl<C: CurveArithmetic+PointCompression, ED, S, G> crate::GetEncapsulator for EcdhDecapsulator<C,ED,S,G>
where ED: EncodeGenericArray<PublicKey<C>> + DecodeSlice<PublicKey<C>>,
    <ED as EncodeGenericArray<PublicKey<C>>>::EncodedLen: ArraySize,
{
    type Encapsulator = EcdhEncapsulator<C, ED, S,G>;
    fn get_encapsulator(&self) -> Self::Encapsulator {
        let public_key = self.recipient_private.public_key();
        //Self::Encapsulator { recipient_public: public_key, _phantom2: PhantomData, _phantom5: PhantomData, _phantom6: PhantomData}
        Self::Encapsulator::from_key(public_key)
    }
}

impl<C: CurveArithmetic+PointCompression, ED, S,G> GetRecipientPublicKeyBytes for EcdhDecapsulator<C,ED,S,G>
where ED: EncodeGenericArray<PublicKey<C>> + DecodeSlice<PublicKey<C>>,
    <ED as EncodeGenericArray<PublicKey<C>>>::EncodedLen: ArraySize,
{
    type EncodedLen = ED::EncodedLen;

    fn get_recipient_public_key_bytes(&self) -> GenericArray<u8, Self::EncodedLen> {
        ED::encode(&self.recipient_private.public_key())
    }
}


///
/// Struct enabling receipt of a EciesEncapKey and recovery of the shared secret
/// 
pub struct EcdhAuthDecapsulator <C: CurveArithmetic+PointCompression, DE>
{
    recipient_private: SecretKey<C>,
    sender_public: PublicKey<C>,
    phantom: PhantomData<DE>,
}

impl<C: CurveArithmetic + PointCompression, DE> FromKeys for EcdhAuthDecapsulator<C, DE>
{
    type PrivateKey = SecretKey<C>;
    type PublicKey = PublicKey<C>;

    fn from_keys ( pub_key: Self::PublicKey, priv_key: Self::PrivateKey ) -> Self {
        Self { recipient_private: priv_key, sender_public: pub_key, phantom: PhantomData}
    }
}

impl<C,DE> Decapsulate<GenericArray<u8, DE::EncodedLen>, Array<u8, Sum<C::FieldBytesSize, C::FieldBytesSize>>> for EcdhAuthDecapsulator<C,DE> 
where   C: CurveArithmetic + PointCompression,
        C::FieldBytesSize: ModulusSize,
        C::AffinePoint: FromSec1Point<C> + ToSec1Point<C>,
        DE: EncodeGenericArray<PublicKey<C>>,
        DE::EncodedLen: ArraySize,
        <C::FieldBytesSize as Add>::Output: ArraySize,
{
    type Error = elliptic_curve::Error;

    fn decapsulate(&self, encapsulated_key: &GenericArray<u8, DE::EncodedLen>) -> Result<Array<u8, Sum<C::FieldBytesSize, C::FieldBytesSize>>, Self::Error> {

        let encapped_key = PublicKey::<C>::from_sec1_bytes(&encapsulated_key)?;
        let public_point_1 = ProjectivePoint::<C>::from(*encapped_key.as_affine());
        let public_point_2 = ProjectivePoint::<C>::from(*self.sender_public.as_affine());

        let raw_shared_secret_1 = public_point_1 * *self.recipient_private.to_nonzero_scalar();
        let raw_shared_secret_2 = public_point_2 * *self.recipient_private.to_nonzero_scalar();
        
        let raw_shared_secret_1 = elliptic_curve::group::Curve::to_affine(&raw_shared_secret_1).x();
        let raw_shared_secret_2 = elliptic_curve::group::Curve::to_affine(&raw_shared_secret_2).x();

        let raw_shared_secret = raw_shared_secret_1.concat::<C::FieldBytesSize>(raw_shared_secret_2);
        Ok(raw_shared_secret)
    }
}



impl<C: CurveArithmetic + PointCompression, DE> GetSenderPublicKeyBytes for EcdhAuthDecapsulator<C, DE>
where DE: EncodeGenericArray<PublicKey<C>>
{
    type EncodedLen = DE::EncodedLen;

    fn get_sender_public_key_bytes(&self) -> GenericArray<u8, Self::EncodedLen> {
        DE::encode(&self.sender_public)
    }
}
impl<C: CurveArithmetic + PointCompression, DE> GetRecipientPublicKeyBytes for EcdhAuthDecapsulator<C, DE>
where DE: EncodeGenericArray<PublicKey<C>>
{
    type EncodedLen = DE::EncodedLen;

    fn get_recipient_public_key_bytes(&self) -> GenericArray<u8, Self::EncodedLen> {
        DE::encode(&self.recipient_private.public_key())
    }
}










///
/// Factory struct to create encapsulators and decapsulators using MQV
/// with Elliptic Curves implementing the RustCryoto CurveArithmetic traits
/// 
//pub struct EcMqvAuthCapsulator<C,K,L,ED> (PhantomData<C>, PhantomData<K>, PhantomData<L>, PhantomData<ED>);
pub struct EcMqvAuthCapsulator<C,ED> (PhantomData<C>, PhantomData<ED>);

/// Authenticed KEM using Elliptic Curve MQV and compressed SEC1 encoding for the ciphertext 
pub type EcMqvAuthCapsulatorCompressed<C> = EcMqvAuthCapsulator<C, EcCompressedEncoder<C>>;
/// Authenticed KEM using Elliptic Curve MQV and uncompressed SEC1 encoding for the ciphertext
pub type EcMqvAuthCapsulatorUncompressed<C> = EcMqvAuthCapsulator<C, EcUncompressedEncoder<C>>;


//impl<C, K, L, DE> Capsulator for EcMqvAuthCapsulator<C,K,L,DE>
impl<C, DE> Capsulator for EcMqvAuthCapsulator<C,DE>
where 
    DE: EncodeGenericArray<PublicKey<C>> + DecodeSlice<PublicKey<C>> + DecodeSlice<SecretKey<C>> + EncodeGenericArray<SecretKey<C>>, 
    <DE as EncodeGenericArray<PublicKey<C>>>::EncodedLen: ArraySize,  
    C: CurveArithmetic+PointCompression + PrimeCurve,
    C::FieldBytesSize: ModulusSize,
    C::AffinePoint: ToSec1Point<C> + FromSec1Point<C>,    
{
    type Encapsulator = EcMqvAuthEncapsulator<C,DE>;
    type Decapsulator = EcMqvAuthDecapsulator<C,DE>;
    type CiphertextSize = <DE as EncodeGenericArray<PublicKey<C>>>::EncodedLen;
    type SharedKeySize = C::FieldBytesSize;

    fn generate ( _rng: &mut impl CryptoRngCore ) -> (Self::Encapsulator, Self::Decapsulator) {
        todo!()
    }
}






///
/// Struct for creating authenticated encapsulated keys using the MQV primitive
/// 
pub struct EcMqvAuthEncapsulator <C: CurveArithmetic+PointCompression, DE>
{
    sender_private: SecretKey<C>,
    recipient_public: PublicKey<C>,
    phantom: PhantomData<DE>
}

/// Encapsulator using the MQV primitive and a compressed public key in the output
pub type EcMqvAuthEncapsulatorCompressed<C> = EcMqvAuthEncapsulator<C, EcCompressedEncoder<C>>;
/// Encapsulator using the MQV primitive and an uncompressed public key in the output
pub type EcMqvAuthEncapsulatorUncompressed<C> = EcMqvAuthEncapsulator<C, EcUncompressedEncoder<C>>;


//impl<C,K,L,E,DE> FromKeys for EcMqvAuthEncapsulator<C,K,L,E,DE>
impl<C,DE> FromKeys for EcMqvAuthEncapsulator<C,DE>
where   C: CurveArithmetic+PointCompression, 
{
    type PrivateKey = SecretKey<C>;
    type PublicKey = PublicKey<C>;

    fn from_keys ( recipient_public: Self::PublicKey, sender_private: Self::PrivateKey ) -> Self {
        Self { sender_private, recipient_public, phantom: PhantomData }
    }
}



impl<C,DE> Encapsulate<GenericArray<u8,DE::EncodedLen>, Array<u8,C::FieldBytesSize>> for EcMqvAuthEncapsulator<C,DE>
where   C: CurveArithmetic + PointCompression + PrimeCurve,
        C::AffinePoint: ToSec1Point<C> + FromSec1Point<C>,
        FieldBytesSize<C>: ModulusSize,
        DE: EncodeGenericArray<PublicKey<C>>,
{
    type Error = TryFromSliceError;

    fn encapsulate(&self, rng: &mut impl CryptoRngCore) -> Result<(GenericArray<u8,DE::EncodedLen>, Array<u8,C::FieldBytesSize>), Self::Error> {
        
        let mut seed = Array::default();
        rng.fill_bytes(&mut seed);

        let ephemeral_prv = SecretKey::<C>::from_bytes(&seed).unwrap();
        let ephemeral_pub = ephemeral_prv.public_key();

        let raw_shared_secret = mqv2 ( &self.sender_private, &ephemeral_prv, &self.recipient_public, &self.recipient_public);
        let raw_shared_secret = elliptic_curve::group::Curve::to_affine(&raw_shared_secret);
        
        let encapsulated_key = DE::encode(&ephemeral_pub);

        Ok((encapsulated_key, raw_shared_secret.x()))
    }
}

impl<C,DE> EncapsulateDeterministic2<GenericArray<u8,DE::EncodedLen>, Array<u8,C::FieldBytesSize>> for EcMqvAuthEncapsulator<C,DE>
where   C: CurveArithmetic + PointCompression + PrimeCurve,
        C::AffinePoint: ToSec1Point<C> + FromSec1Point<C>,
        FieldBytesSize<C>: ModulusSize,
        DE: EncodeGenericArray<PublicKey<C>>,
{
    type Error = TryFromSliceError;
    type SeedSize = C::FieldBytesSize;

    fn encapsulate_deterministic(&self, seed: &[u8]) -> Result<(GenericArray<u8,DE::EncodedLen>, Array<u8,C::FieldBytesSize>), Self::Error> {
        let seed = Array::try_from(seed)?;
        let ephemeral_prv = SecretKey::<C>::from_bytes(&seed).unwrap();
        let ephemeral_pub = ephemeral_prv.public_key();

        let raw_shared_secret = mqv2 ( &self.sender_private, &ephemeral_prv, &self.recipient_public, &self.recipient_public);
        let raw_shared_secret = elliptic_curve::group::Curve::to_affine(&raw_shared_secret);
        
        let encapsulated_key = DE::encode(&ephemeral_pub);

        Ok((encapsulated_key, raw_shared_secret.x()))
    }
}




impl<C,DE> GetSenderPublicKeyBytes for EcMqvAuthEncapsulator<C,DE>
where C: CurveArithmetic + PointCompression,
    DE: EncodeGenericArray<PublicKey<C>> + DecodeSlice<PublicKey<C>>,
{
    type EncodedLen = <DE as EncodeGenericArray<PublicKey<C>>>::EncodedLen;

    fn get_sender_public_key_bytes(&self) -> GenericArray<u8, Self::EncodedLen> {
        DE::encode(&self.sender_private.public_key())
    }
}
impl<C,DE> GetRecipientPublicKeyBytes for EcMqvAuthEncapsulator<C,DE>
where C: CurveArithmetic + PointCompression,
    DE: EncodeGenericArray<PublicKey<C>> + DecodeSlice<PublicKey<C>>,
{
    type EncodedLen = <DE as EncodeGenericArray<PublicKey<C>>>::EncodedLen;
    fn get_recipient_public_key_bytes(&self) -> GenericArray<u8, Self::EncodedLen> {
        DE::encode(&self.recipient_public)
    }
}






///
/// Struct enabling receipt of a EciesEncapKey and recovery of the shared secret
/// 
pub struct EcMqvAuthDecapsulator <C: CurveArithmetic+PointCompression, ED>
{
    recipient_private: SecretKey<C>,
    sender_public: PublicKey<C>,
    phantom: PhantomData<ED>
}

impl<C: CurveArithmetic + PointCompression, DE> FromKeys for EcMqvAuthDecapsulator<C,DE> 
{
    type PrivateKey = SecretKey<C>;
    type PublicKey = PublicKey<C>;
    
    fn from_keys ( sender_public: Self::PublicKey, recipient_private: Self::PrivateKey ) -> Self {
        Self { recipient_private, sender_public, phantom: PhantomData }
    }
}


impl<'a, C,DE> Decapsulate<GenericArray<u8, DE::EncodedLen>, Array<u8, C::FieldBytesSize>> for EcMqvAuthDecapsulator<C,DE> 
where   C: CurveArithmetic + PointCompression + PrimeCurve,
        C::FieldBytesSize: ModulusSize,
        C::AffinePoint: FromSec1Point<C> + ToSec1Point<C>,
        //DE: EncodePublicKey<PublicKey<C>>,
        DE: EncodeGenericArray<PublicKey<C>>,
{
    type Error = elliptic_curve::Error;

    fn decapsulate(&self, encapsulated_key: &GenericArray<u8, DE::EncodedLen>) -> Result<Array<u8, C::FieldBytesSize>, Self::Error> {
        let encapped_key = PublicKey::<C>::from_sec1_bytes(&encapsulated_key.as_slice())?;
        
        let raw_shared_secret = elliptic_curve::group::Curve::to_affine(&mqv2 ( &self.recipient_private, &self.recipient_private, &self.sender_public, &encapped_key ));
        Ok(raw_shared_secret.x())
    }
}


impl<C,DE> GetSenderPublicKeyBytes for EcMqvAuthDecapsulator<C,DE>
where C: CurveArithmetic + PointCompression,
    DE: EncodeGenericArray<PublicKey<C>> + DecodeSlice<PublicKey<C>>,
{
    type EncodedLen = <DE as EncodeGenericArray<PublicKey<C>>>::EncodedLen;

    fn get_sender_public_key_bytes(&self) -> GenericArray<u8, Self::EncodedLen> {
        DE::encode(&self.sender_public)
    }
}
impl<C,DE> GetRecipientPublicKeyBytes for EcMqvAuthDecapsulator<C,DE>
where C: CurveArithmetic + PointCompression,
    DE: EncodeGenericArray<PublicKey<C>> + DecodeSlice<PublicKey<C>>,
{
    type EncodedLen = <DE as EncodeGenericArray<PublicKey<C>>>::EncodedLen;
    fn get_recipient_public_key_bytes(&self) -> GenericArray<u8, Self::EncodedLen> {
        DE::encode(&self.recipient_private.public_key())
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
    let na = n.encode_field_bytes();

    if na[0] == 1 { // Only bottom bit set...
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


///
/// Factory struct to create encapsulators and decapsulators using one-way Diffie-Hellman
/// with Elliptic Curves implementing the RustCryoto CurveArithmetic traits
/// 
pub struct EcdhKem<C,DE,G = SeedAsScalar, S=EcXonlyEncoder<C>> (PhantomData<C>, PhantomData<DE>, PhantomData<G>, PhantomData<S>);

/// Unauthenticated KEM using elliptic curve diffie Hellman and SEC1 compressed encoding of the ciphertext
pub type EcdhKemCompressed<C,G> = EcdhKem<C, EcCompressedEncoder<C>, G, EcXonlyEncoder<C>>;
pub type EcdhKemCompressed2<C> = EcdhKem<C, EcCompressedEncoder<C>, SeedAsScalar, EcXonlyEncoder<C>>;

/// Unauthenticated KEM using elliptic curve diffie Hellman and SEC1 uncompressed encoding of the ciphertext
pub type EcdhKemUncompressed<C,G> = EcdhKem<C, EcUncompressedEncoder<C>, G, EcXonlyEncoder<C>>;



impl<C, DE,G, S> Capsulator for EcdhKem<C,DE,G, S>
where 
    C: CurveArithmetic+PointCompression,
    C::FieldBytesSize: ModulusSize,
    C::AffinePoint: FromSec1Point<C> + ToSec1Point<C>,
    
    DE: EncodeGenericArray<PublicKey<C>> + DecodeSlice<PublicKey<C>> + DecodeSlice<SecretKey<C>> + EncodeGenericArray<SecretKey<C>>, 
    <DE as EncodeGenericArray<PublicKey<C>>>::EncodedLen: ArraySize,    
    <DE as DecodeSlice<PublicKey<C>>>::Error: Debug,
    //S: SecretPointToBytes<C>,
    S: EncodeHybridArray<AffinePoint<C>>
{
    type Encapsulator = EcdhEncapsulator<C,DE,S,G>;
    type Decapsulator = EcdhDecapsulator<C,DE,S,G>;
    type CiphertextSize = <DE as EncodeGenericArray<PublicKey<C>>>::EncodedLen;
    type SharedKeySize = <S as EncodeHybridArray<AffinePoint<C>>>::EncodedLen;
    
    fn generate ( rng: &mut impl CryptoRngCore ) -> (Self::Encapsulator, Self::Decapsulator) {
        let mut rng = wrapper::RngWrapper::from(rng);

        let private = SecretKey::try_generate_from_rng(&mut rng).unwrap();
        let public = private.public_key();
        (EcdhEncapsulator::from_key(public), EcdhDecapsulator::from_key(private))
    }
}


impl<C,DE,G,S> GenerateCapsulatorFromSeed for EcdhKem<C,DE, G, S>
where 
    C: CurveArithmetic + PointCompression,
    C::FieldBytesSize: ModulusSize + ArraySize,
    C::AffinePoint: FromSec1Point<C> + ToSec1Point<C>,
    DE: EncodeGenericArray<PublicKey<C>> + DecodeSlice<PublicKey<C>> + DecodeSlice<SecretKey<C>> + EncodeGenericArray<SecretKey<C>>, 
    <DE as EncodeGenericArray<PublicKey<C>>>::EncodedLen: ArraySize,    
    <DE as DecodeSlice<PublicKey<C>>>::Error: Debug,
    G: DeriveKeyPairFromSeed<SecretKey<C>, PublicKey=PublicKey<C>>,
    //S: SecretPointToBytes<C>,
    S: EncodeHybridArray<AffinePoint<C>>
{
    type SeedSize = G::SeedSize;
    fn derive_from_seed(ikm: &Array::<u8, Self::SeedSize>) -> (Self::Encapsulator, Self::Decapsulator) {
        let Ok((sk, pk)) = G::derive_keypair_from_seed(ikm) else { panic! ( "Derived failed")};
        (EcdhEncapsulator::from_key(pk), EcdhDecapsulator::from_key(sk))
    }
}

/// 
/// Implementation of the derive key pair from draft-ietf-hpke-pq-01
/// This method is described in SEC1 and also listed in FIPS 186-5 as rejection sampling.
/// 
pub struct SeedAsScalar ();

impl<C> DeriveKeyPairFromSeed<SecretKey<C>> for SeedAsScalar 
where C: Curve + CurveArithmetic, 
        // C::FieldBytesSize: Mul<N>,
        // <C::FieldBytesSize as Mul<N>>::Output: Sub<C::FieldBytesSize>,
        // <C::FieldBytesSize as Mul<N>>::Output: ArraySize,
{
    type SeedSize = C::FieldBytesSize; //Prod<C::FieldBytesSize, N>;
    type PublicKey = PublicKey<C>;
    type Error = ();

    // Seed should be at least Self::SeedSize in length, if seed is longer then it is used if the first part of the seed 
    // does not generate a suitable key pair.
    fn derive_keypair_from_seed( seed: &[u8]) -> Result<(SecretKey<C>, PublicKey<C>), Self::Error> {
        for chunk in seed.chunks(C::FieldBytesSize::USIZE) 
        {
            let Ok(candidate) = Array::try_from(chunk) else { continue };
            let Ok(priv_key) = SecretKey::from_bytes(&candidate) else { continue };
            let pub_key = priv_key.public_key();
            return Ok((priv_key, pub_key))
        }
        //panic!( "unable to generate key")       
        Err(())
    }
}




/// Implementation of ScalarFromBytes function from draft-irtf-cfrg-hybrid-kems-03
/// The scalar is used as the private key
/// This method is equivalent to 
/// - 'Extra Random Bits' method from FIPS 186-5, where the number of extra bits is set to the base order / 2
/// - 
pub struct ReduceSeed;

#[cfg(feature="rustcrypto-p256")]
impl DeriveKeyPairFromSeed<SecretKey<NistP256>> for ReduceSeed
{
    type SeedSize = Sum<<NistP256 as Curve>::FieldBytesSize, Quot<<NistP256 as Curve>::FieldBytesSize, U2>>;
    type PublicKey = PublicKey<NistP256>;
    type Error = ();

    //fn derive_keypair_from_seed( seed: &Array::<u8, Self::SeedSize>) -> (SecretKey<NistP256>, PublicKey<NistP256>) {
    fn derive_keypair_from_seed( seed: &[u8]) -> Result<(SecretKey<NistP256>, PublicKey<NistP256>), Self::Error> {
        use elliptic_curve::bigint::Uint;

        let Ok(seed_as_array) = Array::try_from(seed) else { return Err(())};
        let seed_as_bigint = Uint::<{Self::SeedSize::USIZE/8}>::from_be_byte_array(seed_as_array);
        let mut padded_order2 = Uint::<{Self::SeedSize::USIZE/8}>::default();
        padded_order2.as_mut_limbs()[..<NistP256 as Curve>::ORDER.as_limbs().len()].copy_from_slice(<NistP256 as Curve>::ORDER.as_limbs());
        
        let remainder_bigint = seed_as_bigint.rem(&padded_order2.to_nz().unwrap());

        let remainder_generic_array = remainder_bigint.to_be_byte_array();
        let (_,rem) = remainder_generic_array.split_at(<NistP256 as Curve>::FieldBytesSize::USIZE/2);
        
        let priv_key = SecretKey::from_slice(rem).unwrap();
        let pub_key = priv_key.public_key();
        
        Ok((priv_key, pub_key))
    }

}

#[cfg(feature="rustcrypto-p384")]
impl DeriveKeyPairFromSeed<SecretKey<NistP384>> for ReduceSeed
{
    type SeedSize = Sum<<NistP384 as Curve>::FieldBytesSize, Quot<<NistP384 as Curve>::FieldBytesSize, U2>>;
    type PublicKey = PublicKey<NistP384>;
    type Error = ();

    //fn derive_keypair_from_seed( seed: &Array::<u8, Self::SeedSize>) -> (SecretKey<NistP384>, PublicKey<NistP384>) {
    fn derive_keypair_from_seed( seed: &[u8]) -> Result<(SecretKey<NistP384>, PublicKey<NistP384>), Self::Error> {
        use elliptic_curve::bigint::Uint;

        let Ok(seed_as_array) = Array::try_from(seed) else { return Err(())};
        let seed_as_bigint = Uint::<{Self::SeedSize::USIZE/8}>::from_be_byte_array(seed_as_array);
        
        let mut padded_order2 = Uint::<{Self::SeedSize::USIZE/8}>::default();
        padded_order2.as_mut_limbs()[..<NistP384 as Curve>::ORDER.as_limbs().len()].copy_from_slice(<NistP384 as Curve>::ORDER.as_limbs());

        let remainder_bigint = seed_as_bigint.rem(&padded_order2.to_nz().unwrap());

        let remainder_generic_array = remainder_bigint.to_be_byte_array();
        let (_,rem) = remainder_generic_array.split_at(<NistP384 as Curve>::FieldBytesSize::USIZE/2);
        
        let priv_key = SecretKey::from_slice(rem).unwrap();
        let pub_key = priv_key.public_key();
        
        Ok((priv_key, pub_key))
    }
}




//////////////
// Implementation of KEM traits from ml-kem
// 
// 

// impl<C: CurveArithmetic+PointCompression, K: EcdhCombiner, L: ArrayLength<u8>, ED> ml_kem::kem::Encapsulate<hybrid_array::Array<u8,ED::EncodedLen>, hybrid_array::Array<u8,L>> for EcdhEncapsulator <C, K, L, ED>
// where   C: CurveArithmetic + PointCompression,
//         K: EcdhCombiner<> + Clone,
//         L: ArrayLength<u8> + Debug + ArraySize,
//         <C as CurveArithmetic>::AffinePoint: ToEncodedPoint<C> + FromEncodedPoint<C>,
//         FieldBytesSize<C>: ModulusSize,
//         ED: Debug + EncodePublicKey<PublicKey<C>> + DecodePublicKey<elliptic_curve::PublicKey<C>>,
//         <ED as EncodePublicKey<PublicKey<C>>>::EncodedLen: Debug,
//         <ED as EncodePublicKey<elliptic_curve::PublicKey<C>>>::EncodedLen: hybrid_array::ArraySize
// {
//     type Error = kem::Error;
//     fn encapsulate(&self, rng: &mut impl rand_core::CryptoRngCore) -> Result<(hybrid_array::Array<u8,ED::EncodedLen>, hybrid_array::Array<u8,L>), Self::Error> {
//         let (ek, ss) = self.try_encap( rng, &self.key.unwrap() )?;
//         Ok((hybrid_array::Array::try_from(ek.bytes.as_slice()).unwrap(), hybrid_array::Array::try_from(ss.as_bytes()).unwrap()))
//     }
// }






// impl<C,K,L,ED> ml_kem::KemCore for EcdhKem<C,K,L,ED>
// where L: ArrayLength<u8> + Debug + hybrid_array::ArraySize + PartialEq,
//     K: EcdhCombiner + Default + Clone,
//     C: CurveArithmetic + PointCompression,
//     <C as CurveArithmetic>::AffinePoint: ToEncodedPoint<C>, 
//     <C as elliptic_curve::Curve>::FieldBytesSize: ModulusSize,
//     <C as CurveArithmetic>::AffinePoint: FromEncodedPoint<C>,
//     ED: Debug + EncodePublicKey<elliptic_curve::PublicKey<C>> + DecodePrivateKey<elliptic_curve::SecretKey<C>> + DecodePublicKey<elliptic_curve::PublicKey<C>>,
//     <ED as EncodePublicKey<elliptic_curve::PublicKey<C>>>::EncodedLen: Debug,
//     <ED as EncodePublicKey<elliptic_curve::PublicKey<C>>>::EncodedLen: PartialEq,
//     <ED as EncodePublicKey<elliptic_curve::PublicKey<C>>>::EncodedLen: hybrid_array::ArraySize
// {
//     type CiphertextSize = ED::EncodedLen;
//     type SharedKeySize = L;
//     type DecapsulationKey = EcdhDecapsulator<C,K,L,ED>;
//     type EncapsulationKey = EcdhEncapsulator<C,K,L,ED>;

//     fn generate(rng: &mut impl rand_core::CryptoRngCore) -> (Self::DecapsulationKey, Self::EncapsulationKey) {
//         let private = elliptic_curve::SecretKey::random(rng);
//         let public = private.public_key();
//         (EcdhDecapsulator::new(private), EcdhEncapsulator::from(public))
//     }
//     // fn generate_deterministic(_d: &ml_kem::B32, _z: &ml_kem::B32)
//     //         -> (Self::DecapsulationKey, Self::EncapsulationKey) {
//     //     todo!();
//     // }
// }

// impl<C: CurveArithmetic+PointCompression, K: EcdhCombiner, L: ArrayLength<u8>, ED> ml_kem::EncodedSizeUser for EcdhDecapsulator<C,K,L,ED >
// where K: EcdhCombiner + Default,
//     ED: DecodePrivateKey<SecretKey<C>>,
// {
//     type EncodedSize = U32;
//     fn as_bytes(&self) -> ml_kem::Encoded<Self> {
//         todo!()
//     }
//     fn from_bytes(_enc: &ml_kem::Encoded<Self>) -> Self {
//         // let ga = GenericArray::from_slice(&_enc);
//         // let secret_key = elliptic_curve::SecretKey::<C>::from_bytes ( &ga ).unwrap();
//         let secret_key = ED::decode(_enc).unwrap();
//         Self { kdf: K::default(), private: secret_key, phantom: PhantomData, phantom1: PhantomData}
//     }
// }


// impl<C: CurveArithmetic+PointCompression, K: EcCombiner, L: ArrayLength<u8>, ED> ml_kem::EncapsulateDeterministic<hybrid_array::Array<u8,ED::EncodedLen>, hybrid_array::Array<u8,L>> for EcdhEncapsulator <C,K, L,ED>
// where L:ArrayLength<u8> + Debug + ArraySize,
//     K: EcCombiner,
//     ED: EncodePublicKey<PublicKey<C>>,
//     ED::EncodedLen: ArraySize,
// {
//     type Error = kem::Error;
//     fn encapsulate_deterministic(&self, _m: &ml_kem::B32) -> Result<(hybrid_array::Array<u8,ED::EncodedLen>, hybrid_array::Array<u8,L>), Self::Error> {
//         todo!()
//     }
// }

// impl<C: CurveArithmetic + PointCompression, K: MqvAuthCombiner, L: ArrayLength<u8>, DE> PrivateKeyInit<SecretKey<C>> for EcMqvAuthDecapsulator<C,K,L,DE> 
//     where K: Default
// {
//     fn new(private_key: SecretKey<C>) -> Self {
//         Self { private: private_key, kdf: K::default(), sender_key: None, phantom: PhantomData, phantom2: PhantomData}
//     }
// }
// impl<'a, C,K,L,DE> AuthDecapsulator<EcEncapKey<C,L,DE>> for EcMqvAuthDecapsulator<C,K,L,DE> 
// where   C: CurveArithmetic + PointCompression + PrimeCurve,
//         L: ArrayLength<u8> + Debug,
//         K: MqvAuthCombiner<> + Clone,
//         <C as Curve>::FieldBytesSize: ModulusSize,
//         <C as CurveArithmetic>::AffinePoint: FromEncodedPoint<C> + ToEncodedPoint<C>,
//         DE: Debug+ EncodePublicKey<PublicKey<C>> + DecodePublicKey<elliptic_curve::PublicKey<C>>,
//         <DE as EncodePublicKey<PublicKey<C>>>::EncodedLen: Debug
// {
//     ///
//     /// Decapsulate the provided Encapsulated key
//     /// 
//     fn try_auth_decap(&self, encapped_key: &EcEncapKey<C,L,DE>, sender_static_public_key: &PublicKey<C>) 
//         -> Result<SharedSecret<EcEncapKey<C,L,DE>>, kem::Error> 
//     {
//         use elliptic_curve::group::Curve;
//         let raw_shared_secret = mqv2 ( &self.private, &self.private, sender_static_public_key, &encapped_key.to_public_key()? ).to_affine();
//         let processed_shared_secret = self.kdf.combine(&raw_shared_secret.x().as_ref(), &DE::encode(&encapped_key.to_public_key()?), &DE::encode(&self.private.public_key()), &DE::encode(sender_static_public_key));
//         Ok(SharedSecret::new(processed_shared_secret))
//     }
// }


// impl<K,L,DE> GenerateCapsulatorFromSeed for EcdhKem<p256::NistP256,K,L,DE, ReduceSeed>
// where 
//     K: EcdhCombiner + Default + Clone,
//     L: ArraySize + ArrayLength<u8>,
//     DE: EncodePublicKey<elliptic_curve::PublicKey<p256::NistP256>> + DecodePublicKey<elliptic_curve::PublicKey<p256::NistP256>> + DecodePrivateKey<elliptic_curve::SecretKey<p256::NistP256>> + EncodePrivateKey<elliptic_curve::SecretKey<p256::NistP256>>, 
//     <DE as EncodePublicKey<elliptic_curve::PublicKey<p256::NistP256>>>::EncodedLen: ArraySize,    
// {
//     type SeedSize = U48;

//     fn generate_from_seed(seed: &Array::<u8, Self::SeedSize>) -> (Self::Encapsulator, Self::Decapsulator) {
//         let seed_as_generic_array = GenericArray::<u8,U48>::from_slice(seed);
//         let seed_as_bigint = elliptic_curve::bigint::U384::from_be_byte_array(*seed_as_generic_array);
//         let order_as_bigint = p256::NistP256::ORDER;
//         let order_as_generic_array = order_as_bigint.to_be_byte_array();
//         // let mut order_vec = [0u8; 16].to_vec();
//         // order_vec.extend_from_slice(&order_as_generic_array);
//         let padded_order = GenericArray::<u8,U16>::default().concat(order_as_generic_array);
        
//         //let long_order = elliptic_curve::bigint::U384::from_be_byte_array(*GenericArray::from_slice(&order_vec));
//         let long_order_bigint = elliptic_curve::bigint::U384::from_be_byte_array(padded_order);
//         let non_zero_order = elliptic_curve::bigint::NonZero::from_uint(long_order_bigint);
//         let remainder_bigint = seed_as_bigint.rem(&non_zero_order);
//         let remainder_generic_array = remainder_bigint.to_be_byte_array();
//         let remainder_small_generic_array = GenericArray::from_slice(&remainder_generic_array[16..48]);
        
//         let priv_key = elliptic_curve::SecretKey::from_bytes(remainder_small_generic_array).unwrap();
//          (EcdhEncapsulator::from_key(priv_key.public_key()), EcdhDecapsulator::from_key(priv_key))
//     }

// }
// impl<K,L,DE> GenerateCapsulatorFromSeed for EcdhKem<p384::NistP384,K,L,DE,ReduceSeed>
// where 
//     //C: CurveArithmetic+PointCompression,
//     K: EcdhCombiner + Default + Clone,
//     // <C as elliptic_curve::Curve>::FieldBytesSize: ModulusSize,
//     // <C as CurveArithmetic>::AffinePoint: FromEncodedPoint<C>,
//     // <C as CurveArithmetic>::AffinePoint: ToEncodedPoint<C>,
//     L: ArraySize + ArrayLength<u8>,

//     DE: EncodePublicKey<elliptic_curve::PublicKey<p384::NistP384>> + DecodePublicKey<elliptic_curve::PublicKey<p384::NistP384>> + DecodePrivateKey<elliptic_curve::SecretKey<p384::NistP384>> + EncodePrivateKey<elliptic_curve::SecretKey<p384::NistP384>>, 
//     <DE as EncodePublicKey<elliptic_curve::PublicKey<p384::NistP384>>>::EncodedLen: ArraySize,
// {
//     type SeedSize = U72;

//     fn generate_from_seed(seed: &Array::<u8, Self::SeedSize>) -> (Self::Encapsulator, Self::Decapsulator) {
//         let ba = GenericArray::<u8,U72>::from_slice(seed);
//         let xx = elliptic_curve::bigint::U576::from_be_byte_array(*ba);
//         let order = p384::NistP384::ORDER;
//         let yy = order.to_be_byte_array();
//         let mut order_vec = [0u8; 24].to_vec();
//         order_vec.extend_from_slice(&yy);
//         let long_order = elliptic_curve::bigint::U576::from_be_byte_array(*GenericArray::from_slice(&order_vec));
//         let non_zero_order = elliptic_curve::bigint::NonZero::from_uint(long_order);
//         let sj = xx.rem(&non_zero_order).to_be_byte_array();
//         let d = GenericArray::from_slice(&sj[24..72]);
//         let priv_key = elliptic_curve::SecretKey::from_bytes(d).unwrap();
//          (EcdhEncapsulator::from_key(priv_key.public_key()), EcdhDecapsulator::from_key(priv_key))
//     }
// }




// impl<C: CurveArithmetic+PointCompression, K: EcdhCombiner,L: ArrayLength<u8>, DE>  EcdhKem<C,K,L,DE>
// where DE: EncodePublicKey<elliptic_curve::PublicKey<C>>,
//     <C as elliptic_curve::Curve>::FieldBytesSize: ModulusSize,
//     <C as CurveArithmetic>::AffinePoint: FromEncodedPoint<C>,
//     <C as CurveArithmetic>::AffinePoint: ToEncodedPoint<C>,
//     //<DE as EncodePublicKey<elliptic_curve::PublicKey<C>>>::EncodedLen: Debug
// {
//     pub fn new_decapsulator_with_params (private: SecretKey<C>, kdf: K) -> EcdhDecapsulator<C,K,L,DE> {
//         //return EcdhDecapsulator::<C,K,L,DE>::new_with_params (private, kdf);
//         EcdhDecapsulator { recipient_private: private, kdf: kdf, phantom: PhantomData, phantom1: PhantomData }
//     }
//     // pub fn new_encapsulator_with_params ( public: PublicKey<C>, kdf: K) -> EcdhEncapsulator<C,K,L,DE> {
//     //     return EcdhEncapsulator::<C,K,L,DE>::new_(kdf)
//     // }
// }



// impl<C: CurveArithmetic+PointCompression, K: EcdhAuthCombiner+Default,L: ArrayLength<u8>, DE> AuthCapsulator for EcdhKem<C,K,L,DE>{
//     type AuthSecretKey = SecretKey<C>;  
//     type AuthEncapsulator = EcdhAuthEncapsulator<C,K,L,DE>;
//     type AuthDecapsulator = EcdhAuthDecapsulator<C,K,L,DE>;
// }




// impl<K,L,DE> GenerateCapsulatorFromSeed for EcdhKem<p256::NistP256,K,L,DE, SeedAsScalar>
// where 
//     K: EcdhCombiner + Default + Clone,
//     L: ArraySize + ArrayLength<u8>,

//     DE: EncodePublicKey<elliptic_curve::PublicKey<p256::NistP256>> + DecodePublicKey<elliptic_curve::PublicKey<p256::NistP256>> + DecodePrivateKey<elliptic_curve::SecretKey<p256::NistP256>> + EncodePrivateKey<elliptic_curve::SecretKey<p256::NistP256>>, 
//     <DE as EncodePublicKey<elliptic_curve::PublicKey<p256::NistP256>>>::EncodedLen: ArraySize,    
// {
//     type SeedSize = U48;
//     fn generate_from_seed(seed: &Array::<u8, Self::SeedSize>) -> (Self::Encapsulator, Self::Decapsulator) {
//         let seed2 = &seed[0..32];
//         let priv_key = elliptic_curve::SecretKey::from_bytes(&GenericArray::from_slice(seed2)).unwrap();
//         (EcdhEncapsulator::from_key(priv_key.public_key()), EcdhDecapsulator::from_key(priv_key))
//     }
// }
// impl<C: CurveArithmetic + PointCompression, K: EcdhAuthCombiner + Default, L: ArrayLength<u8>, DE: EncodePublicKey<PublicKey<C>>> EncodedSizeUser2 for EcdhAuthDecapsulator<C,K,L, DE> {
//     type EncodedSize = DE::EncodedLen;
//     fn as_bytes(&self) -> crate::Encoded<Self> {
//         todo!()
//     }
//     fn from_bytes(enc: &crate::Encoded<Self>) -> Self {
//         todo!()
//     }
// }

// impl<C: CurveArithmetic+PointCompression, K: EcdhCombiner, L: ArrayLength<u8>, ED> std::fmt::Debug for EcdhDecapsulator<C,K,L,ED>
// {
//     fn fmt(&self, _f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
//         todo!()
//     }
// }

// impl<C: CurveArithmetic+PointCompression, K: EcdhCombiner, L: ArrayLength<u8>, ED> PartialEq for EcdhDecapsulator<C,K,L,ED>
// {
//     fn eq(&self, _other: &Self) -> bool {
//         todo!()
//     }
// }
// impl<C: CurveArithmetic + PointCompression, K: EcdhCombiner, L: ArrayLength<u8>, ED> EcdhDecapsulator<C,K,L,ED> {
//     /// Create a Decapsulator from a private key and kdf, which must match the recipient public key and kdf used 
//     /// during the encapsulation phase
//     pub fn new_with_params (private: SecretKey<C>, kdf: K) -> Self {
//         EcdhDecapsulator { private, kdf, phantom: PhantomData,phantom1: PhantomData }
//     }
// }

// impl<C: CurveArithmetic + PointCompression, K: EcdhCombiner + Default, L: ArrayLength<u8>, DE> From<SecretKey<C>> for EcdhDecapsulator<C,K,L,DE> {
//     /// Create a Decapsulator from a private key and kdf, which must match the recipient public key and kdf used 
//     /// during the encapsulation phase
//     fn from(value: SecretKey<C>) -> Self {
//         Self { private: value, kdf: K::default(), phantom: PhantomData, phantom1: PhantomData }
//     }
// }
// impl<C,K,L,DE> Decapsulator<EcEncapKey<C,L,DE>> for EcdhDecapsulator<C,K,L,DE> 
// where   C: CurveArithmetic + PointCompression,
//         K: EcdhCombiner<> + Clone, //+ OutputSizeUser,
//         L: ArrayLength<u8> + Debug,
//         <C as Curve>::FieldBytesSize: ModulusSize,
//         <C as CurveArithmetic>::AffinePoint: FromEncodedPoint<C> + ToEncodedPoint<C>,
//         DE: Debug + EncodePublicKey<PublicKey<C>> + DecodePublicKey<elliptic_curve::PublicKey<C>>,
//         <DE as EncodePublicKey<PublicKey<C>>>::EncodedLen: Debug
// {
//     ///
//     /// Decapsulate the provided Encapsulated key
//     /// 
//     fn try_decap(&self, encapped_key: &EcEncapKey<C,L,DE>) -> Result<SharedSecret<EcEncapKey<C,L,DE>>, kem::Error> {

//         let public_point = ProjectivePoint::<C>::from(*encapped_key.to_public_key()?.as_affine());
        
//         let raw_shared_secret = public_point * *self.private.to_nonzero_scalar();
//         let raw_shared_secret = elliptic_curve::group::Curve::to_affine(&raw_shared_secret);

//         let shared_secret = self.kdf.combine(&raw_shared_secret.x().as_ref(), raw_shared_secret.to_encoded_point(false).y().unwrap(), &encapped_key.bytes, &DE::encode(&self.private.public_key()));

//         Ok(SharedSecret::new(shared_secret))
//     }
// }
// impl<C,K,L,E,DE> PrivateKeyInit<SecretKey<C>> for EcMqvAuthEncapsulator<C,K,L,E,DE>
// where   C: CurveArithmetic+PointCompression, 
//         K: MqvAuthCombiner + Default,
//         E: ArrayLength<u8>,
//         L: ArrayLength<u8>,
// {
//     fn new(private_key: SecretKey<C>) -> Self {
//         Self { kdf: K::default(), sec_key: private_key, _phantom: PhantomData, _phantom3: PhantomData, _phantom4: PhantomData, recip_key: None}
//     }
// }
// impl<C,K,L,E,DE> Encapsulator<EcEncapKey<C,L,DE>> for EcMqvAuthEncapsulator<C,K,L,E,DE>
// where   C: CurveArithmetic + PointCompression + PrimeCurve,
//         K: MqvAuthCombiner<> + Clone,
//         E: ArrayLength<u8> + Debug,
//         L: ArrayLength<u8> + Debug,
//         <C as CurveArithmetic>::AffinePoint: ToEncodedPoint<C> + FromEncodedPoint<C>,
//         FieldBytesSize<C>: ModulusSize,
//         DE: Debug + EncodePublicKey<PublicKey<C>> + DecodePublicKey<elliptic_curve::PublicKey<C>>,
//         <DE as EncodePublicKey<PublicKey<C>>>::EncodedLen: Debug

// {
//     /// Generate and encapsulate a key using the given recipients public key
//     /// Returns the encapsulated key, as well as the shared secret
//     fn try_encap<R: CryptoRng + RngCore>(
//         &self,
//         csprng: &mut R,
//         //recip_pubkey: &EK::RecipientPublicKey
//         recip_pubkey: &<EcEncapKey<C,L,DE> as EncappedKey>::RecipientPublicKey
//     ) -> Result<(EcEncapKey<C,L,DE>, SharedSecret<EcEncapKey<C,L,DE>>), kem::Error> 
//     {
//         let ( encoded_ephemeral_public_key, ephemeral_prv ) = EcEncapKey::<C,L,DE>::generate ( csprng );

//         let raw_shared_secret = mqv2 ( &self.sec_key, &ephemeral_prv, recip_pubkey, recip_pubkey);
//         let raw_shared_secret = elliptic_curve::group::Curve::to_affine(&raw_shared_secret);
        
//         let derived_shared_secret = self.kdf.combine(&raw_shared_secret.x().as_ref(), &DE::encode(&encoded_ephemeral_public_key.to_public_key()?), &DE::encode(&recip_pubkey), &DE::encode(&self.sec_key.public_key()) );

//         Ok((encoded_ephemeral_public_key, SharedSecret::new(derived_shared_secret)))
//     }
// }


// impl<C,K,L,DE> PrivateKeyInit<SecretKey<C>> for EcdhAuthEncapsulator<C,K,L,DE> 
// where   C: CurveArithmetic+PointCompression, 
//         K: EcdhAuthCombiner + Default,
//         L: ArrayLength<u8>
// {
//     /// Create a new Encapsulator struct using the given kdf and static secret key
//     fn new (sec_key: SecretKey<C>) -> Self {
//         EcdhAuthEncapsulator { kdf: K::default(), sec_key, _phantom4: PhantomData, recip_pub: None, _phantom5: PhantomData}
//     }
//}
// impl<C,K,L,DE> Encapsulator<EcEncapKey<C,L,DE>> for EcdhAuthEncapsulator<C,K,L,DE>
// where   C: CurveArithmetic + PointCompression + PrimeCurve,
//         K: EcdhAuthCombiner<> + Clone,
//         <C as CurveArithmetic>::AffinePoint: ToEncodedPoint<C> + FromEncodedPoint<C>,
//         FieldBytesSize<C>: ModulusSize,
//         L: ArrayLength<u8> + Debug,
//         DE: Debug + EncodePublicKey<PublicKey<C>> + DecodePublicKey<elliptic_curve::PublicKey<C>>,
//         <DE as EncodePublicKey<PublicKey<C>>>::EncodedLen: Debug,
// {
//     /// Generate and encapsulate a key using the given recipients public key
//     /// Returns the encapsulated key, as well as the shared secret
//     fn try_encap<R: CryptoRng + RngCore>(
//         &self,
//         csprng: &mut R,
//         recip_pubkey: &<EcEncapKey<C,L,DE> as EncappedKey>::RecipientPublicKey
//     ) -> Result<(EcEncapKey<C,L,DE>, SharedSecret<EcEncapKey<C,L,DE>>), kem::Error> 
//     {
//         let ( encoded_ephemeral_public_key, ephemeral_prv ) = EcEncapKey::<C,L,DE>::generate ( csprng );
//         let public_point = recip_pubkey.to_projective();
//         let raw_shared_secret_1 = public_point * *ephemeral_prv.to_nonzero_scalar();
//         let raw_shared_secret_2 = public_point * *self.sec_key.to_nonzero_scalar();
        
//         let raw_shared_secret_1 = elliptic_curve::group::Curve::to_affine(&raw_shared_secret_1);
//         let raw_shared_secret_2 = elliptic_curve::group::Curve::to_affine(&raw_shared_secret_2);
        
//         let derived_shared_secret = self.kdf.combine(&raw_shared_secret_1.x().as_ref(), &raw_shared_secret_2.x().as_ref(), &DE::encode(&ephemeral_prv.public_key()), &DE::encode(recip_pubkey), &DE::encode(&self.sec_key.public_key()));

//         Ok((encoded_ephemeral_public_key, SharedSecret::new(derived_shared_secret)))
//     }
// }


// impl<C> Debug for EcCompressedEncoder<C>
// {
//     fn fmt(&self, _f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
//         todo!()
//     }
// }
// impl<C> Debug for EcUncompressedEncoder<C>
// {
//     fn fmt(&self, _f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
//         todo!()
//     }
// }
// impl<C> Debug for EcRawEncoder<C>
// {
//     fn fmt(&self, _f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
//         todo!()
//     }
//}
// impl<C,K,L,E> EncodePublicKey<PublicKey<C>> for EcdhEncapsulator<C,K,L,E>
//     where   C: CurveArithmetic+PointCompression, 
//         <C as elliptic_curve::Curve>::FieldBytesSize: ModulusSize,
//         K: DhKemKdf + Default, 
//         E: ArrayLength<u8>,
//         L: ArrayLength<u8>,
//         <C as CurveArithmetic>::AffinePoint: FromEncodedPoint<C>,
//         <C as CurveArithmetic>::AffinePoint: ToEncodedPoint<C>
// {
//     type EncodedLen = E;
//     fn encode(public_key: &PublicKey<C>) -> GenericArray<u8, Self::EncodedLen> {
//         //let b = public_key.as_bytes();
//         //let g: &GenericArray<u8, U32> = b.into();
//         let is_compressed = E::USIZE == CompressedPointSize::<C>::to_usize();

//         let ephemeral_public_encoded = elliptic_curve::sec1::ToEncodedPoint::to_encoded_point(public_key, is_compressed);
//         let byte_array = GenericArray::from_slice(ephemeral_public_encoded.as_bytes());
//         byte_array.clone()
//     }
// }

// impl<C,K,L,DE> Clone for EcdhEncapsulator<C,K,L,DE> 
// where   C: CurveArithmetic+PointCompression, 
//         K: EcdhCombiner + Default, 
//         L: ArrayLength<u8>,
//         K: Clone,
// {
//     fn clone(&self) -> Self {
//         Self{ kdf: self.kdf.clone(), recipient_public: self.recipient_public.clone(), _phantom2: PhantomData, _phantom4: PhantomData, _phantom5: PhantomData }
//     }
// }
// impl<C: CurveArithmetic+PointCompression, K: EcdhCombiner, L: ArrayLength<u8>, ED> std::fmt::Debug for EcdhEncapsulator<C,K,L,ED>
// {
//     fn fmt(&self, _f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
//         todo!()
//     }
// }

// impl<C: CurveArithmetic+PointCompression, K: EcdhCombiner, L: ArrayLength<u8>, ED> PartialEq for EcdhEncapsulator<C,K,L,ED>
// {
//     fn eq(&self, _other: &Self) -> bool {
//         todo!()
//     }
// }

// impl<C,K,L,DE> Encapsulator<EcEncapKey<C,L,DE>> for EcdhEncapsulator<C,K,L,DE>
// where   C: CurveArithmetic + PointCompression,
//         //K: DhKemKdf<SharedSecret=ProjectivePoint<C>, PublicKey=PublicKey<C>> + Clone,
//         K: EcdhCombiner<> + Clone,
//         //E: ArrayLength<u8> + Debug,
//         L: ArrayLength<u8> + Debug,
//         <C as CurveArithmetic>::AffinePoint: ToEncodedPoint<C> + FromEncodedPoint<C>,
//         FieldBytesSize<C>: ModulusSize,
//         DE: Debug + EncodePublicKey<PublicKey<C>> + DecodePublicKey<elliptic_curve::PublicKey<C>>,
//         <DE as EncodePublicKey<PublicKey<C>>>::EncodedLen: Debug,
// {
//     /// Generate and encapsulate a key using the given recipients public key
//     /// Returns the encapsulated key, as well as the shared secret
//     fn try_encap<R: CryptoRng + RngCore>(
//         &self,
//         csprng: &mut R,
//         //recip_pubkey: &EK::RecipientPublicKey
//         recip_pubkey: &<EcEncapKey<C,L,DE> as EncappedKey>::RecipientPublicKey
//     ) -> Result<(EcEncapKey<C,L,DE>, SharedSecret<EcEncapKey<C,L,DE>>), kem::Error> {
    
//         // create a new EC key pair for this encapsulation using the provided rng
//         let (encoded_ephemeral_public_key, ephemeral_prv) = EcEncapKey::<C,L,DE>::generate(csprng);
        
//         // perform the diffie-hellman action by multiplying the public and private keys
//         let raw_shared_secret = recip_pubkey.to_projective() * *ephemeral_prv.to_nonzero_scalar();
//         let raw_shared_secret = elliptic_curve::group::Curve::to_affine(&raw_shared_secret);
//         let raw_shared_secret2 = raw_shared_secret.to_encoded_point(false);
        
//         let derived_shared_secret = self.kdf.combine(&raw_shared_secret.x().as_ref(), raw_shared_secret2.y().unwrap(), &DE::encode(&ephemeral_prv.public_key()), &DE::encode(recip_pubkey));

//         Ok((encoded_ephemeral_public_key, SharedSecret::new(derived_shared_secret)))
//     }
// }
// impl<C,K,L,DE> EcdhAuthEncapsulator<C,K,L,DE> 
// where   C: CurveArithmetic+PointCompression, 
//         K: EcdhAuthCombiner + Default,
//         L: ArrayLength<u8>,
// {
//     pub fn new2 (sec_key: SecretKey<C>, recip_pub: PublicKey<C>) -> Self {
//         Self { kdf: K::default(), sec_key, _phantom4: PhantomData, recip_pub, _phantom5: PhantomData }
//     }
//}


  

// #[derive(Debug)]
// pub struct EcEncapKey <C,L,ED> 
// where   C: CurveArithmetic, 
//         L: ArrayLength<u8>, 
//         ED: EncodePublicKey<PublicKey<C>>,
// { 
//     bytes: GenericArray<u8, ED::EncodedLen>, 
//     phantom: PhantomData<L>,
//     phantom2: PhantomData<C>,
// }

// /// Type representing an uncompressed encapsulated key. For C and L see EcEncapKey
// pub type EcEncapKeyUncompressed<C,L> = EcEncapKey<C,L,EcUncompressedEncoder<C>>;
// /// Type representing a compressed encapsulated key. For C and L see EcEncapKey
// pub type EcEncapKeyCompressed<C,L> = EcEncapKey<C,L,EcCompressedEncoder<C>>;


// ///
// /// Implementation of trait EncappedKey. Provides functions to import and export an EcEncapKey as a byte array
// /// 
// impl <C, L, ED> EncappedKey for EcEncapKey<C,L,ED> 
// where L: ArrayLength<u8> + std::fmt::Debug,
//     <C as Curve>::FieldBytesSize: ModulusSize,
//     <C as CurveArithmetic>::AffinePoint: FromEncodedPoint<C>,
//     C: CurveArithmetic + elliptic_curve::point::PointCompression,
//     <C as CurveArithmetic>::AffinePoint: ToEncodedPoint<C>,
//     ED: Debug + EncodePublicKey<PublicKey<C>>,
//     <ED as EncodePublicKey<PublicKey<C>>>::EncodedLen: Debug
// {
//     type EncappedKeySize = ED::EncodedLen;
//     type SharedSecretSize = L;
//     type SenderPublicKey = PublicKey<C>;
//     type RecipientPublicKey = PublicKey<C>;

//     fn from_bytes(bytes: &GenericArray<u8, Self::EncappedKeySize>) -> Result<Self, kem::Error> {
//         println! ( "EncappedKeySize = {}", Self::EncappedKeySize::ISIZE);
//         Ok(EcEncapKey { bytes: bytes.clone(), phantom: PhantomData, phantom2: PhantomData})
//     }
// }

// /// Dereference coersion to a byte slice
// impl <C,L,ED> AsRef<[u8]> for EcEncapKey<C,L,ED> 
// where   C: CurveArithmetic, 
//         L: ArrayLength<u8>, 
//         //E: ArrayLength<u8>,
//         <C as Curve>::FieldBytesSize: ModulusSize,
//         ED: EncodePublicKey<PublicKey<C>>,
// {
//     /// Retrieve reference to encoded key as a byte slice
//     fn as_ref(&self) -> &[u8] {
//         self.bytes.as_slice()
//     }
// }

// ///
// /// Functions converting between an EnEncapKey and the raw x and y coordinates
// /// 
// impl <C, L, ED> EcEncapKey<C,L,ED> 
// where   C: CurveArithmetic  + PointCompression,
//         L: ArrayLength<u8> + Debug, 
//         //E: ArrayLength<u8> + Debug,
//         <C as elliptic_curve::Curve>::FieldBytesSize: ModulusSize,
//         <C as CurveArithmetic>::AffinePoint: FromEncodedPoint<C>,
//         <C as CurveArithmetic>::AffinePoint: ToEncodedPoint<C>,
//         ED: Debug + EncodePublicKey<PublicKey<C>> + DecodePublicKey<PublicKey<C>>,
//         <ED as EncodePublicKey<PublicKey<C>>>::EncodedLen: Debug,
// {
//     ///
//     /// Allows for the extraction of x and y components of the public key encapsulated in the struct
//     /// 
//     pub fn to_encoded_point(&self) -> Result<sec1::EncodedPoint<C>, kem::Error> {
//         return sec1::EncodedPoint::<C>::from_bytes(&self.bytes).map_err(|_e|kem::Error);
//     }
//     ///
//     /// Create an EcEncapKey from an x and y coordinate supplied in raw byte form
//     /// 
//     pub fn from_x_y ( x: &[u8], y: &[u8]) -> EcEncapKey<C,L,ED> {
//         let encoded_point = elliptic_curve::sec1::EncodedPoint::<C>::from_affine_coordinates(
//             GenericArray::from_slice(&x), GenericArray::from_slice(&y), false);
        
//         EcEncapKey { bytes: GenericArray::from_slice(encoded_point.as_bytes()).clone(), phantom: PhantomData, phantom2: PhantomData }
//     }
//     ///
//     /// Covert the encapsulated key to a PublicKey
//     /// 
//     pub fn to_public_key (&self) -> Result<PublicKey::<C>, kem::Error>{
//         //PublicKey::<C>::from_sec1_bytes(&self.bytes).map_err(|_e|kem::Error)
//         ED::decode(&self.bytes).map_err(|_e|kem::Error)
//     }

//     ///
//     /// Generate a new key and return the encoded version and private key
//     /// 
//     pub fn generate<R: CryptoRng + RngCore> ( csprng: &mut R )-> ( EcEncapKey<C,L,ED>, SecretKey<C> )
//     {
//         let ephemeral_prv = SecretKey::<C>::random(csprng);
//         ( Self::from(ephemeral_prv.public_key()), ephemeral_prv)
//     }
// }




// /// Convert from an Elliptic Curve PublicKey to an EcEncapKey
// impl <C, L, ED> From<PublicKey<C>> for EcEncapKey<C,L,ED>
// where   C: CurveArithmetic + PointCompression,
//         L: ArrayLength<u8> + Debug,
//         <C as Curve>::FieldBytesSize: ModulusSize,
//         <C as CurveArithmetic>::AffinePoint: FromEncodedPoint<C> + ToEncodedPoint<C>,
//         ED: Debug + EncodePublicKey<PublicKey<C>>,
//         <ED as EncodePublicKey<PublicKey<C>>>::EncodedLen: Debug,
// {
//     fn from(value: elliptic_curve::PublicKey<C>) -> Self {
//         let byte_array = ED::encode(&value);
//         EcEncapKey { bytes: byte_array, phantom: PhantomData, phantom2: PhantomData }
//     }
// }

// impl <C, L, ED> TryInto<PublicKey<C>> for EcEncapKey<C,L,ED>
// where   C: CurveArithmetic + PointCompression,
//         L: ArrayLength<u8> + Debug,
//         <C as Curve>::FieldBytesSize: ModulusSize,
//         <C as CurveArithmetic>::AffinePoint: FromEncodedPoint<C>,
//         <C as CurveArithmetic>::AffinePoint: ToEncodedPoint<C>,
//         ED: EncodePublicKey<PublicKey<C>>
// {
//     type Error = elliptic_curve::Error;
//     fn try_into(self) -> Result<PublicKey<C>, Self::Error>
//     {
//         PublicKey::<C>::from_sec1_bytes(&self.bytes)
//     }
// }






// impl<C,K,L,DE> GetPublicKey<PublicKey<C>> for EcdhEncapsulator<C,K,L,DE> 
// where   C: CurveArithmetic+PointCompression, 
//         K: EcdhCombiner,
//         L: ArrayLength<u8>,
// {
//     fn get_public_key (&self) -> &PublicKey<C> {
//         //let pk) = &self.key else { panic! ( "Missing key")};
//         &self.key
//     }
// }
// impl<C,K,L,DE> Default for EcdhEncapsulator<C,K,L,DE> 
// where   C: CurveArithmetic+PointCompression, 
//         K: EcdhCombiner + Default, 
//         L: ArrayLength<u8>,
// {
//     /// Create a new EcdhEncapsulator struct using the given Curve, Output length and kdf
//     fn default () -> Self {
//         EcdhEncapsulator { kdf: K::default(), _phantom2: PhantomData, _phantom4: PhantomData, _phantom5: PhantomData, key: None }
//     }
// }
// impl<C,K,L,DE> EncapsulatorInit<K> for EcdhEncapsulator<C,K,L,DE> 
// where   C: CurveArithmetic+PointCompression, 
//         K: EcdhCombiner,
//         L: ArrayLength<u8>,
// {
//     /// Create a new EcdhEncapsulator struct using the given Curve, Output length and kdf
//     fn new (kdf: K) -> Self {
//         EcdhEncapsulator { _phantom2: PhantomData, kdf: kdf, _phantom4: PhantomData, _phantom5: PhantomData, key: None }
//     }
// }
// impl<C,K,L,DE> EncodePublicKey<PublicKey<C>> for EcdhEncapsulator<C,K,L,DE> 
// where   C: CurveArithmetic+PointCompression, 
//         K: EcdhCombiner + Default, 
//         L: ArrayLength<u8>,
//         DE: EncodePublicKey<PublicKey<C>>
// {
//     type EncodedLen = DE::EncodedLen;
//     fn encode(public_key: &PublicKey<C>) -> GenericArray<u8, Self::EncodedLen> {
//         DE::encode(public_key)
//     }
// }

// impl<C,K,L,DE> Encode for EcdhEncapsulator<C,K,L,DE> 
// where   C: CurveArithmetic+PointCompression, 
//         K: EcdhCombiner + Default, 
//         L: ArrayLength<u8>,
//         DE: EncodePublicKey<PublicKey<C>>
// {
//     type EncodedLen = DE::EncodedLen;
//     fn encode(&self) -> GenericArray<u8, Self::EncodedLen> {
//         //let Some(key) = self.key else { panic! ("Missing key" ); };
//         DE::encode(&self.key)
//     }
//     fn decode(enc: &GenericArray<u8, Self::EncodedLen>) -> Self {
//         todo!()
//     }
// }



// impl<C,K,L,DE> EncodePublicKey<PublicKey<C>> for EcdhDecapsulator<C,K,L,DE> 
// where   C: CurveArithmetic+PointCompression, 
//         K: EcdhCombiner + Default, 
//         L: ArrayLength<u8>,
//         DE: EncodePublicKey<PublicKey<C>>
// {
//     type EncodedLen = DE::EncodedLen;
//     fn encode(public_key: &PublicKey<C>) -> GenericArray<u8, Self::EncodedLen> {
//         DE::encode(public_key)
//     }
// }

// impl<C,K,L,DE> Encode for EcdhDecapsulator<C,K,L,DE> 
// where   C: CurveArithmetic+PointCompression, 
//         K: EcdhCombiner + Default, 
//         L: ArrayLength<u8>,
//         DE: EncodePublicKey<PublicKey<C>>
// {
//     type EncodedLen = DE::EncodedLen;
//     fn encode(&self) -> GenericArray<u8, Self::EncodedLen> {
//         DE::encode(self.private)
//     }
// }


// Trait for a Key Derivation Function designed for a Key Encapsulation Mechanism.
// Two types of parameters are passed to the derive function
// - SharedSecret which is typically output from the Diffie Hellman primitive. These value must be used in the key derivation
// - PublicKey type used to pass the ephemeral and recipient public keys. These keys may or may not be used in the key derivation
// pub trait EcdhCombiner {
//     fn combine<L: ArraySize>(&self, raw_shared_secret_x: impl AsRef<[u8]>, raw_shared_secret_y:impl AsRef<[u8]> /*Self::SharedSecret*/, ephemeral_pub: impl AsRef<[u8]> /*Self::PublicKey*/, recipient_pub: impl AsRef<[u8]> /*&Self::PublicKey*/ ) -> Array<u8, L>;
// }

// A combiner which is passed the outputs from the ECDH algorithm and associated public keys and returns the shared secret.
// 
// Two types of parameters are passed to the combiner:
// - SharedSecrets which are output from the Diffie-Hellman primitive. These values must be used in the key derivation
// - PublicKey type used to pass the ephemeral, recipient and sender public keys. These keys may or may not be used in the key derivation
// pub trait EcdhAuthCombiner {
//     fn combine<L: ArraySize>(&self, raw_shared_secret_1: impl AsRef<[u8]>, raw_shared_secret_2: impl AsRef<[u8]>, ephemeral_pub: impl AsRef<[u8]>, recipient_pub: impl AsRef<[u8]>, sender_pub: impl AsRef<[u8]> ) -> Array<u8, L>;
// }

// A combiner which accepts the ouput from the MQV algorithm and returns a shared secret 
// 
// This trait accepts a single raw_shared secret field and three public keys.
// pub trait MqvAuthCombiner {
//     fn combine<L: ArraySize>(&self, raw_shared_secret: impl AsRef<[u8]>, ephemeral_pub: impl AsRef<[u8]>, recipient_pub: impl AsRef<[u8]>, sender_pub: impl AsRef<[u8]> ) -> Array<u8, L>;
// }



//
// A combiner for Elliptic Curve which applies a Kdf to the X and Y coordinates
// 
// #[derive(Clone)]
// pub struct EcCombinerXYNoPubKeys<K:Kdf> { 
//     kdf: K, 
// }

// impl<K: Kdf + Default> Default for EcCombinerXYNoPubKeys<K>
// {
//     fn default() -> Self {
//         return Self{kdf: K::default()}
//     }
// }
// impl<K: Kdf + InitSalt> InitSalt for EcCombinerXYNoPubKeys<K>
// {
//     fn new_with_salt(salt: &[u8]) -> Self {
//         return Self{kdf: K::new_with_salt(salt)}
//     }
// }

// impl<K: Kdf + Default + Clone> EcdhCombiner for EcCombinerXYNoPubKeys<K>
// {
//     fn combine<L:ArraySize> (&self, raw_shared_secret_x: impl AsRef<[u8]>, raw_shared_secret_y: impl AsRef<[u8]>,  _ephemeral_pub: impl AsRef<[u8]>, _recipient_pub: impl AsRef<[u8]> ) -> Array<u8, L>
//     {
//         self.kdf.derive_self_secrets_others ([raw_shared_secret_x.as_ref(), raw_shared_secret_y.as_ref()], None )
//     }
// }


//
// Elliptic Curve Combiner as used by the OpenPgp standard, RFC 9580
// Two KDFs are mentioned in RFC 9580
// - Concat KDF 
// - HKDF
// This implementation has a generic parameter which allows for any regular Kdf to be used
// 
// pub struct EcCombinerOpenPgp<K:Kdf> (PhantomData<K>);
// impl<K: Kdf + Default> Default for EcCombinerOpenPgp<K>{
//     fn default() -> Self {
//         Self(Default::default())
//     }
// }

// impl<K:Kdf + Default> Kdf for EcCombinerOpenPgp<K>
// {
//     fn derive_self_secrets_others_into<'a,'b> ( &self, secret: impl IntoIterator<Item=&'a[u8]> + Clone, other_data: impl IntoIterator<Item=&'b[u8]> + Clone, out: &mut [u8]) -> Result<(), kdfs::Error> {
//         let secrets : Vec<_>= secret.into_iter().collect();
//         let other_data: Vec<_> = other_data.into_iter().collect();
//         K::default().derive_self_secrets_other_into([other_data[0], other_data[1], secrets[0]], b"OpenPGP X25519", out)
//     }
// }
