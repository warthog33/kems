//!
//! Wrapper around the ML-KEM crate to provide the same traits as supported by other kems in this crate.
//! It also allows for an explicit KDF which is applied immediately after ML-KEM outputs a shared key
//! 
use crate::kem_with_kdf::{CombinerNoKeys, KemWithKdf};
use crate::{Array, ArraySize, ArrayLength, Capsulator, CryptoRngCore, Decapsulate, DecodeGenericArray, Encapsulate, EncapsulateDeterministic2, EncodeGenericArray, EncodedSizeUser2, GenerateCapsulatorFromSeed, GenericArray, GetEncapsulator, GetRecipientPublicKeyBytes};
#[cfg(all(feature="rustcrypto-ml-kem", feature="rustcrypto-sha3"))]
use cipher::consts::U16;
use kdfs::{misc::PassThroughKdf, Kdf};
use ml_kem::{self, EncapsulateDeterministic, EncodedSizeUser, KemCore, MlKem768Params};
use cipher::consts::{U32, U64};
//use cipher::typenum::Unsigned;
use std::marker::PhantomData;


/// 
/// Applies a key derivation function to the seed before using it as the new seed for generating ML-KEM keys
/// 
impl<M: KemCore, G> GenerateCapsulatorFromSeed for MlKemWrapper<M,G>
where   M: KemCore<SharedKeySize = U32>,
        M::CiphertextSize: ArrayLength, //<u8>,
        //M::SharedKeySize: ArraySize + ArrayLength<u8>,
        G: Kdf + Default,
{
    type SeedSize = U64;

    fn derive_from_seed(seed: &Array<u8, Self::SeedSize>) -> (Self::Encapsulator, Self::Decapsulator) {
        let recipient_seed: Array<u8, U64> = G::derive_secret_others(seed, None).unwrap();
        
        let (seed1, seed2) = recipient_seed.split::<U32>();
        let (recipient_private, recipient_public) = M::generate_deterministic(&seed1.0.into(), &seed2.0.into());
        (Self::Encapsulator{recipient_public}, Self::Decapsulator{recipient_private, recipient_seed})
    }
}




///
/// Wrapper around the KemCore structs adding the following features
/// - Additional derivation function applied to a seed used for key generation
/// - Storage of initial seed such that the private key can be exported and imported as the seed 
/// 
pub struct MlKemWrapper<M: KemCore, G = PassThroughKdf> (PhantomData<M>, PhantomData<G>);

///
/// Type representing ML-KEM with a separate key derivation applied to the output
/// 
pub type MlKemWithOutputKdf<M,K> = KemWithKdf<MlKemWrapper<M, PassThroughKdf>, CombinerNoKeys, K, U32>;

#[cfg(all(feature="rustcrypto-ml-kem", feature="rustcrypto-sha3"))]
pub type MlKem768WithX963KdfU16 = KemWithKdf<MlKemWrapper<ml_kem::MlKem768, PassThroughKdf>, CombinerNoKeys, kdfs::ansi_x9_63::X963Kdf<sha3::Sha3_256>, U16>;

///
/// Type representing ML-KEM with a separate key derivation applied during derivation from seed
/// 
pub type MlKemWithSeedKdf<M,K> = KemWithKdf<MlKemWrapper<M, K>, CombinerNoKeys, PassThroughKdf, U32>;


impl<M, G> Capsulator for MlKemWrapper<M,G>
where 
    M: KemCore<SharedKeySize = U32>,
    M: KemCore,
    //M::SharedKeySize: ArrayLength<u8> + ArraySize,
    M::CiphertextSize: ArrayLength, //<u8>,
    G: Kdf + Default,
{
    type Encapsulator = MlKemEncapsulator<M>;
    type Decapsulator = MlKemDecapsulator<M>;
    type CiphertextSize = M::CiphertextSize;
    type SharedKeySize = M::SharedKeySize;
    
    fn generate ( rng: &mut impl CryptoRngCore ) -> (Self::Encapsulator, Self::Decapsulator) {
        let mut seed = Array::default();
        rng.fill_bytes(&mut seed);
        Self::derive_from_seed(&seed)
    }
}



///
/// A wrapper around an MlKem decapsulation key which provides some additional functionality
/// - storage of initial seed value for use when exporting private keys as seeds
/// - a KDF to apply after key derivation as used with some KEMs
/// - a configurable output length, L
/// 
pub struct MlKemDecapsulator<M: KemCore> //, LE = <<M as KemCore>::DecapsulationKey as KeySizeUser>::KeySize> 
{
    recipient_private: M::DecapsulationKey,
    recipient_seed: Array<u8, U64>,
}

impl<M: KemCore> EncodedSizeUser2 for MlKemDecapsulator<M>
 where <<M as KemCore>::DecapsulationKey as EncodedSizeUser>::EncodedSize: ArrayLength, //<u8>,
{
    type EncodedSize = U64;

    fn from_bytes(seed: &crate::Encoded<Self>) -> Self {
        // let (d,z) = seed.split_at(U32::USIZE);
        // let (recipient_private, _) = M::generate_deterministic(&d.try_into().unwrap(), &z.try_into().unwrap());
        let (d,z) = seed.as_ha0_4().split::<U32>();
        let (recipient_private, _) = M::generate_deterministic(&d.0.into(), &z.0.into());
        Self { recipient_private, recipient_seed: Array::try_from(seed.as_slice()).unwrap() }
    }

    fn as_bytes(&self) -> crate::Encoded<Self> {
        GenericArray::from_slice(&self.recipient_seed).clone()
    }
}


impl <M: KemCore> Decapsulate<GenericArray<u8, M::CiphertextSize>, Array<u8, M::SharedKeySize>> for MlKemDecapsulator<M>
where 
    //M: KemCore<SharedKeySize=U32>,
    M::SharedKeySize: ArraySize,
    M::CiphertextSize: ArrayLength, //<u8>,
    M::DecapsulationKey: Decapsulate<ml_kem::array::Array<u8, M::CiphertextSize>, ml_kem::array::Array<u8, M::SharedKeySize>>,
{   
    type Error = ();
    fn decapsulate(&self, encapsulated_key: &GenericArray<u8, M::CiphertextSize>) -> Result<Array<u8, M::SharedKeySize>, Self::Error> {
        //let x: Array<u8; M::CiphertextSize> = encapsulated_key.iter().collect();
        //let ek = ml_kem::array::Array::<u8, M::CiphertextSize>::from(encapsulated_key.as_ref());
        let Ok(encapsulated_key2) = ml_kem::array::Array::try_from(encapsulated_key.as_slice()) else { return Err(())};

        //let encapsulated_key2 = GenericArray
        let Ok(ss) = self.recipient_private.decapsulate(&encapsulated_key2) else { return Err(())};
        //Ok ( Array::from(ss.0) )
        //Ok (ss.0.into())
        Ok(Array::try_from(ss.as_slice()).unwrap())
    }
}

impl GetEncapsulator for MlKemDecapsulator<ml_kem::MlKem768>
{
    type Encapsulator = MlKemEncapsulator<ml_kem::MlKem768>;
    fn get_encapsulator(&self) -> Self::Encapsulator {
        Self::Encapsulator { recipient_public: self.recipient_private.encapsulation_key().clone()}
    }
}
impl GetEncapsulator for MlKemDecapsulator<ml_kem::MlKem1024>
{
    type Encapsulator = MlKemEncapsulator<ml_kem::MlKem1024>;
    fn get_encapsulator(&self) -> Self::Encapsulator {
        Self::Encapsulator { recipient_public: self.recipient_private.encapsulation_key().clone()}
    }
}

impl GetRecipientPublicKeyBytes for MlKemDecapsulator<ml_kem::MlKem512>
{
    type EncodedLen = <<ml_kem::MlKem512 as KemCore>::EncapsulationKey as EncodedSizeUser>::EncodedSize;

    fn get_recipient_public_key_bytes(&self) -> GenericArray<u8, Self::EncodedLen> {
        *GenericArray::from_slice(self.recipient_private.encapsulation_key().as_bytes().as_slice())
    }
}

impl GetRecipientPublicKeyBytes for MlKemDecapsulator<ml_kem::MlKem768>
{
    type EncodedLen = <<ml_kem::MlKem768 as KemCore>::EncapsulationKey as EncodedSizeUser>::EncodedSize;

    fn get_recipient_public_key_bytes(&self) -> GenericArray<u8, Self::EncodedLen> {
        *GenericArray::from_slice(self.recipient_private.encapsulation_key().as_bytes().as_slice())
    }
}

impl GetRecipientPublicKeyBytes for MlKemDecapsulator<ml_kem::MlKem1024>
{
    type EncodedLen = <<ml_kem::MlKem1024 as KemCore>::EncapsulationKey as EncodedSizeUser>::EncodedSize;

    fn get_recipient_public_key_bytes(&self) -> GenericArray<u8, Self::EncodedLen> {
        *GenericArray::from_slice(self.recipient_private.encapsulation_key().as_bytes().as_slice())
    }
}




///
/// Wrapper around an ML-KEM encapsulation key which provides traits used by other encapsulators and decapsulators used in this package
///
pub struct MlKemEncapsulator<M: KemCore> 
{ 
    recipient_public: M::EncapsulationKey,
}

impl <M: KemCore> EncodedSizeUser2 for MlKemEncapsulator<M>
where 
    M::EncapsulationKey: EncodedSizeUser,
    <M::EncapsulationKey as EncodedSizeUser>::EncodedSize: ArrayLength, //<u8>
{
    type EncodedSize = <M::EncapsulationKey as EncodedSizeUser>::EncodedSize;

    fn as_bytes(&self) -> crate::Encoded<Self> {
        GenericArray::from_slice(self.recipient_public.as_bytes().as_slice()).clone()
    }
    
    fn from_bytes(encoded_recipient_public: &crate::Encoded<Self>) -> Self {
        let recipient_public = M::EncapsulationKey::from_bytes(&ml_kem::array::Array::try_from(encoded_recipient_public.as_slice()).unwrap());
        Self{recipient_public }
    }
}

impl <M: KemCore> EncodeGenericArray<Self> for MlKemEncapsulator<M>
where M::EncapsulationKey: EncodedSizeUser,
    <M::EncapsulationKey as EncodedSizeUser>::EncodedSize: ArrayLength, //<u8>
{
    type EncodedLen = <M::EncapsulationKey as EncodedSizeUser>::EncodedSize;

    fn encode(source: &Self) -> GenericArray<u8, Self::EncodedLen> {
        GenericArray::from_slice(source.recipient_public.as_bytes().as_slice()).clone()
    }
}

impl <M: KemCore> DecodeGenericArray<Self> for MlKemEncapsulator<M>
where M::EncapsulationKey: EncodedSizeUser,
    <M::EncapsulationKey as EncodedSizeUser>::EncodedSize: ArrayLength + ArraySize, //<u8>, // + ArraySize,
{
    type EncodedLen = <M::EncapsulationKey as EncodedSizeUser>::EncodedSize;
    type Error = ();

    fn decode(encoded_bytes: &GenericArray<u8, Self::EncodedLen>) -> Result<Self, Self::Error> {
        let Ok(encoded_bytes2) = ml_kem::array::Array::try_from(encoded_bytes.as_slice()) else { return Err(())};

        // let encoded_bytes2 = encoded_bytes.as_ha0_4();
        // let encoded_bytes3: &[u8,_] = &encoded_bytes2;

        //let encoded_bytes2 = encoded_bytes2.0.into();
        
        //let encoded_bytes2 = encoded_bytes.as_hybrid_array::<Self::EncodedLen>().unwrap();
        //let recipient_public = M::EncapsulationKey::from_bytes(&ml_kem::array::Array::try_from(encoded_bytes.as_slice()).unwrap());
        let recipient_public = M::EncapsulationKey::from_bytes(&ml_kem::array::Array::from(encoded_bytes2));
        Ok(Self{recipient_public })
    }
}


impl <M: KemCore> Encapsulate<GenericArray<u8, M::CiphertextSize>, Array<u8, M::SharedKeySize>> for MlKemEncapsulator<M>
where M::CiphertextSize: ArrayLength, //<u8>,
    M::SharedKeySize: kdfs::hybrid_array::ArraySize,
{
    type Error = ();
    fn encapsulate(&self, rng: &mut impl CryptoRngCore) -> Result<(GenericArray<u8, M::CiphertextSize>, Array<u8, M::SharedKeySize>), Self::Error> {
        let (ct, ss) = self.recipient_public.encapsulate(rng).unwrap();
        //let derived_ss = self.kdf.derive_self_secret_other::<L>(&ss, &[]);
        let ct_ga = GenericArray::from_slice(&ct.as_slice());
        //let ct_ga = GenericArray::from_ha0_4(ct.0.into());
        Ok((ct_ga.clone(), ss.as_slice().try_into().unwrap()))
        //Ok((*ct_ga, derived_ss))
    }
}

impl <M: KemCore> EncapsulateDeterministic2<GenericArray<u8, M::CiphertextSize>, Array<u8, M::SharedKeySize>> for MlKemEncapsulator<M>
where M::CiphertextSize: ArrayLength, //<u8>,
      M::SharedKeySize: ArraySize,
{
    type Error = ();
    type SeedSize = U32;
    fn encapsulate_deterministic(&self, seed: &[u8]) -> Result<(GenericArray<u8, M::CiphertextSize>, Array<u8, M::SharedKeySize>), Self::Error> {
        let Ok(seed_as_array): Result<ml_kem::B32,_> = seed.try_into() else { return Err(())};
        let (ct, ss) = self.recipient_public.encapsulate_deterministic(&seed_as_array).unwrap();
        //let derived_ss = self.kdf.derive_self_secret_other::<L>(&ss, &[]);
        let ct_ga = GenericArray::from_slice(&ct.as_slice());
        
        Ok((ct_ga.clone(), ss.as_slice().try_into().unwrap()))
        //Ok((ct_ga.clone(), ss.0.into() )
        //Ok((*ct_ga, derived_ss))
    }
}


impl GetEncapsulator for ml_kem::kem::DecapsulationKey<MlKem768Params>
{
    type Encapsulator = ml_kem::kem::EncapsulationKey<MlKem768Params>;
    fn get_encapsulator(&self) -> Self::Encapsulator {
        self.encapsulation_key().clone()
    }
}

impl GetEncapsulator for ml_kem::kem::DecapsulationKey<ml_kem::MlKem1024Params>
{
    type Encapsulator = ml_kem::kem::EncapsulationKey<ml_kem::MlKem1024Params>;
    fn get_encapsulator(&self) -> Self::Encapsulator {
        self.encapsulation_key().clone()
    }
}

impl<M: KemCore> GetRecipientPublicKeyBytes for MlKemEncapsulator<M>
where <<M as KemCore>::EncapsulationKey as EncodedSizeUser>::EncodedSize: ArrayLength,//<u8>
{
    type EncodedLen = <M::EncapsulationKey as EncodedSizeUser>::EncodedSize;

    fn get_recipient_public_key_bytes(&self) -> GenericArray<u8, Self::EncodedLen> {
        GenericArray::from_slice(self.recipient_public.as_bytes().as_slice()).clone()
    }
}


// impl<M: KemCore, G, L: ArrayLength<u8>, K: Kdf> MlKemWithAddKeyDer<M,G, L, K>
// where <M as KemCore>::CiphertextSize: generic_array::ArrayLength<u8>, 
//     <M as KemCore>::SharedKeySize: generic_array::ArrayLength<u8>,
//     K: Default
// {
//     pub fn new_decapsulator_with_params (private: M::DecapsulationKey, kdf: K) -> MlKemDecapsulator<M, L, K> {
//         let mut return_value = MlKemDecapsulator::from_key(private);
//         return_value.set_kdf ( kdf);
//         return_value
//     }
// }


// #[cfg(test)]
// mod tests{
//     use ml_kem::MlKem512;
//     use crate::GenerateCapsulatorFromSeed;
//     use crate::ml_kem::MlKemWrapper;
//     use crate::EncodedSizeUser2;

//     #[test]
//     fn test_export()
//     {
//         let (encapsulator, decapsulator) = MlKemWrapper::<MlKem512>::derive_from_seed(&[1u8;64].into());

//         println! ( "decp={:02X?}", decapsulator.as_bytes());
//         println! ( "encp={:02X?}", encapsulator.as_bytes());
        
//     }
// }


// pub struct MlKemEncapKey<M: KemCore, L: ArrayLength<u8>> 
//     where <M as KemCore>::CiphertextSize: ArrayLength<u8> 
// {
//     bytes: GenericArray::<u8, M::CiphertextSize>,
//     phantom: PhantomData<L>
// }

// impl <M: KemCore, L: ArrayLength<u8>> EncappedKey for MlKemEncapKey<M,L> 
// where <M as KemCore>::CiphertextSize: ArrayLength<u8>,
//     <M as KemCore>::SharedKeySize: ArrayLength<u8>
// {
//     type EncappedKeySize = M::CiphertextSize;
//     type SharedSecretSize = L;
//     type SenderPublicKey = M;
//     type RecipientPublicKey = M::EncapsulationKey;
//     fn from_bytes(bytes: &GenericArray<u8, Self::EncappedKeySize>) -> Result<Self, kem::Error> {
//         Ok(Self{bytes: bytes.clone(), phantom: PhantomData})
//     }
    
//     fn as_bytes(&self) -> &GenericArray<u8, Self::EncappedKeySize> {
//         // EncappedKey is already AsRef<[u8]>, so we don't need to do any work. This will panic iff
//         // the underlying bytestring is not precisely NEnc bytes long.
//         self.as_ref().into()
//     }
// }


// impl <M: KemCore,L: ArrayLength<u8>> AsRef<[u8]> for MlKemEncapKey<M,L> 
// where <M as KemCore>::CiphertextSize: ArrayLength<u8>,
//     <M as KemCore>::SharedKeySize: ArrayLength<u8>
// {
//     fn as_ref(&self) -> &[u8] {
//         &self.bytes
//     }
// }
// impl <M: KemCore, L: ArrayLength<u8>> Debug for MlKemEncapKey<M,L> 
// where <M as KemCore>::CiphertextSize: ArrayLength<u8> 
// {
//     fn fmt(&self, _f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
//         todo!()
//     }
// }
// impl <M: KemCore,L,K:Kdf> AsRef<M::EncapsulationKey> for MlKemEncapsulator<M, L,K>
// {
//     fn as_ref(&self) -> &M::EncapsulationKey {
//         &self.pub_key
//     }
// }


// impl <M: KemCore,L,K:Kdf> PartialEq for MlKemEncapsulator<M, L,K>
// where K: Default
// {
//     fn eq(&self, other: &Self) -> bool {
//         todo!()
//     }
//}
// impl <M: KemCore, L,K:Kdf> Debug for MlKemEncapsulator<M,L,K>
// where K: Default
// {
//     fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
//         todo!()
//     }
// }
// impl <M: KemCore, L,K:Kdf + Clone> Clone for MlKemEncapsulator<M, L,K>
// where K: Default,
//     M::EncapsulationKey: Clone
// {
//     fn clone(&self) -> Self {
//         Self{recipient_public: self.recipient_public.clone(), phantom: PhantomData, kdf: self.kdf.clone(), phantom2: PhantomData}
//     }
// }


// impl <M: KemCore, L,K:Kdf> EncodedSizeUser for MlKemEncapsulator<M,L,K>
// where K: Default,
//     M::EncapsulationKey: EncodedSizeUser
// {
//     //type EncodedSize = <M::EncapsulationKey as EncodedSizeUser>::EncodedSize;
//     type EncodedSize = <M::EncapsulationKey as EncodedSizeUser>::EncodedSize;
//     fn as_bytes(&self) -> ml_kem::Encoded<Self> {
//         //let Some(pk) = &self.pub_key else { panic! ("Missing key" );};
//         self.pub_key.as_bytes()
//     }
//     fn from_bytes(enc: &ml_kem::Encoded<Self>) -> Self {
//         let pub_key = M::EncapsulationKey::from_bytes(enc);
//         Self{pub_key: pub_key, phantom: PhantomData, kdf: K::default(), phantom2: PhantomData }
//     }

// }
// impl <M: KemCore,L,K:Kdf> Default for MlKemEncapsulator<M, L,K>
// where K: Default
// {
//     fn default() -> Self {
//         Self {pub_key: None, kdf: K::default(), phantom: PhantomData, phantom2: PhantomData}
//     }
// }
// impl <M,L,K:Kdf> From<M::EncapsulationKey> for MlKemEncapsulator<M,L,K>
// where K: Default,
//     M: KemCore
// {
//     fn from(value: M::EncapsulationKey) -> Self {
//         Self{pub_key: Some(value), kdf: K::default(), phantom: PhantomData, phantom2: PhantomData}
//     }
// }
// impl<M: KemCore, L, K: Kdf> MlKemEncapsulator<M,L, K> {
//     /// Create a Decapsulator from a private key and kdf, which must match the recipient public key and kdf used 
//     /// during the encapsulation phase
//     pub fn new (kdf: K) -> Self {
//         Self { pub_key: None, kdf, phantom: PhantomData,phantom2: PhantomData }
//     }
// }
// impl <M: KemCore,K:Kdf,L: ArrayLength<u8>> Encapsulator<MlKemEncapKey<M,L>> for MlKemEncapsulator<M,L,K>
// where <M as KemCore>::CiphertextSize: ArrayLength<u8>,
//     <M as KemCore>::SharedKeySize: ArrayLength<u8>
// {   
//     fn try_encap<R: rand_core::CryptoRng + rand_core::RngCore>(
//             &self,
//             csprng: &mut R,
//             recip_pubkey: &<MlKemEncapKey<M,L> as EncappedKey>::RecipientPublicKey,
//         ) -> Result<(MlKemEncapKey<M,L>, kem::SharedSecret<MlKemEncapKey<M,L>>), kem::Error> {
        
//         let (ct, ss) = recip_pubkey.encapsulate(csprng).unwrap();
//         let ct_ga = GenericArray::from_slice(&ct);

//         let derived_ss = self.kdf.derive_self_secret_other(&ss, &[]);
//         Ok((MlKemEncapKey::from_bytes(ct_ga)?, kem::SharedSecret::new(derived_ss.clone())))
//     }
// }

// impl <M: KemCore,K:Kdf,L: ArrayLength<u8>> ml_kem::kem::Encapsulate<hybrid_array::Array<u8, M::CiphertextSize>, hybrid_array::Array<u8, M::SharedKeySize>> for MlKemEncapsulator<M,L,K>
// where M::EncapsulationKey: Encapsulate<hybrid_array::Array<u8, M::CiphertextSize>, hybrid_array::Array<u8, M::SharedKeySize>>
// {
//     type Error = ();
//     fn encapsulate(&self, rng: &mut impl rand_core::CryptoRngCore) -> Result<(hybrid_array::Array<u8, M::CiphertextSize>, hybrid_array::Array<u8, M::SharedKeySize>), Self::Error> {
//         //let Some(pk) = &self.pub_key else { panic! ( "no key") };
//         let (ct, ss) = self.pub_key.encapsulate(rng).unwrap();
//         let derived_ss: GenericArray<u8, L> = self.kdf.derive_self_secret_other(&ss, &[]);
//         Ok((ct, hybrid_array::Array::try_from(derived_ss.as_slice()).unwrap()))
//     }
// }

// impl <M: KemCore,K:Kdf,L: ArrayLength<u8>> ml_kem::EncapsulateDeterministic<hybrid_array::Array<u8, M::CiphertextSize>, hybrid_array::Array<u8, M::SharedKeySize>> for MlKemEncapsulator<M,L,K>
// where M::EncapsulationKey: EncapsulateDeterministic<hybrid_array::Array<u8, M::CiphertextSize>, hybrid_array::Array<u8, M::SharedKeySize>>
// {
//     type Error = ();
//     fn encapsulate_deterministic(&self, m: &ml_kem::B32) -> Result<(hybrid_array::Array<u8, M::CiphertextSize>, hybrid_array::Array<u8, M::SharedKeySize>), Self::Error> 
//     {
//         //let Some(pk) = &self.pub_key else { panic! ( "no key") };
//         let (ct, ss) = self.pub_key.encapsulate_deterministic(m).unwrap();
//         let derived_ss: GenericArray<u8, L> = self.kdf.derive_self_secret_other(&ss, &[]);
//         //Ok((ct, hybrid_array::Array::try_from(derived_ss.as_slice()).unwrap()))
//         Ok((ct, hybrid_array::Array::try_from(derived_ss.as_ref()).unwrap()))
//     }
// }
// impl <M: KemCore, K:Kdf + Default,L: ArrayLength<u8>, P> From<<ml_kem::MlKem768 as KemCore>::DecapsulationKey> for MlKemEncapsulator<M,L,K>
// {
//     fn from(value: M::EncapsulationKey) -> Self {
//         Self { kdf: K::default(), pub_key: Some(value), phantom: PhantomData, phantom2: PhantomData}
//     }
// }

// impl<M: KemCore, K: Kdf> PartialEq for MlKemDecapsulator<M,K>
// {
//     fn eq(&self, other: &Self) -> bool {
//         todo!()
//     }
// }

//impl<M: KemCore, K: Kdf> EncodePublicKey2 for MlKemDecapsulator<M,K>
// impl<L, K: Kdf> EncodePublicKey2 for MlKemDecapsulator<ml_kem::MlKem768, L, K>
// {
//     type EncodedLen = <<ml_kem::MlKem768 as ml_kem::KemCore>::EncapsulationKey as EncodedSizeUser>::EncodedSize;
//     fn get_encoded_public_key(&self) -> GenericArray<u8, Self::EncodedLen> {
//         let decap_key = &self.recipient_private;
//         let encap_key = decap_key.encapsulation_key();
//         *GenericArray::from_slice(encap_key.as_bytes().as_slice())
//     }
// }

// impl<K: Kdf> EncodePublicKey2 for MlKemDecapsulator<ml_kem::MlKem1024, K>
// {
//     type EncodedLen = <<ml_kem::MlKem1024 as ml_kem::KemCore>::EncapsulationKey as EncodedSizeUser>::EncodedSize;
//     fn get_encoded_public_key(&self) -> GenericArray<u8, Self::EncodedLen> {
//         let decap_key = &self.recipient_private;
//         let encap_key = decap_key.encapsulation_key();
//         *GenericArray::from_slice(encap_key.as_bytes().as_slice())
//     }
// }

// impl<M: KemCore, K: Kdf> Debug for MlKemDecapsulator<M,K>
// {
//     fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
//         todo!()
//     }
//}
// impl<M: KemCore,L, K: Kdf + Default> EncodedSizeUser for MlKemDecapsulator<M,L,K>
// {
//     //type EncodedSize = <M::DecapsulationKey as EncodedSizeUser>::EncodedSize;
//     type EncodedSize = digest::consts::U64;

//     fn from_bytes(enc: &ml_kem::Encoded<Self>) -> Self {
//         let ( d, z ) = enc.split();
//         let (decap, _) = M::generate_deterministic(&d, &z);
//         Self { kdf: K::default(), recipient_private: decap, phantom: PhantomData}
//     }

//     fn as_bytes(&self) -> ml_kem::Encoded<Self> {
//         todo!()
//     }
//}
//#[derive(Debug)]

// impl<M: KemCore, L, K: Kdf> AsRef<M::DecapsulationKey> for MlKemDecapsulator<M,L,K>{
//     fn as_ref(&self) -> &M::DecapsulationKey {
//         &self.recipient_private
//     }
// }

// impl<M: KemCore, L, K: Kdf> MlKemDecapsulator<M, L, K> {
//     /// Create a Decapsulator from a private key and kdf, which must match the recipient public key and kdf used 
//     /// during the encapsulation phase
//     pub fn new_with_params (private_key: M::DecapsulationKey, kdf: K) -> Self {
//         Self { recipient_private: private_key, kdf, phantom: PhantomData }
//     }
// }

// impl <M: KemCore, K: Kdf, L: ArrayLength<u8>> Decapsulator<MlKemEncapKey<M,L>> for MlKemDecapsulator<M, L, K>
// where <M as KemCore>::CiphertextSize: ArrayLength<u8>,
//     <M as KemCore>::SharedKeySize: ArrayLength<u8>
// {   
//     fn try_decap(&self, encapped_key: &MlKemEncapKey<M,L>) -> Result<kem::SharedSecret<MlKemEncapKey<M,L>>, kem::Error> {
//         let encapped_ga = hybrid_array::Array::try_from(encapped_key.bytes.as_ref()).unwrap();
        
//         let ss = self.private_key.decapsulate(&encapped_ga).unwrap();

//         let derived_ss = self.kdf.derive_self_secret_other(&ss, &[]);
//         Ok(kem::SharedSecret::new(derived_ss))
//     }
// }



// impl<M: KemCore, L: ArrayLength<u8> + Debug, K: Kdf+Default> MlKemWithAddKeyDer<M, L, K>
// where <M as KemCore>::CiphertextSize: cipher::ArrayLength<u8>, 
//     <M as KemCore>::SharedKeySize: cipher::ArrayLength<u8>,
//     Self: Capsulator,
// {   
    
//     pub fn generate ( rng: &mut impl rand_core::CryptoRngCore ) -> Result<(
//         //<MlKemWithAddKeyDer<M, L, K> as Capsulator>::Decapsulator, 
//         MlKemEncapsulator<M, L,K>,
//         MlKemDecapsulator<M, K>,
//         //<MlKemWithAddKeyDer<M, L, K> as Capsulator>::Encapsulator
       
//         ), crate::Error> 
//     {
//         let (d,e) = M::generate(rng);
//         //let dd = MlKemDecapsulator::<M,K>::new_with_params(d, K::default());
//         //let dd = Self::new_decapsulator(d);
//         let dd = MlKemDecapsulator::new(d);
//         let ee = MlKemEncapsulator::from(e);
//         Ok((ee, dd))
//         //Ok(M::generate(rng))
//     }
// }



// impl<M: KemCore,L: ArrayLength<u8>, K: Kdf> kem2::Encapsulate<MlKemEncapKey<M,L>, kem::SharedSecret<MlKemEncapKey<M,L>>> for MlKemEncapsulator<M,L,K>
// where <M as KemCore>::CiphertextSize: cipher::ArrayLength<u8>, 
//     <M as KemCore>::SharedKeySize: cipher::ArrayLength<u8>
// {
//     type Error = kem::Error;    

//     fn encapsulate(&self, rng: &mut impl rand_core::CryptoRngCore) -> Result<(MlKemEncapKey<M,L>, kem::SharedSecret<MlKemEncapKey<M,L>>), Self::Error> {
//         // match &self.pub_key {
//         //     Some(key) => self.try_encap(rng, key),
//         //     None => Err(kem::Error)
//         // }
//         //let Some(pub_key) = &self.pub_key else {panic!("DS")};
//         let (ct, ss) = self.pub_key.encapsulate(rng).unwrap();
//         let ct_ga = GenericArray::from_slice(&ct);

//         let derived_ss = self.kdf.derive_self_secret_other(&ss, &[]);
//         Ok((MlKemEncapKey::from_bytes(ct_ga)?, kem::SharedSecret::new(derived_ss.clone())))
//     }
// }



// impl<M: KemCore, L: ArrayLength<u8>, K: Kdf> kem2::Decapsulate<MlKemEncapKey<M,L>, kem::SharedSecret<MlKemEncapKey<M,L>>> for MlKemDecapsulator<M,K>
// where <M as KemCore>::CiphertextSize: cipher::ArrayLength<u8>, 
//     <M as KemCore>::SharedKeySize: cipher::ArrayLength<u8>
// {
//     type Error = kem::Error;
//     fn decapsulate(&self, encapsulated_key: &MlKemEncapKey<M,L>) -> Result<kem::SharedSecret<MlKemEncapKey<M,L>>, Self::Error> {
//         self.try_decap(encapsulated_key)
//     }
// }



// pub struct MlKemWrapper<M> (PhantomData<M>);

// impl<M: ml_kem::KemCore> ml_kem::KemCore for MlKemWithAddKeyDer<M>
// where <M as KemCore>::CiphertextSize: ArrayLength<u8>,
// <M as KemCore>::SharedKeySize: ArrayLength<u8>
// {
//     type CiphertextSize = M::CiphertextSize;
//     type SharedKeySize = M::SharedKeySize;
//     type DecapsulationKey = MlKemDecapsulator<M>;
//     type EncapsulationKey = MlKemEncapsulator<M, M::SharedKeySize, PassThroughKdf>;

//     fn generate(rng: &mut impl rand_core::CryptoRngCore) -> (Self::DecapsulationKey, Self::EncapsulationKey) {
//         let (private, public) = M::generate(rng);
        
//         (MlKemDecapsulator::new(private), MlKemEncapsulator::from(public))
//     }
//     fn generate_deterministic(_d: &ml_kem::B32, _z: &ml_kem::B32)
//             -> (Self::DecapsulationKey, Self::EncapsulationKey) {
//         todo!();
//     }
// }




//type MlKem768DecapsulationKey = ml_kem::kem::DecapsulationKey<MlKem768Params>;

// impl EncodePublicKey2 for ml_kem::kem::DecapsulationKey<MlKem768Params>
// {
//     type EncodedLen = <<ml_kem::MlKem768 as ml_kem::KemCore>::EncapsulationKey as EncodedSizeUser>::EncodedSize;
//     fn get_encoded_public_key(&self) -> GenericArray<u8, Self::EncodedLen> {
//         let encap_key = self.encapsulation_key();
//         *GenericArray::from_slice(encap_key.as_bytes().as_slice())
//     }
// }

// impl EncodePublicKey2 for ml_kem::kem::DecapsulationKey<ml_kem::MlKem1024Params>
// {
//     type EncodedLen = <<ml_kem::MlKem1024 as ml_kem::KemCore>::EncapsulationKey as EncodedSizeUser>::EncodedSize;
//     fn get_encoded_public_key(&self) -> GenericArray<u8, Self::EncodedLen> {
//         let encap_key = self.encapsulation_key();
//         *GenericArray::from_slice(encap_key.as_bytes().as_slice())
//     }
// }


