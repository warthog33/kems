//! Hybrid kems uses two other kems which are combined to output a single value.
//! 
//! A cryptographic break in either KEM will not compromise the overall hybrid KEM.
//! 
use std::fmt::Debug;
use std::marker::PhantomData;
use std::ops::{Add, Sub};
use crate::{EncapsulateDeterministic};
use crate::{Label};
use cipher::{KeySizeUser, KeyInit};
use cipher::common::KeyExport;
use cipher::typenum::{Sum, Unsigned};

// Split/Concat not needed directly; keep generic_array imports minimal
use elliptic_curve::consts::*;
use kdfs::hybrid_array::{Array, ArraySize};
use kdfs::{Kdf};
use kem::{Decapsulator, Encapsulate, FromSeed, Generate, InvalidKey, Kem, SharedKey, TryDecapsulate, TryKeyInit};

/// 
/// Combiner for use with hybrid KEMS. 
/// Combiner takes the shared secret, ciphertext and public key of both schemes and derives a single output
/// 
pub trait HybridCombiner<L: ArraySize> {
    fn combine ( &self, ss1: impl AsRef<[u8]>, ct1: impl AsRef<[u8]>, pk1: impl AsRef<[u8]>, ss2: impl AsRef<[u8]>, ct2: impl AsRef<[u8]>, pk2: impl AsRef<[u8]> ) -> Array<u8, L>;
}


///
/// QsfCombiner which combines the shared secret from KEM1 and the shared secret, ciphertext and public key from KEM2
/// Commonly used with one of the ML-KEM algorithms as KEM1 and an ECDH KEM as KEM2
/// 
pub struct QsfCombiner<K, LB: Label> { kdf: K, phantom: PhantomData<LB>}
impl<K: Default, LB: Label> Default for QsfCombiner<K, LB> {
    fn default() -> Self {
        return Self{ kdf: K::default(), phantom: PhantomData}
    }
}
impl<K: Kdf<L> + Clone, LB: Label, L: ArraySize> HybridCombiner<L> for QsfCombiner<K, LB>
{
    fn combine ( &self, ss1: impl AsRef<[u8]>, _ct1: impl AsRef<[u8]>, _pk1: impl AsRef<[u8]>, ss2: impl AsRef<[u8]>, ct2: impl AsRef<[u8]>, pk2: impl AsRef<[u8]> ) -> Array<u8, L> {
        self.kdf.derive_self_secrets_other([ss1.as_ref(), ss2.as_ref(), ct2.as_ref(), pk2.as_ref()], LB::LABEL)
    }
}

///
/// QsfCombiner which combines the shared secret from KEM2 and the shared secret, ciphertext and public key from KEM1 and the 
/// Commonly used with an ECDH KEM as KEM1 and one of the ML-KEM algorithms as KEM2
/// 
pub struct QsfCombiner2<K, LB: Label> { kdf: K, phantom: PhantomData<LB>}
impl<K: Default, LB: Label> Default for QsfCombiner2<K, LB> {
    fn default() -> Self {
        return Self{ kdf: K::default(), phantom: PhantomData}
    }
}
impl<K: Kdf<L> + Clone, LB: Label, L: ArraySize> HybridCombiner<L> for QsfCombiner2<K, LB>
{
    fn combine ( &self, ss1: impl AsRef<[u8]>, ct1: impl AsRef<[u8]>, pk1: impl AsRef<[u8]>, ss2: impl AsRef<[u8]>, _ct2: impl AsRef<[u8]>, _pk2: impl AsRef<[u8]> ) -> Array<u8, L> {
        self.kdf.derive_self_secrets_other ([ss2.as_ref(), ss1.as_ref(), ct1.as_ref(), pk1.as_ref()], LB::LABEL)
    }
}

///
/// QsfCombiner which combines the shared secret, ciphertext and public key from KEM1 and the share secret from KEM2
/// Commonly used with an ECDH KEM as KEM1 and one of the ML-KEM algorithms as KEM2
/// 
pub struct QsfCombiner3<K, LB: Label> { kdf: K, phantom: PhantomData<LB>}
impl<K: Default, LB: Label> Default for QsfCombiner3<K, LB> {
    fn default() -> Self {
        return Self{ kdf: K::default(), phantom: PhantomData}
    }
}
impl<K: Kdf<L> + Clone, LB: Label, L: ArraySize> HybridCombiner<L> for QsfCombiner3<K, LB>
{
    fn combine ( &self, ss1: impl AsRef<[u8]>, ct1: impl AsRef<[u8]>, pk1: impl AsRef<[u8]>, ss2: impl AsRef<[u8]>, _ct2: impl AsRef<[u8]>, _pk2: impl AsRef<[u8]> ) -> Array<u8, L> {
        self.kdf.derive_self_secrets_other ([ss1.as_ref(), ct1.as_ref(), pk1.as_ref(), ss2.as_ref()], LB::LABEL)
    }
}


///
/// KitchenSinkCombiners passes all shared secrets, ciphertexts and public keys to the key derivation function
/// 

pub struct KitchenSinkCombiner<K, LB> ( PhantomData<K>, PhantomData<LB> );

impl<K,LB> Default for KitchenSinkCombiner <K,LB> {
    fn default() -> Self {
        return Self(PhantomData, PhantomData)
    }
}

impl<K: Kdf<L> + Default, LB: Label, L: ArraySize> HybridCombiner<L> for KitchenSinkCombiner<K,LB>
{
    fn combine ( &self, pq_ss: impl AsRef<[u8]>, pq_ct: impl AsRef<[u8]>, pq_pk: impl AsRef<[u8]>, trad_ss: impl AsRef<[u8]>, trad_ct: impl AsRef<[u8]>, trad_pk: impl AsRef<[u8]> ) -> Array<u8, L> 
    {
        K::derive_secrets_others ( [b"hybrid_prk".as_slice(), pq_ss.as_ref(), trad_ss.as_ref(), pq_ct.as_ref(), pq_pk.as_ref(), trad_ct.as_ref(), trad_pk.as_ref(), &LB::LABEL], [L::U16.to_be_bytes().as_slice(), b"shared_secret"])
    }
}



///
/// A HybridKem combines two different KEMs, typically a post quantum KEM and a traditional KEM
/// Four type parameters are required
/// - The first KEM
/// - The second KEM
/// - A combiner
/// - A generator
/// 

//pub struct SplitSeed;
// impl<M, C, COM> GenerateDeterministic3 for HybridKem<M, C, COM, SplitSeed>
// where   M: Kem + FromSeed,
//         C: Kem + FromSeed,
//         COM: HybridCombiner + Default,

//         M::SeedSize: Add<C::SeedSize>,
//         Sum<M::SeedSize, C::SeedSize>: ArraySize + Sub<M::SeedSize, Output = C::SeedSize>,
// {
//     type SeedSize = Sum<M::SeedSize, C::SeedSize>;
//     type Public = HybridEncapsulator<M,C,COM,SplitSeed>;
//     type Private = HybridDecapsulator<M,C,COM,SplitSeed>;
//     type Error = ();
//     fn generate_deterministic(seed: &Array::<u8, Self::SeedSize>) -> Result<(Self::Public, Self::Private), Self::Error> 
//     {
//         let (seed1, seed2) = seed.split_ref();

//         let (decapsulator1, encapsulator1 ) = M::from_seed(seed1);
//         let (decapsulator2, encapsulator2 ) = C::from_seed(seed2);

//         let encapsulation_key = HybridEncapsulator{encapsulator1, encapsulator2, phantom: PhantomData, phantom2: PhantomData};
//         Ok((encapsulation_key.clone(),  
//              HybridDecapsulator{decapsulator1, decapsulator2, encapsulation_key, phantom: PhantomData, seed: None, phantom2: PhantomData}))
//     }
// }


//pub struct ExpandSeed<N: Unsigned, K: Kdf> (PhantomData<N>, PhantomData<K>);

pub type DecapsulationKeySize<K> = <<K as Kem>::DecapsulationKey as KeySizeUser>::KeySize;
pub type EncapsulationKeySize<K> = <<K as Kem>::EncapsulationKey as KeySizeUser>::KeySize;

pub type SharedKeySize = U32;

pub struct HybridKem<M: Kem, C: Kem, COM> (PhantomData<M>, PhantomData<C>, PhantomData<COM>);

impl<M: Kem, T: Kem, B> Kem for HybridKem<M, T, B>
where 
    M: Kem,
    T: Kem,
    B: Default + Sync + Send + 'static + HybridCombiner<SharedKeySize>, // Self::SharedKeySize
    M::DecapsulationKey: TryDecapsulate,
    M::CiphertextSize: Add<T::CiphertextSize>,
    
    EncapsulationKeySize<M>: Add<EncapsulationKeySize<T>>, 
    Sum<EncapsulationKeySize<M>, EncapsulationKeySize<T>>: ArraySize,
    
    Sum<M::CiphertextSize, T::CiphertextSize>: Sub<M::CiphertextSize, Output=T::CiphertextSize> + ArraySize,
{
    type EncapsulationKey = HybridEncapsulator<M, T, B>;
    type DecapsulationKey = HybridDecapsulator<M, T, B>;
    type CiphertextSize = Sum<M::CiphertextSize, T::CiphertextSize>;
    type SharedKeySize = SharedKeySize;

    fn generate_keypair_from_rng<R: rand::prelude::CryptoRng>(
        rng: &mut R,
    ) -> (kem::DecapsulationKey<Self>, kem::EncapsulationKey<Self>)
    {
        let (decapsulator1, encapsulator1) = M::generate_keypair_from_rng(rng);
        let (decapsulator2, encapsulator2) = T::generate_keypair_from_rng(rng);

        let encapsulation_key = HybridEncapsulator{encapsulator1, encapsulator2, phantom: PhantomData};
        
        (HybridDecapsulator{decapsulator1, decapsulator2, encapsulation_key: encapsulation_key.clone(), phantom: PhantomData, seed: None}, 
            encapsulation_key)
    }
}







// impl<M, T, B: > Capsulator2 for HybridKem<M, T, B>
// where 
//     M: Kem,
//     T: Kem,
//     B: HybridCombiner + Default + Sync + Send + 'static,

//     M::DecapsulationKey: TryDecapsulate,
//     T::DecapsulationKey: TryDecapsulate,

//     M::CiphertextSize: Add<T::CiphertextSize> + ArraySize, 
//     Sum<M::CiphertextSize, T::CiphertextSize>: Sub<M::CiphertextSize, Output=T::CiphertextSize> + ArraySize, 

//     EncapsulationKeySize<M>: Add<EncapsulationKeySize<T>>,
//     Sum<EncapsulationKeySize<M>, EncapsulationKeySize<T>>: ArraySize,
// {

// }

impl<M: Kem, C: Kem, COM> Ord for HybridKem<M, C, COM>
{
    fn cmp(&self, _other: &Self) -> std::cmp::Ordering {
        todo!()
    }
}
impl<M: Kem, C: Kem, COM> Eq for HybridKem<M, C, COM>
{

}
impl<M: Kem, C: Kem,  COM> Debug for HybridKem<M, C, COM>
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("HybridKem").field(&self.0).field(&self.1).field(&self.2).finish()
    }
}
impl<M: Kem, C: Kem, COM> PartialEq for HybridKem<M, C, COM>
{
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0 && self.1 == other.1 && self.2 == other.2
    }
}
impl<M: Kem, C: Kem, COM> PartialOrd for HybridKem<M, C, COM>
{
    fn partial_cmp(&self, _other: &Self) -> Option<std::cmp::Ordering> {
        todo!()
    }
}
impl<M: Kem, C: Kem, COM> Default for HybridKem<M, C, COM>
{
    fn default() -> Self {
        Self(Default::default(), Default::default(), Default::default())
    }
}
impl<M: Kem, C: Kem, COM> Copy for HybridKem<M, C, COM>
{

}
impl<M: Kem, C: Kem, COM> Clone for HybridKem<M, C, COM>
{
    fn clone(&self) -> Self {
        Self(self.0.clone(), self.1.clone(), self.2.clone())
    }
}







///
/// Encapsulator for a PQ/Traditional hybrid scheme
/// 
pub struct HybridEncapsulator<M: Kem, T: Kem, COM> {
    encapsulator1: M::EncapsulationKey,
    encapsulator2: T::EncapsulationKey,
    phantom: PhantomData<COM>,
}

impl<M: Kem, T: Kem, COM> KeySizeUser for HybridEncapsulator<M, T, COM>
where 
    EncapsulationKeySize<M>: Add<EncapsulationKeySize<T>>,
    Sum<EncapsulationKeySize<M>, EncapsulationKeySize<T>>: ArraySize,
{
    type KeySize = Sum<<M::EncapsulationKey as KeySizeUser>::KeySize, <T::EncapsulationKey as KeySizeUser>::KeySize>;
} 

impl<M: Kem, T: Kem, COM> KeyExport for HybridEncapsulator<M, T, COM>
where M::EncapsulationKey: KeyExport,
    T::EncapsulationKey: KeyExport,
    EncapsulationKeySize<M>: Add<EncapsulationKeySize<T>>,
    Sum<EncapsulationKeySize<M>, EncapsulationKeySize<T>>: ArraySize,
{
    fn to_bytes(&self) -> cipher::Key<Self> {
        let pq_encap = self.encapsulator1.to_bytes();
        let trad_encap = self.encapsulator2.to_bytes();
        
        pq_encap.concat(trad_encap)
    }
} 
impl<M: Kem, T: Kem, COM> std::fmt::Debug for HybridEncapsulator<M, T, COM>
{
    fn fmt(&self, _f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        todo!()
    }
}
impl<M: Kem, T: Kem, COM> Eq for HybridEncapsulator<M, T, COM>
{

}
impl<M: Kem, T: Kem, COM> PartialEq for HybridEncapsulator<M, T, COM>
{
    fn eq(&self, _other: &Self) -> bool {
        todo!()
    }
}
impl<M: Kem, T: Kem, COM> Clone for HybridEncapsulator<M, T, COM>
{
    fn clone(&self) -> Self {
        Self { encapsulator1: self.encapsulator1.clone(), encapsulator2: self.encapsulator2.clone(), phantom: self.phantom.clone()}
    }
}
impl<M: Kem, T: Kem, B> Encapsulate for HybridEncapsulator<M, T, B>
where
    M: Kem,
    T: Kem,
    B: Default + Sync + Send + 'static + HybridCombiner<U32>, //<HybridKem<M, T, B> as Kem>::SharedKeySize>,

    EncapsulationKeySize<M>: Add<EncapsulationKeySize<T>>,
    Sum<EncapsulationKeySize<M>, EncapsulationKeySize<T>>: ArraySize,
    
    M::CiphertextSize: Add<T::CiphertextSize>,
    Sum<M::CiphertextSize, T::CiphertextSize>: ArraySize + Sub<M::CiphertextSize>,
    Sum<M::CiphertextSize, T::CiphertextSize>: Sub<M::CiphertextSize, Output=T::CiphertextSize> + ArraySize,
{
    type Kem = HybridKem<M, T, B>;

    fn encapsulate_with_rng<R>(&self, rng: &mut R) -> (kem::Ciphertext<Self::Kem>, kem::SharedKey<Self::Kem>)
    where R: rand::CryptoRng + ?Sized 
    {
        let (ct1, ss1) = self.encapsulator1.encapsulate_with_rng(rng);
        let (ct2, ss2) = self.encapsulator2.encapsulate_with_rng(rng);

        let ss = B::default().combine(ss1.as_slice(), ct1.as_slice(), &self.encapsulator1.to_bytes(), &ss2, &ct2, &self.encapsulator2.to_bytes());
        
        (ct1.concat(ct2), ss)
    }
}


pub type EncapsulationSeedSize<K> = <<K as Kem>::EncapsulationKey as EncapsulateDeterministic>::SeedSize;

impl<M, T, B> EncapsulateDeterministic for HybridEncapsulator<M, T, B>
where 
    M: Kem,
    T: Kem,
    B: HybridCombiner<SharedKeySize> + Default + Sync + Send + 'static,
    M::EncapsulationKey: EncapsulateDeterministic,
    T::EncapsulationKey: EncapsulateDeterministic,
  
    EncapsulationKeySize<M>: Add<EncapsulationKeySize<T>>,
    Sum<EncapsulationKeySize<M>, EncapsulationKeySize<T>>: ArraySize,
    
    M::CiphertextSize: Add<T::CiphertextSize>,
    Sum<M::CiphertextSize, T::CiphertextSize>: Sub<M::CiphertextSize, Output=T::CiphertextSize> + ArraySize,

    EncapsulationSeedSize<M>: Add<EncapsulationSeedSize<T>>,
    Sum<EncapsulationSeedSize<M>, EncapsulationSeedSize<T>>: ArraySize,

    <<M::EncapsulationKey as EncapsulateDeterministic>::Kem as kem::Kem>::CiphertextSize: Add<<<T::EncapsulationKey as EncapsulateDeterministic>::Kem as kem::Kem>::CiphertextSize>,
    <<<M::EncapsulationKey as EncapsulateDeterministic>::Kem as kem::Kem>::CiphertextSize as Add<<<T::EncapsulationKey as EncapsulateDeterministic>::Kem as kem::Kem>::CiphertextSize>>::Output: ArraySize,
{
    type Kem = HybridKem<M, T, B>;

    type SeedSize = Sum<<<M as Kem>::EncapsulationKey as EncapsulateDeterministic>::SeedSize, <<T as Kem>::EncapsulationKey as EncapsulateDeterministic>::SeedSize>;

    fn encapsulate_deterministic(&self, seed: &[u8]) -> (kem::Ciphertext<Self::Kem>, kem::SharedKey<Self::Kem>) {
        let (seed1, seed2) = seed.split_at(32);

        let (ct1, ss1) = self.encapsulator1.encapsulate_deterministic(seed1);
        let (ct2, ss2) = self.encapsulator2.encapsulate_deterministic(seed2);

        let ss = B::default().combine(ss1.as_slice(), ct1.as_slice(), &self.encapsulator1.to_bytes(), &ss2, &ct2, &self.encapsulator2.to_bytes());
        let ct = ct1.concat(ct2);
        
        //(ct, ss)
        (ct.as_slice().try_into().unwrap(),ss)
    }
}


impl<M: Kem, T: Kem, COM> TryKeyInit for HybridEncapsulator<M, T, COM>
where 
    EncapsulationKeySize<M>: Add<EncapsulationKeySize<T>>,
    Sum<EncapsulationKeySize<M>, EncapsulationKeySize<T>>: ArraySize,
{
    fn new(_key: &cipher::Key<Self>) -> Result<Self, InvalidKey> {
        let (public_key1_bytes, public_key2_bytes) = _key.split_at(EncapsulationKeySize::<M>::USIZE);

        let encapsulator1 = <M::EncapsulationKey as TryKeyInit>::new_from_slice(public_key1_bytes)?;
        let encapsulator2 = <T::EncapsulationKey as TryKeyInit>::new_from_slice(public_key2_bytes)?;

        Ok(Self { encapsulator1, encapsulator2, phantom: PhantomData})
    }
}







///
/// Decapsulator for a hybrid PQ/Trad KEM
/// 
pub struct HybridDecapsulator<M: Kem, C: Kem, COM> 
{
    pub decapsulator1: M::DecapsulationKey,
    pub decapsulator2: C::DecapsulationKey,
    encapsulation_key: HybridEncapsulator<M,C,COM>,
    seed: Option<Array<u8, U32>>,
    phantom: PhantomData<COM>,
}

impl<M: Kem, C: Kem, COM> HybridDecapsulator<M, C, COM>
{
    pub fn from_decapsulators(decapsulator1: M::DecapsulationKey, decapsulator2: C::DecapsulationKey) -> Self 
    {   
        let encapsulation_key = HybridEncapsulator{ encapsulator1: decapsulator1.encapsulation_key().clone(), encapsulator2: decapsulator2.encapsulation_key().clone(), phantom: PhantomData };
        
        Self { decapsulator1, decapsulator2, encapsulation_key, seed: None, phantom: PhantomData}
    }
    
}




//type EncodedSize2<X> = <<X as Capsulator>::Decapsulator as EncodedSizeUser2>::EncodedSize;

// impl<M: Capsulator, C: Capsulator, COM: HybridCombiner> EncodedSizeUser2 for HybridDecapsulator<M, C, COM>
// where 
//     C::Decapsulator: EncodedSizeUser2,
//     M::Decapsulator: EncodedSizeUser2,
//     EncodedSize2<M>: Add<EncodedSize2<C>>,
//     Sum<EncodedSize2<M>, EncodedSize2<C>>: Sub<EncodedSize2<M>, Output=EncodedSize2<C>> + ArrayLength,
// {
//     type EncodedSize = Sum<EncodedSize2<M>, EncodedSize2<C>>;
    
//     fn from_bytes(enc: &crate::Encoded<Self>) -> Self {
//         let (key_1_bytes, key_2_bytes) = enc.split();

//         let decapsulator1 = M::Decapsulator::from_bytes(key_1_bytes);
//         let decapsulator2 = C::Decapsulator::from_bytes(key_2_bytes);
//         Self { decapsulator1, decapsulator2, phantom: PhantomData, seed: None, phantom2: PhantomData}
//     }
//     fn as_bytes(&self) -> crate::Encoded<Self> {
//         let sk1_ha = self.decapsulator1.as_bytes();
//         let sk2_ha = self.decapsulator2.as_bytes();
//         sk1_ha.concat(sk2_ha)
//     }
// }



// impl<M: Capsulator, C: Capsulator, COM: HybridCombiner> DecodeGenericArray<Self> for HybridDecapsulator<M, C, COM>
// where 
//     C::Decapsulator: EncodedSizeUser2,
//     M::Decapsulator: EncodedSizeUser2,
//     EncodedSize2<M>: Add<EncodedSize2<C>>,
//     Sum<EncodedSize2<M>, EncodedSize2<C>>: Sub<EncodedSize2<M>, Output=EncodedSize2<C>> + ArrayLength<u8>,
// {
//     type EncodedLen = Sum<EncodedSize2<M>, EncodedSize2<C>>;
    
//     type Error = ();
    
//     fn decode(encoded_bytes: &GenericArray<u8, Self::EncodedLen>) -> Result<Self, Self::Error> {
//         let (key_1_bytes, key_2_bytes) = encoded_bytes.split(); //Split::split(enc);

//         //let decapsulator1 = M::Decapsulator::from_bytes(GenericArray::from_slice(key_1_bytes));
//         let decapsulator1 = M::Decapsulator::from_bytes(key_1_bytes);
//         let decapsulator2 = C::Decapsulator::from_bytes(key_2_bytes);
//         Ok(Self { decapsulator1, decapsulator2, phantom: PhantomData, seed: None, phantom2: PhantomData})
//     }
 
// }

// impl<M, C, COM> TryFrom<&[u8]> for HybridDecapsulator<M, C, COM>
// where 
//     M: Kem,
//     C: Kem,
//     M::DecapsulationKey:  KeySizeUser + KeyInit, // + EncodedSizeUser2,
//     C::DecapsulationKey: for<'a> TryFrom<&'a [u8]>,
//     COM: HybridCombiner + Default,
// {
//     type Error = TryFromSliceError;
//     fn try_from(value: &[u8]) -> Result<Self, Self::Error> {

//         if let Ok(_seed) = Array::<u8, U32>::try_from(value)
//         {
//             todo!()
//         }
//         else if value.len() > <M::DecapsulationKey as KeySizeUser>::KeySize::USIZE
//         {
//             //println! ( "input_len={}, expected_len={}", value.len()::SeedSize::USIZE);
//             let (key_1_bytes, key_2_bytes) = value.split_at(<M::DecapsulationKey as KeySizeUser>::KeySize::USIZE);
//             let decapsulator1 = M::DecapsulationKey::new(key_1_bytes.try_into()?);
//             let Ok(decapsulator2) = C::DecapsulationKey::try_from(key_2_bytes) else { panic! ("Unhandled")};
//             let encapsulation_key = HybridEncapsulator{encapsulator1: decapsulator1.encapsulation_key().clone(), encapsulator2: decapsulator2.encapsulation_key().clone(), phantom: PhantomData, phantom2: PhantomData};
//             Ok(Self { decapsulator1, decapsulator2, encapsulation_key, phantom: PhantomData, seed: None, phantom2: PhantomData})
//         }
//         else {
//             //Err(())
//             panic!("HHHH")
//         }
//     }
// }

impl<M, C, COM> TryKeyInit for HybridDecapsulator<M, C, COM>
where 
    M: Kem + FromSeed,
    C: Kem + FromSeed,
    M::DecapsulationKey: KeyInit,
    C::DecapsulationKey: TryKeyInit,
    COM: Default,
    M::SeedSize: Add<C::SeedSize>,
    Sum<M::SeedSize, C::SeedSize>: ArraySize + Sub<M::SeedSize, Output = C::SeedSize>,
{
    fn new(key: &kem::Key<Self>) -> Result<Self, InvalidKey> 
    {
        Ok(KeyInit::new(key))
        // let expanded = shake::Shake256::derive_secret_other::<Sum<M::SeedSize, C::SeedSize>>(key.as_slice(), &[]).unwrap();

        // let (key_1_bytes, key_2_bytes) = key.split_at(<M::DecapsulationKey as KeySizeUser>::KeySize::USIZE);
        // let decapsulator1 = M::DecapsulationKey::new(&key_1_bytes.try_into().map_err(|_|InvalidKey)?);
        // let decapsulator2 = C::DecapsulationKey::new_from_slice(key_2_bytes)?;// else { panic! ("Unhandled")};
        // let encapsulation_key = HybridEncapsulator{encapsulator1: decapsulator1.encapsulation_key().clone(), encapsulator2: decapsulator2.encapsulation_key().clone(), phantom: PhantomData};
        // Ok(Self { decapsulator1, decapsulator2, encapsulation_key, phantom: PhantomData, seed: None})
    }
    fn new_from_slice(key: &[u8]) -> Result<Self, kem::InvalidKey> {
        let (key_1_bytes, key_2_bytes) = key.split_at(<M::DecapsulationKey as KeySizeUser>::KeySize::USIZE);
        let decapsulator1 = M::DecapsulationKey::new_from_slice(key_1_bytes).map_err(|_|InvalidKey)?;
        let decapsulator2 = C::DecapsulationKey::new_from_slice(key_2_bytes)?;
        let encapsulation_key = HybridEncapsulator{encapsulator1: decapsulator1.encapsulation_key().clone(), encapsulator2: decapsulator2.encapsulation_key().clone(), phantom: PhantomData};
        Ok(Self { decapsulator1, decapsulator2, encapsulation_key, phantom: PhantomData, seed: None})
    }
}

impl<M, T, B> KeySizeUser for HybridDecapsulator<M, T, B>
where 
    M: Kem,
    T: Kem,
    B: Default,
{
    type KeySize = U32;
}




#[cfg(feature="rustcrypto-sha3")] // Uses Shake256..
impl<M, C, B> KeyInit for HybridDecapsulator<M, C, B>
where 
    M: Kem + FromSeed,
    C: Kem + FromSeed,
    M::DecapsulationKey: KeySizeUser,
    C::DecapsulationKey: KeySizeUser,
    B: Default,

    M::SeedSize: Add<C::SeedSize>,
    Sum<M::SeedSize, C::SeedSize>: ArraySize + Sub<M::SeedSize, Output = C::SeedSize>,
{
    // Expands given seed to produce the two seeds needed for the components
    fn new(seed: &cipher::Key<Self>) -> Self {
        //let expanded = shake::Shake256::derive_secret_other_array::<Sum<M::SeedSize, C::SeedSize>>(seed.as_slice(), &[]).unwrap();
        let expanded = <shake::Shake256 as Kdf<Sum<M::SeedSize, C::SeedSize>>>::derive_secret_other(seed.as_slice(), &[]);
        
        let (seed1, seed2) = Array::split::<<M as FromSeed>::SeedSize>(expanded);
        let (decapsulator1, encapsulator1)= M::from_seed(&seed1);
        let (decapsulator2, encapsulator2)= C::from_seed(&seed2);

        Self { decapsulator1, decapsulator2, encapsulation_key: HybridEncapsulator { encapsulator1, encapsulator2, phantom: PhantomData}, 
            seed: Some(*seed), phantom: PhantomData}
    }
    // Works with expanded seed
    fn new_from_slice(key: &[u8]) -> Result<Self, cipher::InvalidLength> {
        let (key_1_bytes, key_2_bytes) = key.split_at(<M::DecapsulationKey as KeySizeUser>::KeySize::USIZE);
        let (decapsulator1, encapsulator1) = M::from_seed(key_1_bytes.try_into().unwrap());
        let (decapsulator2, encapsulator2) = C::from_seed(key_2_bytes.try_into().unwrap());
        let encapsulation_key = HybridEncapsulator{encapsulator1, encapsulator2, phantom: PhantomData};
        Ok(Self { decapsulator1, decapsulator2, encapsulation_key, phantom: PhantomData, seed: None})
    }
}


impl<M, T, COM> KeyExport for HybridDecapsulator<M, T, COM>
where 
    M: Kem,
    T: Kem,
    COM: Default,
{
    fn to_bytes(&self) -> cipher::Key<Self> {
        self.seed.unwrap()
    }
}




// impl<M: Kem, T: Kem, COM: HybridCombiner> KeyInit for HybridEncapsulator<M, T, COM>
// where M::EncapsulationKey: KeySizeUser,
//     //T::EncapsulationKey: KeySizeUser,
//     <<M as Kem>::EncapsulationKey as KeySizeUser>::KeySize: Add<<<T as Kem>::EncapsulationKey as KeySizeUser>::KeySize>,
//     <<<M as Kem>::EncapsulationKey as KeySizeUser>::KeySize as Add<<<T as Kem>::EncapsulationKey as KeySizeUser>::KeySize>>::Output: ArraySize,

//     M::EncapsulationKey: TryKeyInit,
//     T::EncapsulationKey: for<'a> TryFrom<&'a [u8]> + TryKeyInit,
// {
//     fn new(_key: &cipher::Key<Self>) -> Self {

//         let (public_key1_bytes, public_key2_bytes) = _key.split_at(<M::EncapsulationKey as KeySizeUser>::KeySize::USIZE);

//         let encapsulator1 = <M::EncapsulationKey as TryKeyInit>::new(&public_key1_bytes.try_into().unwrap()).unwrap();
//         let encapsulator2 = <T::EncapsulationKey as TryKeyInit>::new(public_key2_bytes.try_into().unwrap()).unwrap();

//         Self { encapsulator1, encapsulator2, phantom: PhantomData, phantom2: PhantomData}
//         //todo!()
//         //Self::try_from(key.as_slice()).unwrap()
//     }
// }




impl<M, C, COM> Generate for HybridDecapsulator<M, C, COM>
where 
    M: Kem,
    C: Kem,
    COM: Default,
{
    fn try_generate_from_rng<R: rand::TryCryptoRng + ?Sized>(_rng: &mut R) -> Result<Self, R::Error> {
        let decapsulator1 = M::DecapsulationKey::try_generate_from_rng(_rng)?;
        let decapsulator2 = C::DecapsulationKey::try_generate_from_rng(_rng)?;

        let encapsulation_key = HybridEncapsulator{encapsulator1: decapsulator1.encapsulation_key().clone(), encapsulator2: decapsulator2.encapsulation_key().clone(), phantom: PhantomData};
        Ok(HybridDecapsulator{decapsulator1, decapsulator2, encapsulation_key, seed: None, phantom: PhantomData})
    }
    
}


impl<M, C, COM> kem::Decapsulator for HybridDecapsulator<M, C, COM>
where 
    M: Kem,
    C: Kem,
    COM: Default + Sync + Send +  'static + HybridCombiner<SharedKeySize>,
    M::DecapsulationKey: TryDecapsulate,
    C::DecapsulationKey: TryDecapsulate,

    M::CiphertextSize: Add<C::CiphertextSize> + ArraySize,
    Sum<M::CiphertextSize, C::CiphertextSize>: Sub<M::CiphertextSize, Output=C::CiphertextSize> + ArraySize,

    EncapsulationKeySize<M>: Add<EncapsulationKeySize<C>>,
    Sum<EncapsulationKeySize<M>, EncapsulationKeySize<C>>: ArraySize,
{
    type Kem = HybridKem<M, C, COM>;

    fn encapsulation_key(&self) -> &kem::EncapsulationKey<Self::Kem> {
        &self.encapsulation_key
    }
}

impl<M, C, COM> TryDecapsulate for HybridDecapsulator<M, C, COM>
where 
    C: Kem,
    M: Kem,
    COM: HybridCombiner<SharedKeySize> + Default + Sync + Send + 'static,

    M::DecapsulationKey: TryDecapsulate,
    C::DecapsulationKey: TryDecapsulate,
    
    M::CiphertextSize: Add<C::CiphertextSize> + ArraySize,
    EncapsulationKeySize<M>: Add<EncapsulationKeySize<C>>,
    Sum<EncapsulationKeySize<M>, EncapsulationKeySize<C>>: ArraySize,

    Sum<M::CiphertextSize, C::CiphertextSize>: Sub<M::CiphertextSize, Output=C::CiphertextSize> + ArraySize,
{
    type Error = kem::InvalidKey;

    fn try_decapsulate(&self, ct: &kem::Ciphertext<Self::Kem>) -> Result<SharedKey<Self::Kem>, InvalidKey> {
        let (ct1, ct2 ) = ct.clone().split(); // Split::<u8, M::CiphertextSize>::split(encapsulated_key);
        
        let ss1 = self.decapsulator1.try_decapsulate(&ct1).unwrap();
        let ss2 = self.decapsulator2.try_decapsulate(&ct2).unwrap();

        let pub1 = Decapsulator::encapsulation_key(&self.decapsulator1);
        let pub2 = Decapsulator::encapsulation_key(&self.decapsulator2);

        let ss = COM::default().combine(ss1, ct1, pub1.to_bytes(), ss2, ct2, pub2.to_bytes());
        Ok(ss)
    }
}



// impl<M: Kem, T: Kem, COM: HybridCombiner> GetRecipientPublicKeyBytes for HybridEncapsulator<M, T, COM>
// where 
//     T::EncapsulationKey: GetRecipientPublicKeyBytes,
//     M::EncapsulationKey: GetRecipientPublicKeyBytes,
// {
//     type EncodedLen = U0; //<Self as EncodedSizeUser2>::EncodedSize;

//     //fn get_recipient_public_key_bytes(&self) -> GenericArray<u8, Self::EncodedLen> {
//     fn get_recipient_public_key_bytes<'a>(&'a self) -> Cow<'a, [u8]> {
//         let mut pq_encap = self.encapsulator1.get_recipient_public_key_bytes().to_vec();
//         let trad_encap = self.encapsulator2.get_recipient_public_key_bytes();
        
//         pq_encap.extend_from_slice(&trad_encap);
//         pq_encap.into()
//     }
// }

// type EncodedSize3<X> = <<X as Capsulator>::Encapsulator as EncodeGenericArray<<X as Capsulator>::Encapsulator>>::EncodedLen;
// impl<M: Capsulator, T: Capsulator, COM: HybridCombiner> EncodeGenericArray<Self> for HybridEncapsulator<M, T, COM>
// where 
//     T::Encapsulator: EncodeGenericArray<T::Encapsulator>,
//     M::Encapsulator: EncodeGenericArray<M::Encapsulator>,
//     EncodedSize3<M>: Add<EncodedSize3<T>>,
//     Sum<EncodedSize3<M>, EncodedSize3<T>>: Sub<EncodedSize3<M>, Output=EncodedSize3<T>> + ArrayLength<u8>,
// {
//     type EncodedLen = Sum<EncodedSize3<M>, EncodedSize3<T>>;

//     fn encode(source: &Self) -> GenericArray<u8, Self::EncodedLen> {
//         let pq_encap = <M as Capsulator>::Encapsulator::encode(&source.encapsulator1);
//         let trad_encap = <T as Capsulator>::Encapsulator::encode(&source.encapsulator2);
        
//         //pq_encap.concat(trad_encap)
//         generic_array::sequence::Concat::concat(pq_encap, trad_encap)
//     }
// }

// type EncodedSize4<X> = <<X as Capsulator>::Encapsulator as DecodeGenericArray<<X as Capsulator>::Encapsulator>>::EncodedLen;
// //type EncodedSize4<X> = <<X as Capsulator>::Encapsulator as EncodeGenericArray<<X as Capsulator>::Encapsulator>>::EncodedLen;
// impl<M: Capsulator, T: Capsulator, COM: HybridCombiner> DecodeGenericArray<Self> for HybridEncapsulator<M, T, COM>
// where 
//     T::Encapsulator: DecodeGenericArray<T::Encapsulator>,
//     M::Encapsulator: DecodeGenericArray<M::Encapsulator>,
//     EncodedSize4<M>: Add<EncodedSize4<T>>,
//     Sum<EncodedSize4<M>, EncodedSize4<T>>: Sub<EncodedSize4<M>, Output=EncodedSize4<T>> + ArrayLength<u8>,
// {
//     type EncodedLen = Sum<EncodedSize4<M>, EncodedSize4<T>>;
    
//     type Error = ();
    
//     fn decode(encoded_bytes: &GenericArray<u8, Self::EncodedLen>) -> Result<Self, Self::Error> {
//         let (pq_public_key_bytes, trad_public_key_bytes) = encoded_bytes.split(); //Split::<u8, EncodedSize<M>>::split(encoded_encapsulator.clone());

//         let Ok(encapsulator1) = M::Encapsulator::decode(&pq_public_key_bytes) else { return Err(())};
//         let Ok(encapsulator2) = T::Encapsulator::decode(&trad_public_key_bytes) else { return Err(())};

//         Ok(Self { encapsulator1, encapsulator2, phantom: PhantomData})
//     }

// }


// impl<M: Kem, T: Kem, COM: HybridCombiner> TryFrom<&[u8]> for HybridEncapsulator<M, T, COM>
// where 
//     M::EncapsulationKey: KeySizeUser + KeyInit,
//     T::EncapsulationKey: for<'a> TryFrom<&'a [u8]>,
// {
//     type Error = TryFromSliceError;
//     fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
//         let (pq_public_key_bytes, trad_public_key_bytes) = value.split_at(<M::EncapsulationKey as KeySizeUser>::KeySize::USIZE);
//         let encapsulator1 = <M::EncapsulationKey as KeyInit>::new(&Array::try_from(pq_public_key_bytes)?);
//         let Ok(encapsulator2) = T::EncapsulationKey::try_from(trad_public_key_bytes) else { panic!( "Error") };
        
//         Ok(Self{encapsulator1, encapsulator2, phantom: PhantomData, phantom2: PhantomData})
//     }
// }

// impl<M: Capsulator, T: Capsulator, COM: HybridCombiner> HybridEncapsulator<M, T, COM>
// where 
//     //M::Encapsulator: EncodedSizeUser2,

//     M::Encapsulator: KeySizeUser + KeyInit,
//     T::Encapsulator: for<'a> TryFrom<&'a [u8]>,
// {
//     pub fn from_slice(value: &[u8]) -> Result<Self, ()>
//     {
//         Self::try_from(value)
//     }
// }


// impl<M: Kem, C: Kem, COM: HybridCombiner> EncapsulateOld<GenericArray<u8, Sum<M::CiphertextSizeOld, C::CiphertextSizeOld>>, Array<u8, U32>> for HybridEncapsulator<M, C, COM>
// where 
//     C::EncapsulationKey: EncapsulateOld<GenericArray<u8, C::CiphertextSizeOld>, Array<u8,C::SharedKeySizeOld>> + GetRecipientPublicKeyBytes, // + EncodedSizeUser2,
//     COM: Default,
//     C::SharedKeySizeOld: ArraySize,
//     C::CiphertextSizeOld: ArrayLength, //<u8>,
//     M::Encapsulator: GetRecipientPublicKeyBytes, //EncodedSizeUser2,
//     M::CiphertextSizeOld: Add<C::CiphertextSizeOld>,
//     Sum<M::CiphertextSizeOld, C::CiphertextSizeOld>: ArrayLength, //<u8>,
// {
//     type Error = ();

//     fn encapsulate_old(&self, rng: &mut impl CryptoRngCore) -> Result<(GenericArray<u8, Sum<M::CiphertextSizeOld, C::CiphertextSizeOld>>, Array<u8, U32>), Self::Error> {
//         let (ct1, ss1) = self.encapsulator1.encapsulate_old(rng).unwrap();
//         let (ct2, ss2) = self.encapsulator2.encapsulate_old(rng).unwrap();

//         let ss = COM::default().combine(ss1.as_slice(), ct1.as_slice(), &self.encapsulator1.get_recipient_public_key_bytes(), &ss2, &ct2, &self.encapsulator2.get_recipient_public_key_bytes());
//         let ct = ct1.concat(ct2);
        
//         Ok((ct,ss))
//     }
// }


//type Encapsulator<X> = <X::Encapsulator as EncapsulateDeterministic2<GenericArray<u8::X::CiphertextSize>, Array<u8, X::SharedKeySize>>>;


// impl<M: Kem, C: Kem, COM: HybridCombiner> EncapsulateDeterministic2<GenericArray<u8, Sum<M::CiphertextSize, C::CiphertextSize>>, Array<u8, U32>> for HybridEncapsulator<M, C, COM>
// where 
//     COM: Default,
//     C::EncapsulationKey: EncapsulateDeterministic2<Ciphertext<C>, SharedKey<C>> + GetRecipientPublicKeyBytes, // + EncodedSizeUser2,
//     M::CiphertextSize: Add<C::CiphertextSize>,
//     C::SharedKeySize: ArraySize,
//     C::CiphertextSize: ArrayLength, //<u8>,
//     Sum<M::CiphertextSize, C::CiphertextSize>: ArrayLength, //<u8>,
    
//     M::EncapsulationKey: EncapsulateDeterministic2<Ciphertext<M>, SharedKey<M>> + GetRecipientPublicKeyBytes, // + EncodedSizeUser2,
//     SeedSize<M>: Add<SeedSize<C>>,
//     Sum<SeedSize<M>, SeedSize<C>>: ArraySize + Sub<SeedSize<M>, Output = SeedSize<C>>,

//     //<<<M::Encapsulator as EncapsulateDeterministic2<Ciphertext<M>, SharedKey<M>>>::SeedSize as Add<<C::Encapsulator as EncapsulateDeterministic2<Ciphertext<C>, SharedKey<C>>>::SeedSize>>::Output as Sub<<M::Encapsulator as EncapsulateDeterministic2<Ciphertext<M>, SharedKey<M>>>::SeedSize>>::Output: ArraySize,
//     //<Sum<<M::Encapsulator as EncapsulateDeterministic2<Ciphertext<M>, SharedKey<M>>>::SeedSize, <C::Encapsulator as EncapsulateDeterministic2<Ciphertext<C>, SharedKey<C>>>::SeedSize>> as Sub<<M::Encapsulator as EncapsulateDeterministic2<Ciphertext<M>, SharedKey<M>>>::SeedSize>>::Output: ArraySize,
// {
//     type Error = ();
//     type SeedSize = Sum<SeedSize<M>, SeedSize<C>>;

//     fn encapsulate_deterministic(&self, seed: &[u8]) -> Result<(GenericArray<u8, Sum<M::CiphertextSizeOld, C::CiphertextSizeOld>>, Array<u8, U32>), Self::Error> {
//         //let (seed1, seed2) = seed.split_ref();
//         let (seed1, seed2) = seed.split_at(SeedSize::<M>::USIZE);

//         let Ok((ct1, ss1)) = self.encapsulator1.encapsulate_deterministic(seed1) else { return Err(())};
//         let Ok((ct2, ss2)) = self.encapsulator2.encapsulate_deterministic(seed2) else { return Err(())};

//         let ss = COM::default().combine(ss1.as_slice(), ct1.as_slice(), &self.encapsulator1.get_recipient_public_key_bytes(), &ss2, &ct2, &self.encapsulator2.get_recipient_public_key_bytes());
//         let ct = ct1.concat(ct2);
        
//         Ok((ct,ss))
//     }
// }

// impl<M, C, COM, N: ArraySize, K: Kdf+Default> GenerateDeterministic3 for HybridKem<M, C, COM, ExpandSeed<N, K>>
// where   M: Kem + FromSeed,
//         C: Kem + FromSeed,
//         COM: Default + HybridCombiner,

//         M::SeedSize: Add<C::SeedSize>,
//         Sum<M::SeedSize,C::SeedSize>: ArraySize + Sub<M::SeedSize, Output=C::SeedSize>,
// {
//     type SeedSize = U32;
//     type Public = HybridEncapsulator<M,C,COM,ExpandSeed<N,K>>;
//     type Private = HybridDecapsulator<M,C,COM,ExpandSeed<N,K>>;
//     type Error = ();
//     fn generate_deterministic(seed: &Array::<u8, Self::SeedSize>) -> Result<(Self::Public, Self::Private), Self::Error> {
//         let expanded = K::derive_secret_other::<Sum<M::SeedSize, C::SeedSize>>(seed.as_slice(), &[]).unwrap();
        
//         let (seed1, seed2) = Array::split::<<M as FromSeed>::SeedSize>(expanded);
//         let (decapsulator1, encapsulator1)= M::from_seed(&seed1);
//         let (decapsulator2, encapsulator2)= C::from_seed(&seed2);

//         let encapsulation_key = HybridEncapsulator{encapsulator1: encapsulator1.clone(), encapsulator2: encapsulator2.clone(), phantom: PhantomData, phantom2: PhantomData};
//         Ok((encapsulation_key.clone(),  
//               HybridDecapsulator{decapsulator1, decapsulator2, encapsulation_key, phantom: PhantomData, seed: Some(seed.clone()), phantom2: PhantomData}))
//     }
// }



// pub struct DeriveExpandSeed<N: Unsigned, K: Kdf, KI: Kdf> (PhantomData<N>, PhantomData<K>, PhantomData<KI>);

// impl<M, C, COM, N: ArraySize, K, KI> GenerateDeterministic3 for HybridKem<M, C, COM, DeriveExpandSeed<N, K, KI>>
// where   KI:Kdf+Default,
//         K: Kdf+Default,
//         COM: HybridCombiner + Default,
//         M: Kem + FromSeed,
//         C: Kem + FromSeed,
        
//         //M::DecapsulationKey: KeyInit, // + EncodedSizeUser2,
//         //C::DecapsulationKey: KeySizeUser, //for<'a> TryFrom<&'a [u8]>,

//         M::SeedSize: Add<C::SeedSize>,
//         //<M::SeedSize as Add<C::SeedSize>>::Output: ArraySize,
//         Sum<M::SeedSize,C::SeedSize>: ArraySize + Sub<M::SeedSize, Output=C::SeedSize>,

//         // M::CiphertextSize: Add<C::CiphertextSize>,
//         // M::SeedSize: Add<C::SeedSize>,
//         // Sum<M::CiphertextSize, C::CiphertextSize>: ArrayLength, //<u8>,
//         // Sum<M::SeedSize, C::SeedSize>: ArraySize + Sub<M::SeedSize, Output = C::SeedSize>,
//         // Sum<M::CiphertextSize, C::CiphertextSize>: Sub<M::CiphertextSize, Output=C::CiphertextSize> + ArrayLength, //<u8>,
// {
//     type SeedSize = U32;
//     type Public = HybridEncapsulator<M,C,COM,DeriveExpandSeed<N, K, KI>>;
//     type Private = HybridDecapsulator<M,C,COM,DeriveExpandSeed<N, K, KI>>;
//     type Error = ();

//     fn generate_deterministic(_seed: &Array::<u8, Self::SeedSize>) -> Result<(Self::Public, Self::Private), Self::Error> {
//         let derived_seed = KI::derive_secret_others(_seed.as_slice(), None).unwrap();
//         let (encapsulator,decapsulator) = HybridKem::<M, C, COM, ExpandSeed<U32, K>>::generate_deterministic(&derived_seed).map_err(|_|())?;
        
//         let encapsulator_n = HybridEncapsulator{encapsulator1: encapsulator.encapsulator1, encapsulator2: encapsulator.encapsulator2, phantom: PhantomData, phantom2: PhantomData};
//         Ok(( encapsulator_n.clone(),
//             HybridDecapsulator{decapsulator1: decapsulator.decapsulator1, decapsulator2: decapsulator.decapsulator2, 
//                 encapsulation_key: encapsulator_n, phantom: PhantomData, seed: Some(derived_seed), phantom2: PhantomData}))
//     }
// }

