//! Hybrid kems uses two other kems which are combined to output a single value.
//! 
//! A cryptographic break in either KEM will not compromise the overall hybrid KEM.
//! 
use std::fmt::Debug;
use std::marker::PhantomData;
use std::ops::{Add, Sub};

use crate::{Capsulator, CryptoRngCore, Decapsulate, Encapsulate, EncapsulateDeterministic2, EncodeSeed, EncodedSizeUser2, GenerateCapsulatorFromSeed, GetEncapsulator, GetRecipientPublicKeyBytes, Label};

use cipher::typenum::{Sum, Unsigned};
use generic_array::{ArrayLength, GenericArray};
use generic_array::sequence::Split;
use generic_array::sequence::Concat;
use elliptic_curve::consts::*;
use kdfs::hybrid_array::{Array, ArraySize};
use kdfs::Kdf;
//use x25519_dalek::EphemeralSecret;

/// 
/// Combiner for use with hybrid KEMS. 
/// Combiner takes the shared secret, ciphertext and public key of both schemes and derives a single output
/// 
pub trait HybridCombiner {
    fn combine<L: ArraySize> ( &self, ss1: impl AsRef<[u8]>, ct1: impl AsRef<[u8]>, pk1: impl AsRef<[u8]>, ss2: impl AsRef<[u8]>, ct2: impl AsRef<[u8]>, pk2: impl AsRef<[u8]> ) -> Array<u8, L>;
}


///
/// QsfCombiner which combines the shared secret from KEM1 and the shared secret, ciphertext and public key from KEM2
/// Commonly used with one of the ML-KEM algorithms as KEM1 and an ECDH KEM as KEM2
/// 
pub struct QsfCombiner<K:Kdf, LB: Label> { kdf: K, phantom: PhantomData<LB>}
impl<K: Kdf + Default, LB: Label> Default for QsfCombiner<K, LB> {
    fn default() -> Self {
        return Self{ kdf: K::default(), phantom: PhantomData}
    }
}
impl<K: Kdf + Clone, LB: Label> HybridCombiner for QsfCombiner<K, LB>
{
    fn combine<L: ArraySize> ( &self, ss1: impl AsRef<[u8]>, _ct1: impl AsRef<[u8]>, _pk1: impl AsRef<[u8]>, ss2: impl AsRef<[u8]>, ct2: impl AsRef<[u8]>, pk2: impl AsRef<[u8]> ) -> Array<u8, L> {
        self.kdf.derive_self_secrets_other ([ss1.as_ref(), ss2.as_ref(), ct2.as_ref(), pk2.as_ref()], LB::LABEL)
    }
}

///
/// QsfCombiner which combines the shared secret from KEM2 and the shared secret, ciphertext and public key from KEM1 and the 
/// Commonly used with an ECDH KEM as KEM1 and one of the ML-KEM algorithms as KEM2
/// 
pub struct QsfCombiner2<K:Kdf, LB: Label> { kdf: K, phantom: PhantomData<LB>}
impl<K: Kdf + Default, LB: Label> Default for QsfCombiner2<K, LB> {
    fn default() -> Self {
        return Self{ kdf: K::default(), phantom: PhantomData}
    }
}
impl<K: Kdf + Clone, LB: Label> HybridCombiner for QsfCombiner2<K, LB>
{
    fn combine<L: ArraySize> ( &self, ss1: impl AsRef<[u8]>, ct1: impl AsRef<[u8]>, pk1: impl AsRef<[u8]>, ss2: impl AsRef<[u8]>, _ct2: impl AsRef<[u8]>, _pk2: impl AsRef<[u8]> ) -> Array<u8, L> {
        self.kdf.derive_self_secrets_other ([ss2.as_ref(), ss1.as_ref(), ct1.as_ref(), pk1.as_ref()], LB::LABEL)
    }
}

///
/// QsfCombiner which combines the shared secret, ciphertext and public key from KEM1 and the share secret from KEM2
/// Commonly used with an ECDH KEM as KEM1 and one of the ML-KEM algorithms as KEM2
/// 
pub struct QsfCombiner3<K:Kdf, LB: Label> { kdf: K, phantom: PhantomData<LB>}
impl<K: Kdf + Default, LB: Label> Default for QsfCombiner3<K, LB> {
    fn default() -> Self {
        return Self{ kdf: K::default(), phantom: PhantomData}
    }
}
impl<K: Kdf + Clone, LB: Label> HybridCombiner for QsfCombiner3<K, LB>
{
    fn combine<L: ArraySize> ( &self, ss1: impl AsRef<[u8]>, ct1: impl AsRef<[u8]>, pk1: impl AsRef<[u8]>, ss2: impl AsRef<[u8]>, _ct2: impl AsRef<[u8]>, _pk2: impl AsRef<[u8]> ) -> Array<u8, L> {
        self.kdf.derive_self_secrets_other ([ss1.as_ref(), ct1.as_ref(), pk1.as_ref(), ss2.as_ref()], LB::LABEL)
    }
}


///
/// KitchenSinkCombiners passes all shared secrets, ciphertexts and public keys to the key derivation function
/// 
pub struct KitchenSinkCombiner<K, LB> ( PhantomData<K>, PhantomData<LB> );

impl<K: Kdf,LB> Default for KitchenSinkCombiner <K,LB> {
    fn default() -> Self {
        return Self(PhantomData, PhantomData)
    }
}

impl<K: Kdf + Default, LB: Label> HybridCombiner for KitchenSinkCombiner<K,LB>
{
    fn combine<L: ArraySize> ( &self, pq_ss: impl AsRef<[u8]>, pq_ct: impl AsRef<[u8]>, pq_pk: impl AsRef<[u8]>, trad_ss: impl AsRef<[u8]>, trad_ct: impl AsRef<[u8]>, trad_pk: impl AsRef<[u8]> ) -> Array<u8, L> 
    {
        K::derive_secrets_others ( [b"hybrid_prk".as_slice(), pq_ss.as_ref(), trad_ss.as_ref(), pq_ct.as_ref(), pq_pk.as_ref(), trad_ct.as_ref(), trad_pk.as_ref(), &LB::LABEL], [L::U16.to_be_bytes().as_slice(), b"shared_secret"]).unwrap()
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
pub struct HybridKem<M: Capsulator, C: Capsulator, COM: HybridCombiner, G> (PhantomData<M>, PhantomData<C>, PhantomData<COM>, PhantomData<G>);


impl<M: Capsulator, C: Capsulator, COM: HybridCombiner,  G> Capsulator for HybridKem<M, C, COM, G>
where 
    M::Decapsulator: GetEncapsulator,
    M::Encapsulator: EncodedSizeUser2,
    M::CiphertextSize: Add<C::CiphertextSize>,
    <M::CiphertextSize as Add<C::CiphertextSize>>::Output: ArrayLength, //<u8>,
    <M::Decapsulator as GetEncapsulator>::Encapsulator: EncodedSizeUser2,

    C::Encapsulator: EncodedSizeUser2,
    C::Decapsulator: GetEncapsulator,
    <C::Decapsulator as GetEncapsulator>::Encapsulator: EncodedSizeUser2,
    Sum<M::CiphertextSize, C::CiphertextSize>: Sub<M::CiphertextSize, Output=C::CiphertextSize> + ArrayLength, //<u8>,
    
    COM: Default,
{
    type Encapsulator = HybridEncapsulator<M, C, COM>;
    type Decapsulator = HybridDecapsulator<M, C, COM, G>;
    type CiphertextSize = Sum<M::CiphertextSize, C::CiphertextSize>;
    type SharedKeySize = U32;
    
    fn generate ( rng: &mut impl CryptoRngCore ) -> (Self::Encapsulator, Self::Decapsulator) {
        let (encapsulator1, decapsulator1) = M::generate(rng);
        let (encapsulator2, decapsulator2) = C::generate(rng);

        (HybridEncapsulator{encapsulator1, encapsulator2, phantom: PhantomData}, 
                    HybridDecapsulator{decapsulator1, decapsulator2, seed: None, phantom: PhantomData, phantom2: PhantomData})
    }
}




pub struct SplitSeed;
impl<M, C, COM> GenerateCapsulatorFromSeed for HybridKem<M, C, COM, SplitSeed>
where   M: Capsulator,
        M::Encapsulator: EncodedSizeUser2,
        M: GenerateCapsulatorFromSeed,
        M::CiphertextSize: Add<C::CiphertextSize>,
        M::Decapsulator: GetEncapsulator,
        M::SeedSize: Add<C::SeedSize>,
        Sum<M::CiphertextSize, C::CiphertextSize>: ArrayLength, //<u8>,
        <M::Decapsulator as GetEncapsulator>::Encapsulator: EncodedSizeUser2,
        <M::SeedSize as Add<C::SeedSize>>::Output: ArraySize,

        C: Capsulator + GenerateCapsulatorFromSeed,
        C::Encapsulator: EncodedSizeUser2,
        C::Decapsulator: GetEncapsulator,
        <C::Decapsulator as GetEncapsulator>::Encapsulator: EncodedSizeUser2,
        COM: HybridCombiner + Default,

        Sum<M::SeedSize, C::SeedSize>: Sub<M::SeedSize, Output = C::SeedSize>,
        Sum<M::CiphertextSize, C::CiphertextSize>: Sub<M::CiphertextSize, Output=C::CiphertextSize> + ArrayLength, //<u8>,
{
    type SeedSize = Sum<M::SeedSize, C::SeedSize>;
    fn derive_from_seed(seed: &Array::<u8, Self::SeedSize>) -> (Self::Encapsulator, Self::Decapsulator) {

        //let (seed1, seed2) = Array::split_ref::<M::SeedSize>(seed);
        let (seed1, seed2) = seed.split_ref();
        let (encapsulator1, decapsulator1) = M::derive_from_seed(seed1);
        let (encapsulator2, decapsulator2) = C::derive_from_seed(seed2);

        (HybridEncapsulator{encapsulator1, encapsulator2, phantom: PhantomData}, 
             HybridDecapsulator{decapsulator1, decapsulator2, phantom: PhantomData, seed: None, phantom2: PhantomData})
    }
}


pub struct ExpandSeed<N: Unsigned, K: Kdf> (PhantomData<N>, PhantomData<K>);

impl<M, C, COM, N: ArraySize, K: Kdf+Default> GenerateCapsulatorFromSeed for HybridKem<M, C, COM, ExpandSeed<N, K>>
where   M: Capsulator + GenerateCapsulatorFromSeed,
        C: Capsulator + GenerateCapsulatorFromSeed, 
        M::Encapsulator: EncodedSizeUser2,
        C::Encapsulator: EncodedSizeUser2,
        M::Decapsulator: GetEncapsulator,
        C::Decapsulator: GetEncapsulator,
        M::CiphertextSize: Add<C::CiphertextSize>,
        M::SeedSize: Add<C::SeedSize>,
        //<M::CiphertextSize as Add<C::CiphertextSize>>::Output: ArrayLength<u8>,
        
        <M::Decapsulator as GetEncapsulator>::Encapsulator: EncodedSizeUser2,
        <C::Decapsulator as GetEncapsulator>::Encapsulator: EncodedSizeUser2,
        COM: Default + HybridCombiner,
        
        Sum<M::CiphertextSize, C::CiphertextSize>: ArrayLength, //<u8>,
        Sum<M::SeedSize, C::SeedSize>: ArraySize + Sub<M::SeedSize, Output = C::SeedSize>,
        Sum<M::CiphertextSize, C::CiphertextSize>: Sub<M::CiphertextSize, Output=C::CiphertextSize> + ArrayLength, //<u8>,
{
    type SeedSize = U32;
    fn derive_from_seed(seed: &Array::<u8, Self::SeedSize>) -> (Self::Encapsulator, Self::Decapsulator) {
        let expanded = K::derive_secret_other::<Sum<M::SeedSize, C::SeedSize>>(seed.as_slice(), &[]).unwrap();
        let (seed1, seed2) = expanded.split(); //Array::split::<M::SeedSize>(expanded);
        
        let (encapsulator1, decapsulator1) = M::derive_from_seed(&seed1);
        let (encapsulator2, decapsulator2) = C::derive_from_seed(&seed2);

        (HybridEncapsulator{encapsulator1, encapsulator2, phantom: PhantomData}, 
             HybridDecapsulator{decapsulator1, decapsulator2, phantom: PhantomData, seed: Some(seed.clone()), phantom2: PhantomData})
    }
}



pub struct DeriveExpandSeed<N: Unsigned, K: Kdf, KI: Kdf> (PhantomData<N>, PhantomData<K>, PhantomData<KI>);

impl<M, C, COM, N: ArraySize, K, KI> GenerateCapsulatorFromSeed for HybridKem<M, C, COM, DeriveExpandSeed<N, K, KI>>
where   KI:Kdf+Default,
        K: Kdf+Default,
        COM: HybridCombiner + Default,
        M: Capsulator + GenerateCapsulatorFromSeed,
        C: Capsulator + GenerateCapsulatorFromSeed,
        M::Encapsulator: EncodedSizeUser2,
        C::Encapsulator: EncodedSizeUser2,
        M::CiphertextSize: Add<C::CiphertextSize>,
        M::Decapsulator: GetEncapsulator,
        C::Decapsulator: GetEncapsulator,
        M::SeedSize: Add<C::SeedSize>,
        //<M::SeedSize as Add<C::SeedSize>>::Output: ArraySize,
        //<M::CiphertextSize as Add<C::CiphertextSize>>::Output: ArrayLength<u8>,
        
        <M::Decapsulator as GetEncapsulator>::Encapsulator: EncodedSizeUser2,
        <C::Decapsulator as GetEncapsulator>::Encapsulator: EncodedSizeUser2,

        Sum<M::CiphertextSize, C::CiphertextSize>: ArrayLength, //<u8>,
        Sum<M::SeedSize, C::SeedSize>: ArraySize + Sub<M::SeedSize, Output = C::SeedSize>,
        Sum<M::CiphertextSize, C::CiphertextSize>: Sub<M::CiphertextSize, Output=C::CiphertextSize> + ArrayLength, //<u8>,
{
    type SeedSize = U32;

    fn derive_from_seed(seed: &Array::<u8, Self::SeedSize>) -> (Self::Encapsulator, Self::Decapsulator) {
        let derived_seed = KI::derive_secret_others(seed.as_slice(), None).unwrap();
        
        let (encapsulator,decapsulator) = HybridKem::<M, C, COM, ExpandSeed<U32, K>>::derive_from_seed(&derived_seed);
        (encapsulator, HybridDecapsulator{decapsulator1: decapsulator.decapsulator1, decapsulator2: decapsulator.decapsulator2, phantom: PhantomData, seed: Some(derived_seed), phantom2: PhantomData})
    }
}





///
/// Encapsulator for a PQ/Traditional hybrid scheme
/// 
#[derive(PartialEq, Debug)]
pub struct HybridEncapsulator<M: Capsulator, T: Capsulator, COM: HybridCombiner> {
    encapsulator1: M::Encapsulator,
    encapsulator2: T::Encapsulator,
    phantom: PhantomData<COM>
}

type EncodedSize<X> = <<X as Capsulator>::Encapsulator as EncodedSizeUser2>::EncodedSize;

impl<M: Capsulator, T: Capsulator, COM: HybridCombiner> EncodedSizeUser2 for HybridEncapsulator<M, T, COM>
where 
    T::Encapsulator: EncodedSizeUser2,
    M::Encapsulator: EncodedSizeUser2,
    EncodedSize<M>: Add<EncodedSize<T>>,
    Sum<EncodedSize<M>, EncodedSize<T>>: Sub<EncodedSize<M>, Output=EncodedSize<T>> + ArrayLength, //<u8>,
{
    type EncodedSize = Sum<EncodedSize<M>, EncodedSize<T>>;
    
    fn from_bytes(encoded_encapsulator: &crate::Encoded<Self>) -> Self {
        let (pq_public_key_bytes, trad_public_key_bytes) = encoded_encapsulator.split();

        let encapsulator1 = M::Encapsulator::from_bytes(&pq_public_key_bytes);
        let encapsulator2 = T::Encapsulator::from_bytes(&trad_public_key_bytes);

        Self { encapsulator1, encapsulator2, phantom: PhantomData}
    }

    fn as_bytes(&self) -> crate::Encoded<Self> {
        let pq_encap = self.encapsulator1.as_bytes();
        let trad_encap = self.encapsulator2.as_bytes();
        
        //pq_encap.concat(trad_encap)
        generic_array::sequence::Concat::concat(pq_encap, trad_encap)
    }
}


impl<M: Capsulator, T: Capsulator, COM: HybridCombiner> GetRecipientPublicKeyBytes for HybridEncapsulator<M, T, COM>
where 
    T::Encapsulator: EncodedSizeUser2,
    M::Encapsulator: EncodedSizeUser2,
    EncodedSize<M>: Add<EncodedSize<T>>,
    Sum<EncodedSize<M>, EncodedSize<T>>: Sub<EncodedSize<M>, Output=EncodedSize<T>> + ArrayLength,
{
    type EncodedLen = <Self as EncodedSizeUser2>::EncodedSize;

    fn get_recipient_public_key_bytes(&self) -> GenericArray<u8, Self::EncodedLen> {
        todo!()
    }
}

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


impl<M: Capsulator, T: Capsulator, COM: HybridCombiner> TryFrom<&[u8]> for HybridEncapsulator<M, T, COM>
where 
    M::Encapsulator: EncodedSizeUser2,
    T::Encapsulator: for<'a> TryFrom<&'a [u8]>,
{
    type Error = ();
    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let (pq_public_key_bytes, trad_public_key_bytes) = value.split_at(<M::Encapsulator as EncodedSizeUser2>::EncodedSize::USIZE);
        let encapsulator1 = M::Encapsulator::from_bytes(&GenericArray::from_slice(pq_public_key_bytes));
        let encapsulator2 = T::Encapsulator::try_from(trad_public_key_bytes).map_err(|_|())?;
        Ok(Self{encapsulator1, encapsulator2, phantom: PhantomData})
    }
}
impl<M: Capsulator, T: Capsulator, COM: HybridCombiner> HybridEncapsulator<M, T, COM>
where 
    M::Encapsulator: EncodedSizeUser2,
    T::Encapsulator: for<'a> TryFrom<&'a [u8]>,
{
    pub fn from_slice(value: &[u8]) -> Result<Self, ()>
    {
        Self::try_from(value)
    }
}


impl<M: Capsulator, C: Capsulator, COM: HybridCombiner> Encapsulate<GenericArray<u8, Sum<M::CiphertextSize, C::CiphertextSize>>, Array<u8, U32>> for HybridEncapsulator<M, C, COM>
where 
    C::Encapsulator: Encapsulate<GenericArray<u8, C::CiphertextSize>, Array<u8,C::SharedKeySize>> + EncodedSizeUser2,
    COM: Default,
    C::SharedKeySize: ArraySize,
    C::CiphertextSize: ArrayLength, //<u8>,
    M::Encapsulator: EncodedSizeUser2,
    M::CiphertextSize: Add<C::CiphertextSize>,
    Sum<M::CiphertextSize, C::CiphertextSize>: ArrayLength, //<u8>,
{
    type Error = ();

    fn encapsulate(&self, rng: &mut impl CryptoRngCore) -> Result<(GenericArray<u8, Sum<M::CiphertextSize, C::CiphertextSize>>, Array<u8, U32>), Self::Error> {
        let (ct1, ss1) = self.encapsulator1.encapsulate(rng).unwrap();
        let (ct2, ss2) = self.encapsulator2.encapsulate(rng).unwrap();

        let ss = COM::default().combine(ss1.as_slice(), ct1.as_slice(), &self.encapsulator1.as_bytes(), &ss2, &ct2, &self.encapsulator2.as_bytes());
        let ct = ct1.concat(ct2);
        
        Ok((ct,ss))
    }
}


//type Encapsulator<X> = <X::Encapsulator as EncapsulateDeterministic2<GenericArray<u8::X::CiphertextSize>, Array<u8, X::SharedKeySize>>>;
type Ciphertext<X> = GenericArray<u8, <X as Capsulator>::CiphertextSize>;
type SharedKey<X> = Array<u8, <X as Capsulator>::SharedKeySize>;
type SeedSize<X> = <<X as Capsulator>::Encapsulator as EncapsulateDeterministic2<Ciphertext<X>, SharedKey<X>>>::SeedSize;

impl<M: Capsulator, C: Capsulator, COM: HybridCombiner> EncapsulateDeterministic2<GenericArray<u8, Sum<M::CiphertextSize, C::CiphertextSize>>, Array<u8, U32>> for HybridEncapsulator<M, C, COM>
where 
    COM: Default,
    C::Encapsulator: EncapsulateDeterministic2<Ciphertext<C>, SharedKey<C>> + EncodedSizeUser2,
    M::CiphertextSize: Add<C::CiphertextSize>,
    C::SharedKeySize: ArraySize,
    C::CiphertextSize: ArrayLength, //<u8>,
    Sum<M::CiphertextSize, C::CiphertextSize>: ArrayLength, //<u8>,
    
    M::Encapsulator: EncapsulateDeterministic2<Ciphertext<M>, SharedKey<M>> + EncodedSizeUser2,
    SeedSize<M>: Add<SeedSize<C>>,
    Sum<SeedSize<M>, SeedSize<C>>: ArraySize + Sub<SeedSize<M>, Output = SeedSize<C>>,

    //<<<M::Encapsulator as EncapsulateDeterministic2<Ciphertext<M>, SharedKey<M>>>::SeedSize as Add<<C::Encapsulator as EncapsulateDeterministic2<Ciphertext<C>, SharedKey<C>>>::SeedSize>>::Output as Sub<<M::Encapsulator as EncapsulateDeterministic2<Ciphertext<M>, SharedKey<M>>>::SeedSize>>::Output: ArraySize,
    //<Sum<<M::Encapsulator as EncapsulateDeterministic2<Ciphertext<M>, SharedKey<M>>>::SeedSize, <C::Encapsulator as EncapsulateDeterministic2<Ciphertext<C>, SharedKey<C>>>::SeedSize>> as Sub<<M::Encapsulator as EncapsulateDeterministic2<Ciphertext<M>, SharedKey<M>>>::SeedSize>>::Output: ArraySize,
{
    type Error = ();
    type SeedSize = Sum<SeedSize<M>, SeedSize<C>>;

    fn encapsulate_deterministic(&self, seed: &[u8]) -> Result<(GenericArray<u8, Sum<M::CiphertextSize, C::CiphertextSize>>, Array<u8, U32>), Self::Error> {
        //let (seed1, seed2) = seed.split_ref();
        let (seed1, seed2) = seed.split_at(SeedSize::<M>::USIZE);

        let Ok((ct1, ss1)) = self.encapsulator1.encapsulate_deterministic(seed1) else { return Err(())};
        let Ok((ct2, ss2)) = self.encapsulator2.encapsulate_deterministic(seed2) else { return Err(())};

        let ss = COM::default().combine(ss1.as_slice(), ct1.as_slice(), &self.encapsulator1.as_bytes(), &ss2, &ct2, &self.encapsulator2.as_bytes());
        let ct = ct1.concat(ct2);
        
        Ok((ct,ss))
    }
}


///
/// Decapsulator for a hybrid PQ/Trad KEM
/// 
#[derive(Debug)]
pub struct HybridDecapsulator<M: Capsulator, C: Capsulator, COM: HybridCombiner, G> 
{
    decapsulator1: M::Decapsulator,
    decapsulator2: C::Decapsulator,
    seed: Option<Array<u8, U32>>,

    phantom: PhantomData<COM>,
    phantom2: PhantomData<G>,
    
}

impl<M: Capsulator, C: Capsulator, COM: HybridCombiner,  G> HybridDecapsulator<M, C, COM, G>
{
    pub fn from_decapsulators(decapsulator1: M::Decapsulator, decapsulator2: C::Decapsulator) -> Self 
    {   
        Self { decapsulator1, decapsulator2, seed: None, phantom: PhantomData, phantom2: PhantomData}
    }
    
}

type EncodedSize2<X> = <<X as Capsulator>::Decapsulator as EncodedSizeUser2>::EncodedSize;

impl<M: Capsulator, C: Capsulator, COM: HybridCombiner, G> EncodedSizeUser2 for HybridDecapsulator<M, C, COM, G>
where 
    C::Decapsulator: EncodedSizeUser2,
    M::Decapsulator: EncodedSizeUser2,
    EncodedSize2<M>: Add<EncodedSize2<C>>,
    Sum<EncodedSize2<M>, EncodedSize2<C>>: Sub<EncodedSize2<M>, Output=EncodedSize2<C>> + ArrayLength,
{
    type EncodedSize = Sum<EncodedSize2<M>, EncodedSize2<C>>;
    
    fn from_bytes(enc: &crate::Encoded<Self>) -> Self {
        let (key_1_bytes, key_2_bytes) = enc.split();

        let decapsulator1 = M::Decapsulator::from_bytes(key_1_bytes);
        let decapsulator2 = C::Decapsulator::from_bytes(key_2_bytes);
        Self { decapsulator1, decapsulator2, phantom: PhantomData, seed: None, phantom2: PhantomData}
    }
    fn as_bytes(&self) -> crate::Encoded<Self> {
        let sk1_ha = self.decapsulator1.as_bytes();
        let sk2_ha = self.decapsulator2.as_bytes();
        sk1_ha.concat(sk2_ha)
    }
}



// impl<M: Capsulator, C: Capsulator, COM: HybridCombiner, G> DecodeGenericArray<Self> for HybridDecapsulator<M, C, COM, G>
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

impl<M, C, COM, G> TryFrom<&[u8]> for HybridDecapsulator<M, C, COM, G>
where 
    M: Capsulator, // + GenerateCapsulatorFromSeed,
    C: Capsulator, // + GenerateCapsulatorFromSeed,
    // M::Encapsulator: EncodedSizeUser2,
    // C::Encapsulator: EncodedSizeUser2,
    M::Decapsulator: EncodedSizeUser2 + GetEncapsulator,
    C::Decapsulator: for<'a> TryFrom<&'a [u8]> + GetEncapsulator,
    // M::CiphertextSize: Add<C::CiphertextSize>,
    // M::SeedSize: Add<C::SeedSize>,
    // <M::Decapsulator as GetEncapsulator>::Encapsulator: EncodedSizeUser2,
    // <C::Decapsulator as GetEncapsulator>::Encapsulator: EncodedSizeUser2,
    COM: HybridCombiner + Default,
    // Sum<M::CiphertextSize, C::CiphertextSize>: ArrayLength, //<u8>,
    // Sum<M::SeedSize, C::SeedSize>: ArraySize + Sub<M::SeedSize, Output = C::SeedSize>,
    // Sum<M::CiphertextSize, C::CiphertextSize>: Sub<M::CiphertextSize, Output=C::CiphertextSize> + ArrayLength, //<u8>,
{
    type Error = ();
    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {

        if let Ok(_seed) = Array::<u8, U32>::try_from(value)
        {
            todo!()
            // let (_encapsulator,decapsulator) = HybridKem::<M, C, COM, ExpandSeed<U32, sha3::Shake256>>::derive_from_seed(&seed);
            // Ok(Self { decapsulator1: decapsulator.decapsulator1, decapsulator2: decapsulator.decapsulator2, seed: Some(seed), phantom: PhantomData, phantom2: PhantomData})
        }
        else if value.len() > <M::Decapsulator as EncodedSizeUser2>::EncodedSize::USIZE
        {
            let (key_1_bytes, key_2_bytes) = value.split_at(<M::Decapsulator as EncodedSizeUser2>::EncodedSize::USIZE);
            let decapsulator1 = M::Decapsulator::from_bytes(GenericArray::from_slice(key_1_bytes));
            let decapsulator2 = C::Decapsulator::try_from(key_2_bytes).map_err(|_|())?;
            Ok(Self { decapsulator1, decapsulator2, phantom: PhantomData, seed: None, phantom2: PhantomData})
        }
        else {
            Err(())
        }
    }
}

impl<M, C, COM, G> HybridDecapsulator<M, C, COM, G>
where 
    M: Capsulator, // + GenerateCapsulatorFromSeed,
    C: Capsulator, // + GenerateCapsulatorFromSeed,
    M::Encapsulator: EncodedSizeUser2,
    C::Encapsulator: EncodedSizeUser2,
    M::Decapsulator: EncodedSizeUser2 + GetEncapsulator,
    C::Decapsulator: for<'a> TryFrom<&'a [u8]> + GetEncapsulator,
    // M::CiphertextSize: Add<C::CiphertextSize>,
    // M::SeedSize: Add<C::SeedSize>,
    // <M::Decapsulator as GetEncapsulator>::Encapsulator: EncodedSizeUser2,
    // <C::Decapsulator as GetEncapsulator>::Encapsulator: EncodedSizeUser2,
    COM: HybridCombiner + Default,
    // Sum<M::CiphertextSize, C::CiphertextSize>: ArrayLength, //<u8>,
    // Sum<M::SeedSize, C::SeedSize>: ArraySize + Sub<M::SeedSize, Output = C::SeedSize>,
    // Sum<M::CiphertextSize, C::CiphertextSize>: Sub<M::CiphertextSize, Output=C::CiphertextSize> + ArrayLength, //<u8>,
{
    pub fn from_slice(slice: &[u8]) -> Result<Self, ()>
    {
        TryFrom::<&[u8]>::try_from(slice)
    }
}

impl<M: Capsulator, C: Capsulator, COM: HybridCombiner, K, KI> EncodeSeed for HybridDecapsulator<M,C,COM, DeriveExpandSeed<U32, K, KI>>
where K: Kdf + Default,
    KI: Kdf + Default,
    M: GenerateCapsulatorFromSeed,
    C: GenerateCapsulatorFromSeed,
    M::SeedSize: Add<C::SeedSize>,
    //<M::SeedSize as Add<C::SeedSize>>::Output: ArraySize,
    //<<M as GenerateCapsulatorFromSeed>::SeedSize as Add<<C as GenerateCapsulatorFromSeed>::SeedSize>>::Output: Sub<<M as GenerateCapsulatorFromSeed>::SeedSize>,
    //<<<M as GenerateCapsulatorFromSeed>::SeedSize as Add<<C as GenerateCapsulatorFromSeed>::SeedSize>>::Output as Sub<<M as GenerateCapsulatorFromSeed>::SeedSize>>::Output: ArraySize,

    Sum<M::SeedSize, C::SeedSize>: ArraySize + Sub<M::SeedSize, Output = C::SeedSize>,
{ 
    type EncodedSize = U32;
    fn as_seed_bytes(&self) -> Option<Array::<u8, Self::EncodedSize>> {
        self.seed
    }
    fn from_seed_bytes(enc: &Array::<u8, Self::EncodedSize>) -> Self {
    
        //let derived_seed = KI::derive_secret_others(enc, None);
        let expanded = K::derive_secret_other::<Sum<M::SeedSize, C::SeedSize>>(enc, &[]).unwrap();
        
        let (seed1, seed2) = expanded.split(); //Array::split::<M::SeedSize>(expanded);
        
        let (_, decapsulator1) = M::derive_from_seed(&seed1);
        let (_, decapsulator2) = C::derive_from_seed(&seed2);

        HybridDecapsulator{decapsulator1, decapsulator2, seed: Some(enc.clone()), phantom: PhantomData, phantom2: PhantomData}
    }
}

impl<M: Capsulator, C: Capsulator, COM: HybridCombiner, K> EncodeSeed for HybridDecapsulator<M,C,COM, ExpandSeed<U32, K>>
where K: Kdf + Default,
    M: GenerateCapsulatorFromSeed,
    C: GenerateCapsulatorFromSeed,
    M::SeedSize: Add<C::SeedSize>,
    //<M::SeedSize as Add<C::SeedSize>>::Output: ArraySize,
    //Sum<M::SeedSize, C::SeedSize>: ArraySize,
    Sum<M::SeedSize, C::SeedSize>: Sub<M::SeedSize, Output = C::SeedSize> + ArraySize,
{ 
    type EncodedSize = U32;
    fn as_seed_bytes(&self) -> Option<Array::<u8, Self::EncodedSize>> {
        self.seed
    }
    fn from_seed_bytes(enc: &Array::<u8, Self::EncodedSize>) -> Self {
        let expanded = K::derive_secret_other::<Sum<M::SeedSize, C::SeedSize>>(&enc, &[]).unwrap();
        //let (seed1, seed2) = expanded.split_at(M::SeedSize::USIZE);
        let (seed1, seed2) = expanded.split(); //Array::split::<M::SeedSize>(expanded);
        
        let (_, decapsulator1) = M::derive_from_seed(&seed1);
        let (_, decapsulator2) = C::derive_from_seed(&seed2);

        HybridDecapsulator{decapsulator1, decapsulator2, seed: Some(enc.clone()), phantom: PhantomData, phantom2: PhantomData}
    }
}



impl<M: Capsulator, C: Capsulator, COM: HybridCombiner, G> Decapsulate<GenericArray<u8, Sum<M::CiphertextSize, C::CiphertextSize>>, Array<u8, U32>> for HybridDecapsulator<M, C, COM, G>
where COM: Default,
    M::CiphertextSize: Add<C::CiphertextSize>,
    

    C::Decapsulator: GetEncapsulator,
    M::Decapsulator: GetEncapsulator,
    <C::Decapsulator as GetEncapsulator>::Encapsulator: EncodedSizeUser2,
    <M::Decapsulator as GetEncapsulator>::Encapsulator: EncodedSizeUser2,

    Sum<M::CiphertextSize, C::CiphertextSize>: Sub<M::CiphertextSize, Output=C::CiphertextSize> + ArrayLength, //<u8>,
{
    type Error = ();
    
    fn decapsulate(&self, encapsulated_key: &GenericArray<u8,  Sum<M::CiphertextSize,  C::CiphertextSize>>) -> Result<Array<u8, U32>, Self::Error> {

        //let (ct1, ct2 ) = encapsulated_key.split_at(M::CiphertextSize::USIZE);
        let (ct1, ct2 ) = encapsulated_key.split(); // Split::<u8, M::CiphertextSize>::split(encapsulated_key);
        //let (ct2, ct1 ) = encapsulated_key.split_at(C2::CiphertextSize::USIZE);

        //let ss1 = self.decapsulator1.decapsulate(ct1.try_into().map_err(|_|())?).map_err(|_|())?;
        let ss1 = self.decapsulator1.decapsulate(ct1).map_err(|_|())?;
        //let ss2 = self.decapsulator2.decapsulate(ct2.try_into().map_err(|_|())?).map_err(|_|())?;
        let ss2 = self.decapsulator2.decapsulate(ct2).map_err(|_|())?;

        let pub1 = self.decapsulator1.get_encapsulator().as_bytes();
        let pub2 = self.decapsulator2.get_encapsulator().as_bytes();

        let ss = COM::default().combine(ss1, ct1, pub1, ss2, ct2, pub2);
        Ok(ss)
    }
}


impl<M: Capsulator, C: Capsulator, COM: HybridCombiner, G> GetEncapsulator for HybridDecapsulator<M, C, COM, G>
where COM: Default,
    M::Decapsulator: GetEncapsulator<Encapsulator=M::Encapsulator>,
    C::Decapsulator: GetEncapsulator<Encapsulator=C::Encapsulator>, 
{
    type Encapsulator = HybridEncapsulator<M, C, COM>;
    fn get_encapsulator(&self) -> Self::Encapsulator {
        Self::Encapsulator { encapsulator1: self.decapsulator1.get_encapsulator(), encapsulator2: self.decapsulator2.get_encapsulator(), phantom: PhantomData }
    }
}

impl<M: Capsulator, C: Capsulator, COM: HybridCombiner, G> GetRecipientPublicKeyBytes for HybridDecapsulator<M, C, COM, G>
where COM: Default,
    M::Decapsulator: GetEncapsulator<Encapsulator=M::Encapsulator>,
    C::Decapsulator: GetEncapsulator<Encapsulator=C::Encapsulator>, 
    M::Encapsulator: EncodedSizeUser2,
    // C::Encapsulator: EncodedSizeUser2,
    // <M::Encapsulator as EncodedSizeUser2>::EncodedSize: Add<<C::Encapsulator as EncodedSizeUser2>::EncodedSize>,
    // <<M::Encapsulator as EncodedSizeUser2>::EncodedSize as Add<<C::Encapsulator as EncodedSizeUser2>::EncodedSize>>::Output: Sub<<M::Encapsulator as EncodedSizeUser2>::EncodedSize>,
    // <<<M as Capsulator>::Encapsulator as EncodedSizeUser2>::EncodedSize as Add<<<C as Capsulator>::Encapsulator as EncodedSizeUser2>::EncodedSize>>::Output: ArrayLength

{
    type EncodedLen = U0; //<<Self as GetEncapsulator>::Encapsulator as EncodedSizeUser2>::EncodedSize;

    fn get_recipient_public_key_bytes(&self) -> GenericArray<u8, Self::EncodedLen> {
        todo!()
    }
}

// pub struct HybridKemSeed<M: Capsulator, C: Capsulator, COM: HybridCombiner, G> (PhantomData<M>, PhantomData<C>, PhantomData<COM>, PhantomData<G>);

// impl<M: Capsulator, C: Capsulator, COM: HybridCombiner,  G> Capsulator for HybridKemSeed<M, C, COM, G>
// where 
//     <M as Capsulator>::Decapsulator: GetEncapsulator,
//     <M as Capsulator>::Encapsulator: EncodedSizeUser2,
//     <M as Capsulator>::CiphertextSize: Add<<C as Capsulator>::CiphertextSize>,
//     <<M as Capsulator>::CiphertextSize as Add<<C as Capsulator>::CiphertextSize>>::Output: ArrayLength<u8>,
//     <<M as Capsulator>::Decapsulator as GetEncapsulator>::Encapsulator: EncodedSizeUser2,

//     C::Encapsulator: EncodedSizeUser2,
//     <C as Capsulator>::Decapsulator: GetEncapsulator,
//     <<C as Capsulator>::Decapsulator as GetEncapsulator>::Encapsulator: EncodedSizeUser2,
    
//     COM: Default,
//     HybridKem<M, C, COM, G>: GenerateCapsulatorFromSeed,
// {
//     type Encapsulator = HybridEncapsulator<M, C, COM>;
//     type Decapsulator = HybridDecapsulatorSeed<M, C, COM, G>;
//     type CiphertextSize = Sum<M::CiphertextSize, C::CiphertextSize>;
//     type SharedKeySize = U32;
    
//     fn generate ( rng: &mut impl CryptoRngCore ) -> (Self::Encapsulator, Self::Decapsulator) {
//         todo!()
//         // let (pq_encapsulator, pq_decapsulator) = M::generate(rng);
//         // let (trad_encapsulator, trad_decapsulator) = C::generate(rng);

//         // (HybridEncapsulator{encapsulator1: pq_encapsulator, encapsulator2: trad_encapsulator, phantom: PhantomData}, 
//         //      HybridDecapsulatorSeed{decapsulator1: pq_decapsulator, decapsulator2: trad_decapsulator, seed: None, phantom: PhantomData})
//     }
//     // fn generate2 ( rng: &mut impl rand_core2::CryptoRng ) -> (Self::Encapsulator, Self::Decapsulator) {
//     //     todo!()
//     // }
// }



// impl<M: Capsulator, C: Capsulator, COM: HybridCombiner, N: ArraySize, K: Kdf+Default, KI:Kdf+Default> 
// GenerateCapsulatorFromSeed for HybridKemSeed<M, C, COM, DeriveExpandSeed<N, K, KI>>
// where   M::Encapsulator: EncodedSizeUser2,
//         M: GenerateCapsulatorFromSeed,
//         <M as Capsulator>::CiphertextSize: Add<<C as Capsulator>::CiphertextSize>,
//         <M as Capsulator>::Decapsulator: GetEncapsulator,
//         <<M as Capsulator>::CiphertextSize as Add<<C as Capsulator>::CiphertextSize>>::Output: ArrayLength<u8>,
//         <<M as Capsulator>::Decapsulator as GetEncapsulator>::Encapsulator: EncodedSizeUser2,
//         C::Encapsulator: EncodedSizeUser2,
//         <C as Capsulator>::Decapsulator: GetEncapsulator,
//         <<C as Capsulator>::Decapsulator as GetEncapsulator>::Encapsulator: EncodedSizeUser2,
//         COM: Default,
//         C: GenerateCapsulatorFromSeed, 
//         M::SeedSize: Add<<C as GenerateCapsulatorFromSeed>::SeedSize>,
//         <M::SeedSize as Add<<C as GenerateCapsulatorFromSeed>::SeedSize>>::Output: ArraySize

// {
//     type SeedSize = U32;

//     fn derive_from_seed(seed: &Array::<u8, Self::SeedSize>) -> (Self::Encapsulator, Self::Decapsulator) {
//         let derived_seed = KI::derive_secret_others(&seed, None);
//         let (e,d ) = HybridKemSeed::<M, C, COM, ExpandSeed<U32, K>>::derive_from_seed(&derived_seed);
//         let d2 = HybridDecapsulatorSeed{seed: d.seed, phantom: PhantomData, phantom2: PhantomData, phantom3: PhantomData, phantom4: PhantomData};
//         (e,d2)
//     }
// }



// impl<M: Capsulator, C: Capsulator, COM: HybridCombiner, N: ArraySize, K: Kdf+Default> GenerateCapsulatorFromSeed for HybridKemSeed<M, C, COM, ExpandSeed<N, K>>
// where   M::Encapsulator: EncodedSizeUser2,
//         M: GenerateCapsulatorFromSeed,
//         <M as Capsulator>::CiphertextSize: Add<<C as Capsulator>::CiphertextSize>,
//         <M as Capsulator>::Decapsulator: GetEncapsulator,
//         <<M as Capsulator>::CiphertextSize as Add<<C as Capsulator>::CiphertextSize>>::Output: ArrayLength<u8>,
//         <<M as Capsulator>::Decapsulator as GetEncapsulator>::Encapsulator: EncodedSizeUser2,
//         C::Encapsulator: EncodedSizeUser2,
//         <C as Capsulator>::Decapsulator: GetEncapsulator,
//         <<C as Capsulator>::Decapsulator as GetEncapsulator>::Encapsulator: EncodedSizeUser2,
//         COM: Default,
//         C: GenerateCapsulatorFromSeed, 
//         M::SeedSize: Add<<C as GenerateCapsulatorFromSeed>::SeedSize>,
//         <M::SeedSize as Add<<C as GenerateCapsulatorFromSeed>::SeedSize>>::Output: ArraySize

//     //     <<M as KemCore>::EncapsulationKey as ml_kem::EncodedSizeUser>::EncodedSize: Add<<T::Encapsulator as EncodedSizeUser2>::EncodedSize>,
//     // <<<M as KemCore>::EncapsulationKey as ml_kem::EncodedSizeUser>::EncodedSize as Add<<T::Encapsulator as EncodedSizeUser2>::EncodedSize>>::Output: Debug + PartialEq + ArrayLength<u8>,
//     // <M::EncapsulationKey as ml_kem::EncodedSizeUser>::EncodedSize: ArrayLength<u8>,
// {
//     type SeedSize = N;
//     fn derive_from_seed(seed: &Array::<u8, Self::SeedSize>) -> (Self::Encapsulator, Self::Decapsulator) {
//         // let mut hasher = sha3::Shake256::default();
//         // hasher.update(seed);
//         // let mut reader = hasher.finalize_xof();

//         // let mut expanded = Array::<u8, Sum<M::SeedSize/*Seed size for ml-kem*/, C::SeedSize>>::default();
//         // reader.read(&mut expanded);

//         let expanded = K::derive_secret_other::<Sum<M::SeedSize, C::SeedSize>>(&seed, &[]);
        
//         //let mut pred_rng = PredictableRngForHybrid::new2(&expanded[0..64]);
//         //let (pq_decapsulator, pq_encapsulator) = M::generate_deterministic(&ml_kem::array::Array::try_from(&expanded[0..32]).unwrap(), &ml_kem::array::Array::try_from(&expanded[32..64]).unwrap());
//         let (encapsulator1, decapsulator1) = M::derive_from_seed(&Array::try_from(&expanded[..M::SeedSize::USIZE]).unwrap());

//         // let x = &derive_ec_key_wide_reduction_p256(&expanded[64..112]);
//         // pred_rng.add(&x);
//         let (encapsulator2, decapsulator2) = C::derive_from_seed(&Array::try_from(&expanded[M::SeedSize::USIZE..]).unwrap());

//         let seed2 = Array::try_from(seed.as_slice()).unwrap();
//         //let seed = if Self::SeedSize::USIZE == U32::USIZE { Some(Array::try_from(seed.as_slice()).unwrap()) } else { None};
//         (HybridEncapsulator{encapsulator1, encapsulator2, phantom: PhantomData}, 
//              HybridDecapsulatorSeed{seed: seed2, phantom: PhantomData, phantom2: PhantomData, phantom3: PhantomData, phantom4: PhantomData })
//     }
// }






// #[derive(Debug)]
// pub struct HybridDecapsulatorSeed<M: Capsulator, C: Capsulator, COM: HybridCombiner, G> 
// {
//     //decapsulator1: M::Decapsulator,
//     //decapsulator2: C::Decapsulator,

//     phantom: PhantomData<COM>,
//     seed: Array<u8, U32>,
//     phantom2: PhantomData<G>,
//     phantom3: PhantomData<M>,
//     phantom4: PhantomData<C>
// }
// impl<M: Capsulator, C2: Capsulator, COM: HybridCombiner, G> EncodedSizeUser2 for HybridDecapsulatorSeed<M, C2, COM, G>
// where 
//     C2::Decapsulator: EncodedSizeUser2,
//     <M as Capsulator>::Decapsulator: EncodedSizeUser2,
//     <M as Capsulator>::Encapsulator: EncodedSizeUser2,
//     <M as Capsulator>::Decapsulator: GetEncapsulator,
//     <C2 as Capsulator>::Encapsulator: EncodedSizeUser2,
//     <<M as Capsulator>::Decapsulator as GetEncapsulator>::Encapsulator: EncodedSizeUser2,
//     <M as Capsulator>::CiphertextSize: Add<<C2 as Capsulator>::CiphertextSize>,
//     COM: Default,
//     <C2 as Capsulator>::Decapsulator: GetEncapsulator,
//     <<C2 as Capsulator>::Decapsulator as GetEncapsulator>::Encapsulator: EncodedSizeUser2,
//     <<M as Capsulator>::CiphertextSize as Add<<C2 as Capsulator>::CiphertextSize>>::Output: ArrayLength<u8>,
//     //<M as Capsulator>::Decapsulator: EncodedSizeUser,
//     <<M as Capsulator>::Decapsulator as EncodedSizeUser2>::EncodedSize: Add<<<C2 as Capsulator>::Decapsulator as EncodedSizeUser2>::EncodedSize>,

//     // U64: Add<<<C2 as Capsulator>::Decapsulator as EncodedSizeUser2>::EncodedSize>,
//     // <U64 as Add<<<C2 as Capsulator>::Decapsulator as EncodedSizeUser2>::EncodedSize>>::Output: ArrayLength<u8>,
//     <<M as Capsulator>::Decapsulator as EncodedSizeUser2>::EncodedSize: Add<<<C2 as Capsulator>::Decapsulator as EncodedSizeUser2>::EncodedSize>,
//     <<<M as Capsulator>::Decapsulator as EncodedSizeUser2>::EncodedSize as Add<<<C2 as Capsulator>::Decapsulator as EncodedSizeUser2>::EncodedSize>>::Output: ArrayLength<u8>,
//     HybridKem<M, C2, COM, G>: GenerateCapsulatorFromSeed,
// {
//     //type EncodedSize = Sum<U64, <C2::Decapsulator as EncodedSizeUser2>::EncodedSize>;
//     type EncodedSize = U32; //Sum<<M::Decapsulator as EncodedSizeUser2>::EncodedSize, <C2::Decapsulator as EncodedSizeUser2>::EncodedSize>;
    
//     fn from_bytes(enc: &crate::Encoded<Self>) -> Self {
//         //let split_pos = 64; // key size for seed for ML-kem
        
//         //let split_pos = <M::Decapsulator as EncodedSizeUser2>::EncodedSize::USIZE;
//         //let (pq_key_bytes, trad_key_bytes) = enc.split_at(split_pos);

        
//         // let d = hybrid_array2::Array::<u8, U32>::try_from(&pq_key_bytes[0..32]).unwrap();
//         //let seed = Array::try_from(enc.as_slice()).unwrap();
//         let seed2 = Array::try_from(enc.as_slice()).unwrap();
//         // let z = hybrid_array2::Array::<u8, U32>::try_from(&pq_key_bytes[32..64]).unwrap();
//         //let (encap, decap) = <HybridKem::<M, C2, COM, G> as GenerateCapsulatorFromSeed>::derive_from_seed(&seed);

//         // let (pq_decapsulator, _) = M::generate_deterministic(&d, &z);
//         //let pq_decapsulator = M::Decapsulator::from_bytes(GenericArray::from_slice(pq_key_bytes));
//         //let trad_decapsulator = C2::Decapsulator::from_bytes(&GenericArray::from_slice(trad_key_bytes));
//         Self { seed: seed2, phantom: PhantomData, phantom2: PhantomData, phantom3: PhantomData, phantom4: PhantomData}
//     }
//     fn as_bytes(&self) -> crate::Encoded<Self> {
//         // let sk1_ha = self.decapsulator1.as_bytes();
//         // let sk2_ha = self.decapsulator2.as_bytes();
        
//         // let sk1_ga = GenericArray::<u8, <M::Decapsulator as EncodedSizeUser2>::EncodedSize>::from_slice(&sk1_ha).clone();
//         // let sk2_ga = GenericArray::<u8, <C2::Decapsulator as EncodedSizeUser2>::EncodedSize>::from_slice(&sk2_ha).clone();
//         // //let x = pq_encap_ha.0;
//         // //let pq_encap_ga2 = GenericArray::<u8, <M::EncapsulationKey as EncodedSizeUser>::EncodedSize>::from(&pq_encap_ha.0);
//         // sk1_ga.concat(sk2_ga)
//         GenericArray::from(self.seed.0)

//     }
// }

// impl<M: Capsulator, C2: Capsulator, COM: HybridCombiner, G> Decapsulate<GenericArray<u8, Sum<M::CiphertextSize, C2::CiphertextSize>>, Array<u8, U32>> for HybridDecapsulatorSeed<M, C2, COM, G>

// where COM: Default,
//     M::Decapsulator: GetEncapsulator,
//     M::CiphertextSize: Add<C2::CiphertextSize>,
//     <M::Decapsulator as GetEncapsulator>::Encapsulator: EncodedSizeUser2,
//     <M::CiphertextSize as Add<C2::CiphertextSize>>::Output: ArrayLength<u8>,

//     C2::Encapsulator: EncodedSizeUser2,
//     C2::Decapsulator: GetEncapsulator, 
//     <C2::Decapsulator as GetEncapsulator>::Encapsulator: EncodedSizeUser2,
//     <M as Capsulator>::Encapsulator: EncodedSizeUser2,
//     <M as Capsulator>::Encapsulator: EncodedSizeUser2,
//     HybridKem<M, C2, COM, G>: GenerateCapsulatorFromSeed,
//     //<HybridKem<M, C2, COM, G> as GenerateCapsulatorFromSeed>::SeedSize: U32,

// {
//     type Error = ();
    
//     fn decapsulate(&self, encapsulated_key: &GenericArray<u8,  Sum<M::CiphertextSize,  C2::CiphertextSize>>) -> Result<Array<u8, U32>, Self::Error> {
//         // let ct1 = encapsulated_key[..M::CiphertextSize::USIZE].try_into().unwrap();
//         // let ct2 = encapsulated_key[M::CiphertextSize::USIZE..].try_into().unwrap();

//         // let ss1 = self.decapsulator1.decapsulate(ct1).unwrap();
//         // let ss2 = self.decapsulator2.decapsulate(ct2).unwrap();

//         // let pub1 = self.decapsulator1.get_encapsulator().as_bytes();
//         // let pub2 = self.decapsulator2.get_encapsulator().as_bytes();

//         let seed2 = Array::try_from(self.seed.as_slice()).unwrap();
        
//         let (encap, decap) = <HybridKem::<M, C2, COM, G> as GenerateCapsulatorFromSeed>::derive_from_seed(&seed2);

//         let ek = GenericArray::from_slice(&encapsulated_key);
//         let ss = decap.decapsulate(ek).unwrap();
//         //let ss = COM::default().combine(pq_ss.as_slice(), pq_ct, &encoded_pq_pub_key, &trad_ss, &trad_ct, &encoded_trad_pub_key);
//         //let ss = COM::default().combine(ss1, ct1, pub1, ss2, ct2, pub2);
//         //Ok(Array::try_from(ss.as_slice()).unwrap())
//         let ss2 = Array::try_from(ss.as_slice()).unwrap();
//         Ok(ss2)
//     }
// }


// impl<M: KemCore, COM: HybridCombiner, C2: Capsulator> HybridDecapsulator<M, COM, C2>
// where 
//     //D: PrivateKeyInit<C>,
//     //C2::Decapsulator: PrivateKeyInit<C>
// {
//     pub fn new22(private_key: HybridPrivateKey<M, 
//         //EK::RecipientPublicKey, 
//         <<C2 as Capsulator>::EncappedKey as EncappedKey>::RecipientPublicKey,
//         C2>, 
//         public_key: HybridPublicKey<M, 
//         //EK::RecipientPublicKey, 
//         //<<C2 as Capsulator>::EncappedKey as EncappedKey>::RecipientPublicKey,
//         C2>) -> Self {
//         //let decapsulator_2 = C2::new_decapsulator(private_key.ec_private_key);
//         Self { pq_priv_key: private_key.pq_private_key, decapsulator_2: private_key.trad_private_key, /*public_key,*/ phantom5: PhantomData }
//     }
// }

// // impl<M: KemCore, COM: HybridCombiner, C2: Capsulator> PrivateKeyInit<HybridPrivateKey<M,
// //     //EK::RecipientPublicKey
// //     <<C2 as Capsulator>::EncappedKey as EncappedKey>::RecipientPublicKey
// // , C2>> for HybridDecapsulator<M, COM, C2>
// // where 
// //     //D: PrivateKeyInit<C>,
// //     <C2 as Capsulator>::Encapsulator: Default + From<<<C2 as Capsulator>::EncappedKey as EncappedKey>::RecipientPublicKey>,
// //     //<<C2 as Capsulator>::EncappedKey as EncappedKey>::RecipientPublicKey: Clone,
// // {
// //     fn new(private_key: HybridPrivateKey<M,
// //         //EK::RecipientPublicKey
// //         <<C2 as Capsulator>::EncappedKey as EncappedKey>::RecipientPublicKey
// //         , C2>) -> Self 
// //     {
// //         let trad_encapsulator = C2::Encapsulator::from(private_key.ec_public_key);
// //         // let public_key = HybridPublicKey::from_keys(private_key.pq_public_key, 
// //         //     //private_key.ec_public_key, 
// //         //     //C2::new_encapsulator()
// //         //     trad_encapsulator
// //         // );
// //         Self { pq_priv_key: private_key.pq_private_key, decapsulator_2: private_key.trad_private_key, /*public_key,*/ phantom5: PhantomData}
// //     }
// }

// impl<M: KemCore, C, EK: EncappedKey, D, DE, COM: HybridCombiner> EncodePublicKey<elliptic_curve::PublicKey<C>> for HybridDecapsulator<M, C, EK, D, DE, COM>
// where 
//     C: CurveArithmetic,
//     D: PrivateKeyInit<C>,
//     DE: EncodePublicKey<elliptic_curve::PublicKey<C>>
// {
//     type EncodedLen = DE::EncodedLen;
//     fn encode(public_key: &elliptic_curve::PublicKey<C>) -> GenericArray<u8, Self::EncodedLen> {
//         DE::encode(public_key)
//     }
    
// }


// impl<M: KemCore, COM: HybridCombiner + Default, C2: Capsulator> Decapsulator<HybridEncapKey<M, C2::EncappedKey, C2>> for HybridDecapsulator<M, COM, C2> 
// where  <C2::EncappedKey as EncappedKey>::EncappedKeySize: Add<<M as KemCore>::CiphertextSize>, 
//     <<C2::EncappedKey as EncappedKey>::EncappedKeySize as Add<<M as KemCore>::CiphertextSize>>::Output: ArrayLength<u8>, 
//     <C2::EncappedKey as EncappedKey>::EncappedKeySize: Debug,
//     //D: Decapsulator<EK2> + PrivateKeyInit<C> + EncodePublicKey<EK2::RecipientPublicKey>,
//     C2::Decapsulator: Decapsulator<C2::EncappedKey> + GetEncapsulator, 
//     <C2::Decapsulator as GetEncapsulator>::Encapsulator: EncodedSizeUser2,
    
//     //C2::Encapsulator: EncodePublicKey<<C2::EncappedKey as EncappedKey>::RecipientPublicKey> + GetPublicKey<<C2::EncappedKey as EncappedKey>::RecipientPublicKey>,
//     //M::DecapsulationKey: EncodePublicKey2,
//     //DE: EncodePublicKey<EK2::RecipientPublicKey>,
//     M::DecapsulationKey: GetEncapsulator,
//     <M::DecapsulationKey as GetEncapsulator>::Encapsulator: EncodedSizeUser
// {
//     fn try_decap(&self, encapped_key: &HybridEncapKey<M, C2::EncappedKey, C2>) -> Result<kem::SharedSecret<HybridEncapKey<M, C2::EncappedKey,C2>>, kem::Error> {

//         let pq_ct_len = M::CiphertextSize::USIZE;
//         let pq_ct = hybrid_array::Array::try_from(encapped_key.as_bytes()[0..pq_ct_len].as_ref()).map_err(|_v|kem::Error)?;
//         let pq_ss = self.pq_priv_key.decapsulate(&pq_ct).map_err(|_v|kem::Error)?;

//         let trad_ek: &GenericArray<_, <C2::EncappedKey as EncappedKey>::EncappedKeySize> = GenericArray::from_slice(&encapped_key.as_bytes()[pq_ct_len..]);

//         let encapped_key_2 = C2::EncappedKey::from_bytes(trad_ek)?;
//         let trad_ss = self.decapsulator_2.try_decap(&encapped_key_2)?;

//         //let encoded_pub_key_2 = D::encode(&self.public_key.trad_public_key);
//         //let encoded_pub_key_2 = self.public_key.trad_encapsulator.encode();
        
//         // let trad_public_kkey = self.public_key.trad_encapsulator.get_public_key();
//         // let encoded_pub_key_2 = C2::Encapsulator::encode(trad_public_kkey);

//         let encoded_pq_pub_key = self.pq_priv_key.get_encapsulator().as_bytes();
//         let encoded_pub_key_2 = self.decapsulator_2.get_encapsulator().as_bytes(); //get_encoded_public_key();
        
//         //let ss = COM::default().combine(pq_ss.as_slice(), pq_ct.as_slice(), &self.public_key.pq_public_key.as_bytes(), trad_ss.as_bytes(), trad_ek.as_ref(), &encoded_pub_key_2);
//         let ss = COM::default().combine(pq_ss.as_slice(), pq_ct.as_slice(), &encoded_pq_pub_key, trad_ss.as_bytes(), trad_ek.as_ref(), &encoded_pub_key_2);
//         //let ss = COM::default().combine(pq_ss.as_slice(), pq_ct.as_slice(), &self.pq_priv_key.get_public_key().as_bytes(), trad_ss.as_bytes(), trad_ek.as_ref(), &encoded_pub_key_2);
//         Ok ( kem::SharedSecret::new(ss))
//     }
// }

//>, Array<u8, U32>

//impl<M: KemCore, C2: Capsulator, COM: HybridCombiner> kem2::Decapsulate<GenericArray<u8, Sum<M::CiphertextSize, <C2::Encapsulator as EncodedSizeUser>::EncodedSize>>, Array<u8, U32>> for HybridDecapsulator<M, COM,C2>
//impl<M: KemCore, C2: Capsulator, COM: HybridCombiner> kem2::Decapsulate<GenericArray<u8, Sum<M::CiphertextSize, <C2::Encapsulator as EncodedSizeUser>::EncodedSize>>, Array<u8, U32>> for HybridDecapsulator<M, COM,C2>



// #[derive(PartialEq)]
// pub struct HybridPublicKey<M: KemCore, C: Capsulator> 
// {
//     pq_public_key: M::EncapsulationKey,
//     //trad_public_key: PK,
//     trad_encapsulator: C::Encapsulator,
// }

// impl <M: KemCore, C: Capsulator> Debug for HybridPublicKey<M, C>
// {
//     fn fmt(&self, _f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
//         todo!()
//     }
// }
// impl<M: KemCore, C: Capsulator> Clone for HybridPublicKey<M,C>
// where 
//     M::EncapsulationKey: Clone,
//     C::Encapsulator: Clone
// {
//     fn clone(&self) -> Self {
//         Self{pq_public_key: self.pq_public_key.clone(), trad_encapsulator: self.trad_encapsulator.clone()}
//     }
// }



// impl<M: KemCore, C: Capsulator> HybridPublicKey<M,C> 
// where <C as Capsulator>::Encapsulator: Default
// {
//     pub fn from_keys ( public_key_1: M::EncapsulationKey, encap: C::Encapsulator ) -> Self
//     {
//         Self { pq_public_key: public_key_1, trad_encapsulator: encap}
//     }
// }
// impl<M: KemCore, C: Capsulator> HybridPublicKey<M,C> 
// where <C as Capsulator>::Encapsulator: Default + From<<C::EncappedKey as EncappedKey>::RecipientPublicKey>,
// <C::EncappedKey as EncappedKey>::RecipientPublicKey: Clone
// {
//     pub fn from_bytes<ED: DecodePublicKey<<C::EncappedKey as EncappedKey>::RecipientPublicKey>> ( key: &[u8] ) -> Result<Self, crate::Error> 
//     {
//         let pq_pk_len = <M::EncapsulationKey as ml_kem::EncodedSizeUser>::EncodedSize::USIZE;
//         let pq_public_key = M::EncapsulationKey::from_bytes(&hybrid_array::Array::try_from(&key[0..pq_pk_len])?);

//         let ec_public_key = ED::decode(&key[pq_pk_len..])?;
//         //let ec_encapsulator = C::new_encapsulator();
//         let ec_encapsulator = C::Encapsulator::from(ec_public_key.clone());
        
//         Ok(Self { pq_public_key, trad_encapsulator: ec_encapsulator})
//     }
// }

// impl<M: KemCore, C: Capsulator> HybridPublicKey<M,C> 
// // where C::Encapsulator: crate::Encode + crate::GetPublicKey<<C::EncappedKey as EncappedKey>::RecipientPublicKey>
// where C::Encapsulator: crate::Encode + crate::GetPublicKey<<C::EncappedKey as EncappedKey>::RecipientPublicKey>
// {
//     pub fn to_bytes<D: EncodePublicKey<<C::EncappedKey as EncappedKey>::RecipientPublicKey>> (&self) -> Vec<u8>
//     {
//         let mut result = Vec::new();
//         result.extend_from_slice(&self.pq_public_key.as_bytes());
//         let trad_public_key = self.trad_encapsulator.get_public_key();
//         result.extend_from_slice(&D::encode(trad_public_key));
//         //result.extend_from_slice(&D::encode(&self.trad_public_key));
//         //result.extend_from_slice(&<C as Capsulator>::Encapsulator::encode());
//         //result.extend_from_slice(&self.trad_encapsulator.encode());
//         result
//     }
// }





// #[derive(Debug)]
// #[cfg(all(feature="rustcrypto-ml-kem"))]
// pub struct HybridPrivateKey<M: KemCore, CP, C2: Capsulator> {
//     pub pq_private_key: M::DecapsulationKey,
//     //pub ec_private_key: C,
//     pub pq_public_key: M::EncapsulationKey,
//     pub ec_public_key: CP,

//     pub trad_private_key: C2::Decapsulator,
//     pub trad_public_key: C2::Encapsulator,
// }






// pub struct HybridEncapKey<M: KemCore, C: EncappedKey, C2: Capsulator> 
// where <C as EncappedKey>::EncappedKeySize: Add<<M as KemCore>::CiphertextSize>,
//     <<C as EncappedKey>::EncappedKeySize as Add<<M as KemCore>::CiphertextSize>>::Output: ArrayLength<u8>
// {
//     bytes: GenericArray<u8, Sum<C::EncappedKeySize,M::CiphertextSize>>,
//     phantom: PhantomData<C2>
// }


// impl<M: KemCore, C: EncappedKey, C2: Capsulator> Debug for HybridEncapKey<M, C, C2>
// where <C as EncappedKey>::EncappedKeySize: Add<<M as KemCore>::CiphertextSize>,
//     <<C as EncappedKey>::EncappedKeySize as Add<<M as KemCore>::CiphertextSize>>::Output: ArrayLength<u8>
// {
//     fn fmt(&self, _f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
//         todo!()
//     }
// }
// impl<M: KemCore, C: EncappedKey, C2: Capsulator> EncappedKey for HybridEncapKey<M, C, C2>
// where
//     <M as KemCore>::CiphertextSize: Debug,
//     <C as EncappedKey>::EncappedKeySize: Add<<M as KemCore>::CiphertextSize>,
//     <<C as EncappedKey>::EncappedKeySize as Add<<M as KemCore>::CiphertextSize>>::Output: ArrayLength<u8>,
//     <C as EncappedKey>::EncappedKeySize: Debug,
// {
//     type EncappedKeySize = Sum<C::EncappedKeySize, M::CiphertextSize>;
//     type SharedSecretSize = U32;
//     type SenderPublicKey = HybridPublicKey<M, C2>;
//     type RecipientPublicKey = HybridPublicKey<M, C2>;
    
//     fn from_bytes(bytes: &GenericArray<u8, Self::EncappedKeySize>) -> Result<Self, kem::Error> {
//         Ok(Self{bytes: bytes.clone(), phantom: PhantomData})
//     }
// }
// impl<M: KemCore, C: EncappedKey, C2: Capsulator> AsRef<[u8]> for HybridEncapKey<M,C, C2> 
// where 
//     <C as EncappedKey>::EncappedKeySize: Add<<M as KemCore>::CiphertextSize>,
//     <<C as EncappedKey>::EncappedKeySize as Add<<M as KemCore>::CiphertextSize>>::Output: ArrayLength<u8>
// {
//     fn as_ref(&self) -> &[u8] {
//          &self.bytes
//     }
// }


// impl<M: KemCore, C: EncappedKey, C2: Capsulator>  HybridEncapKey<M, C, C2>
// where <C as EncappedKey>::EncappedKeySize: Add<<M as KemCore>::CiphertextSize>,
//      <<C as EncappedKey>::EncappedKeySize as Add<<M as KemCore>::CiphertextSize>>::Output: ArrayLength<u8>,
//      <M as KemCore>::CiphertextSize: ArrayLength<u8>
// {
//     fn from_components(pq_bytes: &hybrid_array::Array<u8, M::CiphertextSize>, trad_bytes: &GenericArray<u8, C::EncappedKeySize>) -> Result<Self, kem::Error> {
//         let mut bytes = GenericArray::default();
//         let (ek3, ek4) = bytes.split_at_mut(M::CiphertextSize::USIZE);
//         ek3.copy_from_slice(pq_bytes);
//         ek4.copy_from_slice(trad_bytes);

//         Ok(Self{bytes, phantom: PhantomData})
//     }
// }






// pub struct HybridKem2<M, T, C> { phantom1: PhantomData<M>, phantom2: PhantomData<T>, phantom3: PhantomData<C>}

// impl<M,T,C> ml_kem::KemCore for HybridKem2<M,T,C>
// where M: KemCore,
//     T: KemCore,
//     C: HybridCombiner + Default,
//     <M as KemCore>::CiphertextSize: Add<<T as KemCore>::CiphertextSize>,
//     <<M as KemCore>::CiphertextSize as Add<<T as KemCore>::CiphertextSize>>::Output: Debug+PartialEq+ArraySize,
//     <M as KemCore>::CiphertextSize: Add<<<T as KemCore>::EncapsulationKey as EncodedSizeUser>::EncodedSize>,
//     <<M as KemCore>::CiphertextSize as Add<<<T as KemCore>::EncapsulationKey as EncodedSizeUser>::EncodedSize>>::Output: hybrid_array::ArraySize,
//     <<M as KemCore>::EncapsulationKey as EncodedSizeUser>::EncodedSize: Add<<<T as KemCore>::EncapsulationKey as EncodedSizeUser>::EncodedSize>,
//     <<<M as KemCore>::EncapsulationKey as EncodedSizeUser>::EncodedSize as Add<<<T as KemCore>::EncapsulationKey as EncodedSizeUser>::EncodedSize>>::Output: Debug + PartialEq + ArraySize,
//  {
//     type SharedKeySize = U32;
//     type CiphertextSize = Sum<M::CiphertextSize, T::CiphertextSize>;
//     type DecapsulationKey = HybridPrivateKey2<M, T, C>;
//     type EncapsulationKey = HybridPublicKey2<M, T, C>;

//     fn generate(rng: &mut impl rand_core::CryptoRngCore) -> (Self::DecapsulationKey, Self::EncapsulationKey) {
//         let (pq_private_key, pq_public_key ) = M::generate(rng);
//         let (trad_priv_key, trad_pub_key) = T::generate(rng);
//         (HybridPrivateKey2{pq_key: pq_private_key, trad_key : trad_priv_key, phantom: PhantomData}, 
//             HybridPublicKey2 {pq_key: pq_public_key, trad_key: trad_pub_key, phantom: PhantomData})
//     }
//     // fn generate_deterministic(_d: &ml_kem::B32, _z: &ml_kem::B32)
//     //         -> (Self::DecapsulationKey, Self::EncapsulationKey) {
//     //     todo!()
        
//     // }
// }

// pub struct HybridPublicKey2<M: KemCore, T: KemCore, COM: HybridCombiner>
// {
//     pq_key: M::EncapsulationKey,
//     trad_key: T::EncapsulationKey,
//     phantom: PhantomData<COM>
// }

// impl <M: KemCore, T:KemCore, COM: HybridCombiner> EncodedSizeUser for HybridPublicKey2<M,T,COM>
// where <<M as KemCore>::EncapsulationKey as EncodedSizeUser>::EncodedSize: Add<<<T as KemCore>::EncapsulationKey as EncodedSizeUser>::EncodedSize>,
//       <<<M as KemCore>::EncapsulationKey as EncodedSizeUser>::EncodedSize as Add<<<T as KemCore>::EncapsulationKey as EncodedSizeUser>::EncodedSize>>::Output: Debug + PartialEq + ArraySize
// {
//     type EncodedSize = Sum<<<M as KemCore>::EncapsulationKey as EncodedSizeUser>::EncodedSize, <<T as KemCore>::EncapsulationKey as EncodedSizeUser>::EncodedSize>;
//     fn as_bytes(&self) -> ml_kem::Encoded<Self> {
//         todo!()
//     }
//     fn from_bytes(_enc: &ml_kem::Encoded<Self>) -> Self {
//         todo!()
//     }
// }
// impl <M: KemCore, T:KemCore, COM: HybridCombiner> PartialEq for HybridPublicKey2<M,T, COM>
// {
//     fn eq(&self, _other: &Self) -> bool {
//         todo!()
//     }
// }
// impl <M: KemCore, T:KemCore, C: HybridCombiner> Debug for HybridPublicKey2<M,T,C>
// {
//     fn fmt(&self, _f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
//         todo!()
//     }
// }
// impl <M: KemCore, T:KemCore, COM: HybridCombiner> Encapsulate<Array<u8, Sum<M::CiphertextSize, T::CiphertextSize>>, Array<u8,U32>> for HybridPublicKey2<M,T,COM>
// where <M as KemCore>::CiphertextSize: Add<<T as KemCore>::CiphertextSize>,
//     <<M as KemCore>::CiphertextSize as Add<<T as KemCore>::CiphertextSize>>::Output: hybrid_array::ArraySize,
//     COM: Default,
// {
//     type Error = kem::Error;
//     fn encapsulate(&self, rng: &mut impl rand_core::CryptoRngCore) -> Result<(Array<u8, Sum<M::CiphertextSize, T::CiphertextSize>>, Array<u8,U32>), Self::Error> {
//         let (pq_ct, pq_ss) = self.pq_key.encapsulate(rng).unwrap();
//         let (trad_ek, trad_ss2) = self.trad_key.encapsulate(rng).unwrap();
//         let ss: GenericArray<u8, U32> = COM::default().combine(pq_ss.as_slice(), pq_ct.as_slice(), &self.pq_key.as_bytes(), &trad_ss2, &trad_ek, &self.trad_key.as_bytes());
                
//         Ok((pq_ct.concat(trad_ek), Array::try_from(ss.as_slice()).unwrap() ))

//     }
// }
// // impl <M: KemCore, T:KemCore, C: HybridCombiner> EncapsulateDeterministic<Array<u8, Sum<M::CiphertextSize, T::CiphertextSize>>, Array<u8, U32>> for HybridPublicKey2<M,T,C>
// // where <M as KemCore>::CiphertextSize: Add<<T as KemCore>::CiphertextSize>,
// //     <<M as KemCore>::CiphertextSize as Add<<T as KemCore>::CiphertextSize>>::Output: hybrid_array::ArraySize
// // {
// //     type Error = kem::Error;
// //     fn encapsulate_deterministic(&self, _m: &ml_kem::B32) -> Result<(Array<u8, Sum<M::CiphertextSize, T::CiphertextSize>>, Array<u8, U32>), Self::Error> {
// //         todo!()
// //     }
// // }
// pub struct HybridPrivateKey2<M:KemCore, T:KemCore, COM: HybridCombiner> {
//     pq_key: M::DecapsulationKey,
//     trad_key: T::DecapsulationKey,
//     phantom: PhantomData<COM>
// }
// impl <M: KemCore, T: KemCore, C: HybridCombiner> PartialEq for HybridPrivateKey2<M,T, C>
// {
//     fn eq(&self, _other: &Self) -> bool {
//         todo!()
//     }
// }
// impl <M: KemCore, T: KemCore, C: HybridCombiner> Debug for HybridPrivateKey2<M,T,C>
// {
//     fn fmt(&self, _f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
//         todo!()
//     }
// }
// impl <M: KemCore, T: KemCore, COM: HybridCombiner> Decapsulate<Array<u8, Sum<M::CiphertextSize, T::CiphertextSize>>, Array<u8, U32>> for HybridPrivateKey2<M,T,COM>
// where <M as KemCore>::CiphertextSize: Add<<T as KemCore>::CiphertextSize>,
//         <<M as KemCore>::CiphertextSize as Add<<T as KemCore>::CiphertextSize>>::Output: hybrid_array::ArraySize,
//         COM: Default,
// {
//     type Error = kem::Error;
//     fn decapsulate(&self, encapsulated_key: &Array<u8, Sum<M::CiphertextSize, T::CiphertextSize>>) -> Result<Array<u8, U32>, Self::Error> {
//         //let (ek1,ek2) = encapsulated_key.split(1);
//         let pq_ct = encapsulated_key[..M::CiphertextSize::USIZE].try_into().unwrap();
//         let trad_ek = encapsulated_key[M::CiphertextSize::USIZE..].try_into().unwrap();


//         let pq_ss = self.pq_key.decapsulate(pq_ct).unwrap();
//         let trad_ss2 = self.trad_key.decapsulate(trad_ek).unwrap();
//         let ss: GenericArray<u8, U32> = COM::default().combine(pq_ss.as_slice(), pq_ct, &self.pq_key.as_bytes(), &trad_ss2, &trad_ek, &self.trad_key.as_bytes());
                
//         Ok(Array::try_from(ss.as_slice()).unwrap())
//     }
// }

// impl <M: KemCore, T: KemCore, C: HybridCombiner> EncodedSizeUser for HybridPrivateKey2<M,T,C>
// {
//     type EncodedSize = <<M as KemCore>::DecapsulationKey as EncodedSizeUser>::EncodedSize;
//     fn as_bytes(&self) -> ml_kem::Encoded<Self> {
//         todo!()
//     }
//     fn from_bytes(_enc: &ml_kem::Encoded<Self>) -> Self {
//         todo!()
//     }
// }



// impl<M: KemCore, C: Capsulator, COM: HybridCombiner> Default for HybridEncapsulator<M, C, COM>
// where C::Encapsulator: Default
// {
//     fn default() -> Self {
//         Self{ pq_encapsulator: None, encapsulator_2: C::Encapsulator::default(), phantom6: PhantomData}
//     }
// }

// impl<M: KemCore, C: Encapsulator<EK>, C2: Capsulator<EncappedKey = EK>, EK: EncappedKey, COM: HybridCombiner + Default> Encapsulator<HybridEncapKey<M, EK, C2>> for HybridEncapsulator<M, C, EK, COM>
// where <EK as EncappedKey>::EncappedKeySize: Add<<M as KemCore>::CiphertextSize>,
//     <<EK as EncappedKey>::EncappedKeySize as Add<<M as KemCore>::CiphertextSize>>::Output: ArrayLength<u8>,
//     <EK as EncappedKey>::EncappedKeySize: Debug,
//     C: Default,
//     C: EncodePublicKey<EK::RecipientPublicKey>,
//     <M as KemCore>::CiphertextSize: ArrayLength<u8>,
//     C2::Encapsulator: GetPublicKey<<C2::EncappedKey as EncappedKey>::RecipientPublicKey>,
// {
//     fn try_encap<R: rand_core::CryptoRng + rand_core::RngCore>(
//         &self,
//         csprng: &mut R,
//         recip_pubkey: &<HybridEncapKey<M, EK, C2> as EncappedKey>::RecipientPublicKey,
//     ) -> Result<(HybridEncapKey<M, EK, C2>, kem::SharedSecret<HybridEncapKey<M, EK, C2>>), kem::Error> {

//         let (pq_ct, pq_ss) = recip_pubkey.pq_public_key.encapsulate(csprng).unwrap();

//         let trad_pub_key = recip_pubkey.trad_encapsulator.get_public_key();
//         //let (trad_ek, trad_ss2) = self.encapsulator_2.try_encap(csprng, &recip_pubkey.trad_public_key).unwrap();
//         let (trad_ek, trad_ss2) = self.encapsulator_2.try_encap(csprng, trad_pub_key).unwrap();

        
//         let ss = COM::default().combine(pq_ss.as_slice(), pq_ct.as_slice(), &recip_pubkey.pq_public_key.as_bytes(), trad_ss2.as_bytes(), trad_ek.as_bytes(), 
//             &C::encode(trad_pub_key));
        
//         Ok((HybridEncapKey::from_components(&pq_ct, trad_ek.as_bytes()).unwrap(), kem::SharedSecret::new(ss)))
//     }
// }

//pub type U1282 = UInt<UInt<UInt<UInt<UInt<UInt<UInt<UInt<UInt<UInt<UInt<UTerm, B1>, B0>, B1>, B0>, B0>, B0>, B0>, B0>, B0>, B1>, B0>;
// pub struct PredictableRng<'a> { rng_material: &'a [u8]}

// #[allow(dead_code)]
// impl PredictableRng<'_> {
//     pub fn new ( material: &[u8]) -> PredictableRng {
//         PredictableRng { rng_material: material }
//     }
// }
// impl CryptoRng for PredictableRng<'_> {}
// impl RngCore for PredictableRng<'_> {
//     fn next_u32(&mut self) -> u32 {
//         todo!()
//     }

//     fn next_u64(&mut self) -> u64 {
//         todo!()
//     }

//     fn fill_bytes(&mut self, dest: &mut [u8]) {
//         dest.copy_from_slice(&self.rng_material[..dest.len()]);
//     }

//     fn try_fill_bytes(&mut self, _dest: &mut [u8]) -> Result<(), elliptic_curve::rand_core::Error> {
//         todo!()
//     }
//}

// impl<M: Capsulator, C: Capsulator, COM: HybridCombiner> Encode for HybridEncapsulator<M, C, COM>
// where C::Encapsulator: Default + EncodedSizeUser2,
//     <M as Capsulator>::Encapsulator: EncodedSizeUser2,
//     <<M as Capsulator>::Encapsulator as EncodedSizeUser2>::EncodedSize: Add<<C::Encapsulator as EncodedSizeUser2>::EncodedSize>,
//     <<<M as Capsulator>::Encapsulator as EncodedSizeUser2>::EncodedSize as Add<<<C as Capsulator>::Encapsulator as EncodedSizeUser2>::EncodedSize>>::Output: ArrayLength<u8>,
//     <<M as Capsulator>::Encapsulator as EncodedSizeUser2>::EncodedSize: ArrayLength<u8>
// {
//     type EncodedLen = Sum<<M::Encapsulator as EncodedSizeUser2>::EncodedSize, <C::Encapsulator as EncodedSizeUser2>::EncodedSize>;

//     fn encode(&self) -> GenericArray<u8, Self::EncodedLen> {
//         let encapsulator1_pub_bytes = self.encapsulator1.as_bytes();
//         let encapsulator2_pub_bytes = self.encapsulator2.as_bytes();
        
//         encapsulator1_pub_bytes.concat(encapsulator2_pub_bytes)
//     }
//     fn decode(enc: &GenericArray<u8, Self::EncodedLen>) -> Self {
//         let (public_key1_bytes, public_key2_bytes) = enc.split_at(<M::Encapsulator as EncodedSizeUser2>::EncodedSize::USIZE);

//         let encapsulator1 = M::Encapsulator::from_bytes(public_key1_bytes.into());
//         let encapsulator2 = C::Encapsulator::from_bytes(public_key2_bytes.into());

//         Self { encapsulator1, encapsulator2, phantom: PhantomData}
//     }
// }
// impl<M: KemCore, C: Capsulator, COM: HybridCombiner> HybridKem<M, C, COM>
// where M: KemCore, 
//     M::EncapsulationKey: Clone,
//     <C as Capsulator>::Encapsulator: Default,
//     <C as Capsulator>::Decapsulator: PrivateKeyInit<<C as Capsulator>::SecretKey>,
// {
//     pub fn generate<CC: CurveArithmetic> (mut rng: &mut impl rand_core::CryptoRngCore ) -> 
//     (HybridPrivateKey<M, elliptic_curve::PublicKey<CC>, C>, 
//         HybridPublicKey<M,  C>)

//     where C:Capsulator<SecretKey = SecretKey<CC>>
//     {
//         let (dk2, pq_ek) = M::generate(&mut rng);
//         let skrm3 = elliptic_curve::SecretKey::<CC>::random(&mut rng);
//         let pkrm = skrm3.public_key();
//         //let (pk_trad, sk_trad) = C::generate3(rng);
        
//         //let trad_encaps = C::Encapsulator::from(pkrm);
        
//         //let (pkrm, skrm3) = C::generate3(rng);

//         return ( HybridPrivateKey { pq_private_key: dk2, pq_public_key: pq_ek.clone(), ec_public_key: pkrm, 
//                         trad_private_key: C::new_decapsulator(skrm3), trad_public_key: C::new_encapsulator()},
//                  HybridPublicKey { pq_public_key: pq_ek.clone(), trad_encapsulator: C::new_encapsulator()
//             } )

//     }
//     pub fn generate2 (mut pred_rng: &mut impl rand_core::CryptoRngCore ) -> (HybridPrivateKey::<M,x25519_dalek::PublicKey, C>, 
//         HybridPublicKey<M,C>)
//     where C: Capsulator<SecretKey = x25519_dalek::StaticSecret>,
//     {
//         let (dk2, _ek2) = M::generate(&mut pred_rng);

//         let skrm = x25519_dalek::StaticSecret::random_from_rng(&mut pred_rng);
//         let pkrm = x25519_dalek::PublicKey::from(&skrm);

//         return ( HybridPrivateKey { pq_private_key: dk2, pq_public_key: _ek2.clone(), ec_public_key: pkrm, 
//                     trad_private_key: C::new_decapsulator(skrm), trad_public_key: C::new_encapsulator() },
//                 HybridPublicKey { pq_public_key: _ek2, trad_encapsulator: C::new_encapsulator() })

//     }
// }



//pub type U1217 = UInt<UInt<UInt<UInt<UInt<UInt<UInt<UInt<UInt<UInt<UInt<UTerm, B1>, B0>, B0>, B1>, B1>, B0>, B0>, B0>, B0>, B0>, B1>;
//pub type U1121 = UInt<UInt<UInt<UInt<UInt<UInt<UInt<UInt<UInt<UInt<UInt<UTerm, B1>, B0>, B0>, B0>, B1>, B1>, B0>, B0>, B0>, B0>, B1>;

//impl<M: KemCore, C: Encapsulator<EK>, EK: EncappedKey, COM: HybridCombiner> ml_kem::kem::Encapsulate<GenericArray<u8, U1121>, Array<u8, U32>> for HybridEncapsulator<M, C, EK, COM>
//impl<M: KemCore, C: Encapsulator<EK>, EK: EncappedKey, COM: HybridCombiner> ml_kem::kem::Encapsulate<GenericArray<u8, Sum<M::CiphertextSize, EK::EncappedKeySize>>, Array<u8, U32>> for HybridEncapsulator<M, C, EK, COM>


// Wrapper to allow for the implementation of Debug as required by some of the Kem traits in rust crypto
// pub struct MlKemWrapper<M: KemCore> (M);

// impl<M: KemCore> KemCore for MlKemWrapper<M> {
//     type SharedKeySize = M::SharedKeySize;
//     type CiphertextSize = M::CiphertextSize;
//     type DecapsulationKey = M::DecapsulationKey;
//     type EncapsulationKey = M::EncapsulationKey;
    
//     fn generate(rng: &mut impl rand_core::CryptoRngCore) -> (Self::DecapsulationKey, Self::EncapsulationKey) {
//         M::generate(rng)
//     }
    
//     // fn generate_deterministic(_d: &ml_kem::B32, _z: &ml_kem::B32) -> (Self::DecapsulationKey, Self::EncapsulationKey) {
//     //     todo!()
//     // }
// }
// impl<M: KemCore> Debug for MlKemWrapper<M>
// {
//     fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
//         f.pad("Hello World")
//     }
// }