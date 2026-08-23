

use std::iter::once;
use std::{marker::PhantomData, fmt::Debug};
use cipher::{Array, KeySizeUser, array::ArraySize, common::KeyExport, KeyInit, common::TryKeyInit};
use kem::{Ciphertext, Decapsulate, Decapsulator, Encapsulate, FromSeed, Generate, InvalidKey, Kem, SharedKey, TryDecapsulate};
use kdfs::{Kdf};
use crate::{EncapsulateDeterministic, FromKey, FromKeys};
use crate::{SetKdf};


///
/// JwaKdf is the KDF used as part of JSON Web Algorithms, specifically in the ECDH-ES Key Agreement 
/// RFC 7518 references the Concat KDF as defined in NIST SP 800-56A
/// The structure includes some fields set at init time which means the object can be passed around to functions 
/// accepting the KdfWithContext trait and it will derive keys properly 
///
/// The following example is from Appendix C of RFC 7518. The curve parameter is not strictly needed for this example, as the secret key derivation is not required.
/// ```
/// use kems::kem_with_kdf::JwaKdf;
/// use kdfs::nistsp800_56::ConcatKdf;
/// use kdfs::hybrid_array::{Array, typenum::consts::*};
/// use kdfs::Kdf;
/// use sha2::Sha256;
/// 
/// let secret = [158, 86, 217, 29, 129, 113, 53, 211, 114, 131, 66, 131, 191, 132, 38, 156, 251, 49, 110, 163, 218, 128, 106, 72, 246, 218, 167, 121, 140, 254, 144, 196];
/// let algorithm_id = b"A128GCM";
/// let party_u_info = b"Alice";
/// let party_v_info = b"Bob";
/// let exp_result = [86, 170, 141, 234, 248, 35, 109, 32, 92, 34, 40, 205, 113, 167, 16, 26];
/// 
/// let mut kdf = JwaKdf::<ConcatKdf<Sha256>,true>::new(algorithm_id, party_u_info, party_v_info);
/// let result: Array<u8, U16> = kdf.derive_self_secret_other( &secret, &[]);
/// 
/// assert! ( result == exp_result)
/// ```
#[derive(Clone)]
pub struct JwaKdf<K, const INCLUDE_KEY_LEN: bool> {
    algorithm_id: Vec<u8>,
    party_u_info: Vec<u8>,
    party_v_info: Vec<u8>,
    phantom: PhantomData<K>,
}

impl<K, const INCLUDE_KEY_LEN: bool> JwaKdf<K, INCLUDE_KEY_LEN> {
    /// Create a new object with the static fields recorded for later use in derivation
    pub fn new(algorithm_id: impl AsRef<[u8]>, party_u_info: impl AsRef<[u8]>, party_v_info: impl AsRef<[u8]>) -> Self {
        Self {
            algorithm_id: algorithm_id.as_ref().to_vec(),
            party_u_info: party_u_info.as_ref().to_vec(),
            party_v_info: party_v_info.as_ref().to_vec(),
            phantom: PhantomData,
        }
    }
}
impl<K, const INCLUDE_KEY_LEN: bool> Default for JwaKdf<K, INCLUDE_KEY_LEN>
{
    fn default() -> Self {
        Self { algorithm_id: Default::default(), party_u_info: Default::default(), party_v_info: Default::default(), phantom: Default::default() }
    }
}

// impl<K: KdfSlice + Default, const INCLUDE_KEY_LEN: bool> KdfSlice for JwaKdf<K, INCLUDE_KEY_LEN>
// {
//     fn derive_self_secrets_others_into<'a,'b> ( &self, secret: impl IntoIterator<Item=&'a[u8]> + Clone, _other_data: impl IntoIterator<Item=&'b[u8]> + Clone, out: &mut [u8]) -> Result<(), kdfs::Error> {
//         let algorithm_id_len = (self.algorithm_id.len() as u32 ).to_be_bytes();
//         let party_u_info_len = (self.party_u_info.len() as u32 ).to_be_bytes();
//         let party_v_info_len = (self.party_v_info.len() as u32 ).to_be_bytes();
//         if INCLUDE_KEY_LEN {
//             let key_len = ((out.len() as u32 )* 8).to_be_bytes();
//             K::default().derive_self_secrets_others_into ( secret, [&algorithm_id_len[..], &self.algorithm_id[..], &party_u_info_len[..], &self.party_u_info[..], &party_v_info_len[..], &self.party_v_info[..], &key_len], out )
//         } else {
//             K::default().derive_self_secrets_others_into ( secret, [&algorithm_id_len[..], &self.algorithm_id[..], &party_u_info_len[..], &self.party_u_info[..], &party_v_info_len[..], &self.party_v_info[..]], out )
//         }
//     }
// }

impl<K: Kdf<L> + Default, const INCLUDE_KEY_LEN: bool, L: ArraySize> Kdf<L> for JwaKdf<K, INCLUDE_KEY_LEN>
{
    fn derive_self_secrets_others<'a,'b> ( &self, secret: impl IntoIterator<Item=&'a[u8]> + Clone, _other_data: impl IntoIterator<Item=&'b[u8]> + Clone) -> Array<u8, L> {
        let algorithm_id_len = (self.algorithm_id.len() as u32 ).to_be_bytes();
        let party_u_info_len = (self.party_u_info.len() as u32 ).to_be_bytes();
        let party_v_info_len = (self.party_v_info.len() as u32 ).to_be_bytes();
        if INCLUDE_KEY_LEN {
            let key_len = (L::U32 * 8).to_be_bytes();
            K::default().derive_self_secrets_others(secret, [&algorithm_id_len[..], &self.algorithm_id[..], &party_u_info_len[..], &self.party_u_info[..], &party_v_info_len[..], &self.party_v_info[..], &key_len])
        } else {
            K::default().derive_self_secrets_others ( secret, [&algorithm_id_len[..], &self.algorithm_id[..], &party_u_info_len[..], &self.party_u_info[..], &party_v_info_len[..], &self.party_v_info[..]])
        }
    }
}


/// A combiner inputs the shared secret, ciphertext and public key/s and pushes it through a KDF to derive an output key
pub trait Combiner {
    //fn combine<L: ArraySize, K: KdfSlice>(raw_shared_secret: impl AsRef<[u8]>, ephemeral_pub: impl AsRef<[u8]>, encapsulator: &impl KeyExport, kdf: &K ) -> Result<Array<u8, L>, ()>;
    fn combine<L: ArraySize, K: Kdf<L>>(raw_shared_secret: impl AsRef<[u8]>, ephemeral_pub: impl AsRef<[u8]>, encapsulator: &impl KeyExport, kdf: &K ) -> Result<Array<u8, L>, ()>;
}



///
/// Combiner which includes the ciphertext (ephemeral public key) but not the public key/s.
/// Used by ECIES-KEM in ISO 18033-2, Apples ECIES implementation and EMVCo ECC DH implementation used in kernel C8
/// 
#[derive(Debug, Default, Ord, PartialEq, PartialOrd, Eq, Copy, Clone)]
pub struct CombinerCiphertext;

impl Combiner for CombinerCiphertext {
    fn combine<L: ArraySize, K: Kdf<L>>(raw_shared_secret: impl AsRef<[u8]>, ciphertext: impl AsRef<[u8]>, _encapsulator: &impl KeyExport, kdf: &K ) -> Result<Array<u8, L>, ()> {
        Ok(kdf.derive_self_secret_other(raw_shared_secret.as_ref(), ciphertext.as_ref()))
    }
}


///
/// Combiner which includes public key/s and ciphertext.
/// Used by HPKE, GPG and often with X25519 KEMs
/// 
#[derive(Debug, Default, Ord, PartialEq, PartialOrd, Eq, Copy, Clone)]
pub struct CombinerAllPubKeys;

impl Combiner for CombinerAllPubKeys {
    fn combine<L: ArraySize, K: Kdf<L>>(raw_shared_secret: impl AsRef<[u8]>, ciphertext: impl AsRef<[u8]>, encapsulator: &impl KeyExport, kdf: &K ) -> Result<Array<u8, L>,()> {
        Ok(kdf.derive_self_secret_others(raw_shared_secret.as_ref(), [ciphertext.as_ref(), &encapsulator.to_bytes()]))
    }
}

///
/// Combiner which does not include any public keys or ciphertexts.
/// Used by NIST, X9 and CMS
/// 
#[derive(Debug, Default, Ord, PartialEq, PartialOrd, Eq, Copy, Clone)]
pub struct CombinerNoKeys;

impl Combiner for CombinerNoKeys {
    fn combine<L: ArraySize, K: Kdf<L>>(raw_shared_secret: impl AsRef<[u8]>, _ciphertext: impl AsRef<[u8]>, _encapsulator: &impl KeyExport, kdf: &K ) -> Result<Array<u8, L>, ()> {
        Ok(kdf.derive_self_secret_other(raw_shared_secret.as_ref(), &[]))
    }
}

///
/// Elliptic Curve Combiner as used by the OpenPgp standard, RFC 9580
/// Two KDFs are mentioned in RFC 9580
/// - Concat KDF 
/// - HKDF
/// This implementation has a generic parameter which allows for any regular Kdf to be used
/// 
#[derive(Default, Clone)]
pub struct EcKdfOpenPgp<K> (PhantomData<K>);

// impl<K:KdfSlice + Default> KdfSlice for EcKdfOpenPgp<K>
// {
//     fn derive_self_secrets_others_into<'a,'b> ( &self, secret: impl IntoIterator<Item=&'a[u8]> + Clone, other_data: impl IntoIterator<Item=&'b[u8]> + Clone, out: &mut [u8]) -> Result<(), kdfs::Error> {
//         let secrets : Vec<_>= secret.into_iter().collect();
//         let other_data: Vec<_> = other_data.into_iter().collect();
//         K::default().derive_self_secrets_other_into([other_data[0], other_data[1], secrets[0]], b"OpenPGP X25519", out)
//     }
// }
impl<K:Kdf<L> + Default, L: ArraySize> Kdf<L> for EcKdfOpenPgp<K>
{
    
    fn derive_self_secrets_others<'a,'b> ( &self, secret: impl IntoIterator<Item=&'a[u8]> + Clone, other_data: impl IntoIterator<Item=&'b[u8]> + Clone) -> Array<u8, L> {
        let secrets : Vec<_>= secret.into_iter().collect();
        let other_data: Vec<_> = other_data.into_iter().collect();
        K::default().derive_self_secrets_others([other_data[0], other_data[1], secrets[0]], once(b"OpenPGP X25519".as_slice()))
    }
}


///
/// Wrapper function for a Kem which uses a Kdf to whiten the output
/// Four generic parameters:
///  KEM: Key Encapsulation Mechanism
///  COM: Combiner function, typically one of CombinerNoKeys, CombinerEphemOnly or CombinerAllPubKeys
///  KDF: Key derivation function to use
///  L: Length of output
/// 
/// 
#[derive(Default)]
pub struct KemWithKdf<KEM,COM,KDF,L> 
(
    PhantomData<KEM>,
    PhantomData<COM>,
    PhantomData<KDF>,
    PhantomData<L>
);
impl<KEM,COM,KDF,L> Debug for KemWithKdf<KEM,COM,KDF,L>
{
    fn fmt(&self, _f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        todo!()
    }
}
impl<KEM,COM,KDF,L> PartialOrd for KemWithKdf<KEM,COM,KDF,L>
{
    fn partial_cmp(&self, _other: &Self) -> Option<std::cmp::Ordering> {
        todo!()
    }
}
impl<KEM,COM,KDF,L> PartialEq for KemWithKdf<KEM,COM,KDF,L>
{
    fn eq(&self, _other: &Self) -> bool {
        todo!()
    }
}
impl<KEM,COM,KDF,L> Eq for KemWithKdf<KEM,COM,KDF,L>
{
}
impl<KEM,COM,KDF,L> Ord for KemWithKdf<KEM,COM,KDF,L>
{
    fn cmp(&self, _other: &Self) -> std::cmp::Ordering {
        todo!()
    }
}
impl<KEM,COM,KDF,L> Copy for KemWithKdf<KEM,COM,KDF,L>
{
    
}
impl<KEM,COM,KDF,L> Clone for KemWithKdf<KEM,COM,KDF,L>
{
    fn clone(&self) -> Self {
        todo!()
    }
}




impl<KEM, COM, KDF, L> Kem for KemWithKdf<KEM,COM,KDF,L>
where KEM: Kem,
    KEM::EncapsulationKey: Encapsulate + Eq + Clone + Debug,
    COM: Combiner + Debug + Ord + Default + Copy + Sync + Send + 'static,
    KDF: Kdf<L> + Default + Sync + Clone + Send + 'static,
    L: ArraySize + Ord + Sync + Send,
{
    type DecapsulationKey = KemWithKdfDecapsulator<KEM, COM, KDF, L>;
    type EncapsulationKey = KemWithKdfEncapsulator<KEM, COM, KDF, L>;
    type SharedKeySize = L;
    type CiphertextSize = <KEM as kem::Kem>::CiphertextSize;

    fn generate_keypair_from_rng<R: rand::prelude::CryptoRng>( rng: &mut R, ) -> (kem::DecapsulationKey<Self>, kem::EncapsulationKey<Self>)
    {
        let (decapsulator, encapsulator) = KEM::generate_keypair_from_rng(rng);
        let encapsulation_key = Self::EncapsulationKey{encapsulator: encapsulator.clone(), kdf: KDF::default(), phantom:PhantomData, phantom2: PhantomData};
        (Self::DecapsulationKey{decapsulator, encapsulation_key, kdf: KDF::default()},
            Self::EncapsulationKey{encapsulator, kdf: KDF::default(), phantom:PhantomData, phantom2: PhantomData})
    }
}


///
/// Wrapper struct which appends a KDF onto the output of a shared secret
///  KEM is the type of the raw key encapsulation mechanism used
///  COM is the combiner type, which defines the inputs to the KDF, which always includes the shared secret and may also include the ciphertext and/or public key/s
///  KDF is the key derivation function to use
///  N is the size of the output from the key derivation
/// 
//#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct KemWithKdfEncapsulator<KEM,COM,KDF,N>
where KEM: Kem
{
    pub encapsulator: KEM::EncapsulationKey,
    kdf: KDF,
    phantom: PhantomData<N>,
    phantom2: PhantomData<COM>
}



impl<KEM, COM, KDF, N> kem::Encapsulate for KemWithKdfEncapsulator<KEM,COM,KDF,N>
where KEM: Kem,
    N: ArraySize + Ord + Sync + Send,
    COM: Combiner + Debug + Ord + Default + Copy + Sync + Send + 'static,
    KDF: Kdf<N> + Default + Sync + Send + Clone + 'static,
{
    type Kem = KemWithKdf<KEM,COM,KDF,N>;

    fn encapsulate_with_rng<R>(&self, _rng: &mut R) -> (Ciphertext<Self::Kem>, SharedKey<Self::Kem>)
    where
        R: rand::CryptoRng + ?Sized {
        let (ciphertext, raw_shared_secret) = Encapsulate::encapsulate_with_rng(&self.encapsulator, _rng);
        let shared_secret = COM::combine(raw_shared_secret, &ciphertext, &self.encapsulator, &self.kdf).unwrap();
        (ciphertext, shared_secret)
    }
}


impl<KEM,COM,KDF,N> FromKey for KemWithKdfEncapsulator<KEM,COM,KDF,N> 
where KEM: Kem,
    KDF: Default,
    KEM::EncapsulationKey: FromKey,
{
    type Key = <KEM::EncapsulationKey as FromKey>::Key;

    fn from_key(key: Self::Key) -> Self {
        Self{encapsulator: KEM::EncapsulationKey::from_key(key), kdf: KDF::default(), phantom: PhantomData, phantom2: PhantomData}
    }
}


impl<KEM,COM,KDF,N> SetKdf for KemWithKdfEncapsulator<KEM,COM,KDF,N> 
where KEM: Kem,
{
    type Kdf = KDF;

    fn set_kdf(&mut self, kdf: Self::Kdf) {
        self.kdf = kdf
    }
}

impl<KEM,COM,KDF,N> FromKeys for KemWithKdfEncapsulator<KEM,COM,KDF,N> 
where KEM: Kem,
    KDF: Default,
    KEM::EncapsulationKey: FromKeys,
{
    type PrivateKey = <KEM::EncapsulationKey as FromKeys>::PrivateKey;
    type PublicKey = <KEM::EncapsulationKey as FromKeys>::PublicKey;
    
    fn from_keys ( pub_key: Self::PublicKey, priv_key: Self::PrivateKey ) -> Self {
        Self{encapsulator: KEM::EncapsulationKey::from_keys(pub_key, priv_key), kdf: KDF::default(), phantom: PhantomData, phantom2: PhantomData}
    }
}

impl<KEM,COM,KDF,N> KemWithKdfEncapsulator<KEM,COM,KDF,N>
where KEM: Kem,
    KDF: Default
{
    pub fn from_encapsulator(encapsulator: KEM::EncapsulationKey) -> Self {
        Self{encapsulator, kdf: KDF::default(), phantom: PhantomData, phantom2: PhantomData}
    }
    pub fn from_encapsulator_and_kdf(encapsulator: KEM::EncapsulationKey, kdf: KDF) -> Self {
        Self{encapsulator, kdf, phantom: PhantomData, phantom2: PhantomData}
    }
}

impl<KEM,COM,KDF,N> KeySizeUser for KemWithKdfEncapsulator<KEM,COM,KDF,N> 
where KEM: Kem,
    KDF: Default,
{
    type KeySize = <KEM::EncapsulationKey as KeySizeUser>::KeySize;
}

impl<KEM,COM,KDF,N> KeyExport for KemWithKdfEncapsulator<KEM,COM,KDF,N> 
where KEM: Kem,
    KDF: Default,
{
    fn to_bytes(&self) -> cipher::Key<Self> {
        self.encapsulator.to_bytes()
    }
}
impl<KEM,COM,KDF,N> KeyInit for KemWithKdfEncapsulator<KEM,COM,KDF,N> 
where KEM: Kem,
    KDF: Default,
    KEM::EncapsulationKey: KeyInit,
{
    fn new(key: &cipher::Key<Self>) -> Self {
        let encapsulator = <KEM::EncapsulationKey as KeyInit>::new(key);
        Self{encapsulator, kdf: KDF::default(), phantom: PhantomData, phantom2: PhantomData}
    }
}

impl<KEM,COM,KDF,N> TryKeyInit for KemWithKdfEncapsulator<KEM,COM,KDF,N> 
where KEM: Kem,
    KEM::EncapsulationKey: TryKeyInit,
    KDF: Default,
{
    fn new(key: &cipher::Key<Self>) -> Result<Self, kem::InvalidKey> {
        let encapsulator = <KEM::EncapsulationKey as TryKeyInit>::new(key)?;
        Ok(Self{encapsulator, kdf: KDF::default(), phantom: PhantomData, phantom2: PhantomData})
    }
}

impl<KEM, COM, KDF, N> Ord for KemWithKdfEncapsulator<KEM,COM,KDF,N>
where KEM: Kem
{
    fn cmp(&self, _other: &Self) -> std::cmp::Ordering {
        todo!()
    }
}
impl<KEM, COM, KDF, N> Eq for KemWithKdfEncapsulator<KEM,COM,KDF,N>
where KEM: Kem
{
    
}
impl<KEM, COM, KDF, N> PartialOrd for KemWithKdfEncapsulator<KEM,COM,KDF,N>
where KEM: Kem
{
    fn partial_cmp(&self, _other: &Self) -> Option<std::cmp::Ordering> {
        todo!()
    }
}
impl<KEM, COM, KDF, N> PartialEq for KemWithKdfEncapsulator<KEM,COM,KDF,N>
where KEM: Kem
{
    fn eq(&self, _other: &Self) -> bool {
        todo!()
    }
}
impl<KEM, COM, KDF, N> std::fmt::Debug for KemWithKdfEncapsulator<KEM,COM,KDF,N>
where KEM: Kem
{
    fn fmt(&self, _f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        todo!()
    }
}
impl<KEM, COM, KDF, N> Clone for KemWithKdfEncapsulator<KEM,COM,KDF,N>
where KEM: Kem,
    KDF: Default,
{
    fn clone(&self) -> Self {
        KemWithKdfEncapsulator{kdf: KDF::default(), encapsulator: self.encapsulator.clone(), phantom: PhantomData, phantom2: PhantomData}
    }
}

impl<KEM, COM, KDF, N> EncapsulateDeterministic for KemWithKdfEncapsulator<KEM,COM,KDF,N>
where KEM: Kem, 
    KEM::EncapsulationKey: EncapsulateDeterministic<Kem=KEM>,
    COM: Combiner + Debug + Ord + Default + Copy + Sync + Send + 'static,
    KDF: Default + Kdf<N> + Default + Sync + Clone + Send + 'static,
    N: ArraySize + Ord + Sync + Send,
{
    type Kem = KemWithKdf<KEM,COM,KDF,N>;
    type SeedSize = <KEM::EncapsulationKey as EncapsulateDeterministic>::SeedSize;

    fn encapsulate_deterministic(&self, seed: &[u8]) -> (Ciphertext<Self::Kem>, SharedKey<Self::Kem>) {
        let (ciphertext, raw_shared_secret) = self.encapsulator.encapsulate_deterministic(seed);
        
        let shared_secret = COM::combine(raw_shared_secret, &ciphertext, &self.encapsulator, &self.kdf).unwrap();
        (ciphertext, shared_secret)
    }
}







pub struct KemWithKdfDecapsulator<KEM,COM,KDF,L>
where KEM: Kem
{
    pub decapsulator: KEM::DecapsulationKey,
    encapsulation_key: KemWithKdfEncapsulator<KEM,COM,KDF,L>,
    kdf: KDF,
}


impl<KEM,COM,KDF,N> Generate for KemWithKdfDecapsulator<KEM,COM,KDF,N>
where KEM: Kem,
    KDF: Default
{
    fn try_generate_from_rng<R: rand::TryCryptoRng + ?Sized>(_rng: &mut R) -> Result<Self, R::Error> {
        let (decapsulator,_) = KEM::generate_keypair();
        let encapsulation_key = KemWithKdfEncapsulator { encapsulator: decapsulator.encapsulation_key().clone(), kdf: KDF::default(), phantom: PhantomData, phantom2: PhantomData};

        Ok(Self{ decapsulator, encapsulation_key, kdf: KDF::default() })
    }
}

impl<KEM,COM,KDF,N> Decapsulator for KemWithKdfDecapsulator<KEM,COM,KDF,N>
where KEM: kem::Kem,
    COM: Combiner + Sync + Send + Default + Debug + Ord + Copy + 'static,
    KDF: Kdf<N> + Default + Sync + Send + Clone + 'static,
    N: Ord + Sync + Send + ArraySize,
    KEM::EncapsulationKey: KeyExport + TryKeyInit + Clone + Eq + Debug + Encapsulate,
{
    type Kem = KemWithKdf<KEM,COM,KDF,N>;

    fn encapsulation_key(&self) -> &kem::EncapsulationKey<Self::Kem> {
        &self.encapsulation_key
    }
}

impl<KEM,COM,KDF,N> Decapsulate for KemWithKdfDecapsulator<KEM,COM,KDF,N>
where KEM: Kem, 
    KEM::EncapsulationKey: TryKeyInit + Eq + Clone + Debug + Encapsulate,
    COM: Combiner + Debug + Ord + Default + Copy + Sync + Send + 'static,
    KDF: Kdf<N> + Default + Sync + Send + Clone + 'static,
    N: ArraySize + Ord + Sync + Send,
{
    fn decapsulate(&self, ct: &kem::Ciphertext<Self::Kem>) -> kem::SharedKey<Self::Kem> {
        let raw_shared_secret = self.decapsulator.try_decapsulate(ct).unwrap();
        COM::combine(raw_shared_secret, ct, self.decapsulator.encapsulation_key(), &self.kdf).unwrap()
    }
}


impl<KEM,COM,KDF,N> FromKey for KemWithKdfDecapsulator<KEM,COM,KDF,N> 
where KEM: Kem,
    KDF: Default,
    KEM::DecapsulationKey: FromKey,
{
    type Key = <KEM::DecapsulationKey as FromKey>::Key;

    fn from_key(key: Self::Key) -> Self {
        let decapsulator = KEM::DecapsulationKey::from_key(key);
        let encapsulation_key = KemWithKdfEncapsulator::<KEM,COM,KDF,N>{encapsulator: decapsulator.encapsulation_key().clone(), kdf: KDF::default(), phantom: PhantomData, phantom2: PhantomData };
        Self{decapsulator, encapsulation_key, kdf: KDF::default()}
    }
}



impl<KEM,COM,KDF,N> KemWithKdfDecapsulator<KEM,COM,KDF,N>
where KEM: Kem,
    KDF: Default
{
    pub fn from_decapsulator_and_kdf(decapsulator: KEM::DecapsulationKey, kdf: KDF) -> Self {
        let encapsulation_key = KemWithKdfEncapsulator::<KEM,COM,KDF,N>{encapsulator: decapsulator.encapsulation_key().clone(), kdf: KDF::default(), phantom: PhantomData, phantom2: PhantomData };
        Self{decapsulator, encapsulation_key, kdf}
    }
}

impl<KEM,COM,KDF,N> SetKdf for KemWithKdfDecapsulator<KEM,COM,KDF,N> 
where KEM: Kem,
    KDF: Default,
{
    type Kdf = KDF;

    fn set_kdf(&mut self, kdf: Self::Kdf) {
        self.kdf = kdf
    }
}


impl<KEM,COM,KDF,N> KeySizeUser for KemWithKdfDecapsulator<KEM,COM,KDF,N> 
where KEM: Kem,
    KEM::DecapsulationKey: KeySizeUser,
    KDF: Default,
{
    type KeySize = <KEM::DecapsulationKey as KeySizeUser>::KeySize;
}

impl<KEM,COM,KDF,N> TryKeyInit for KemWithKdfDecapsulator<KEM,COM,KDF,N> 
where KEM: Kem,
    KEM::DecapsulationKey: KeySizeUser + TryKeyInit,
    KDF: Default,
{
    fn new(key: &cipher::Key<Self>) -> Result<KemWithKdfDecapsulator<KEM, COM, KDF, N>, InvalidKey> {
        let decapsulator = KEM::DecapsulationKey::new(key)?;
        let encapsulation_key = KemWithKdfEncapsulator { encapsulator: decapsulator.encapsulation_key().clone(), kdf: KDF::default(), phantom:PhantomData, phantom2: PhantomData};
        Ok(Self{decapsulator, encapsulation_key, kdf: KDF::default()})
    }
}
impl<KEM,COM,KDF,N> FromSeed for KemWithKdf<KEM,COM,KDF,N>
where KEM: FromSeed,
    KEM::EncapsulationKey: TryKeyInit,
    COM: Combiner + Debug + Ord + Default + Copy + Send + Sync + 'static,
    KDF: Kdf<N> + Default + Clone + Sync + Send + 'static, 
    N: ArraySize + Ord + Sync + Send,
{
    type SeedSize = KEM::SeedSize;

    fn from_seed(seed: &kem::Seed<Self>) -> (kem::DecapsulationKey<Self>, kem::EncapsulationKey<Self>) {
        let (decapsulator, encapsulator) = KEM::from_seed(seed);
        (KemWithKdfDecapsulator::from_decapsulator_and_kdf(decapsulator, KDF::default()), KemWithKdfEncapsulator::from_encapsulator(encapsulator))
    }
}


impl<KEM,COM,KDF,N> KeyExport for KemWithKdfDecapsulator<KEM,COM,KDF,N> 
where KEM: Kem,
    KEM::DecapsulationKey: KeySizeUser + KeyExport,
    KDF: Default,
{
    fn to_bytes(&self) -> cipher::Key<Self> {
        self.decapsulator.to_bytes()
    }
}






///
/// Wrapper function which applies a key derivation function to the output of a key encapsulation mechanism
///  KEM - Underlying key encapsulation function to use, which implements encapsulate and decapsulate
///  COM - Combiner which selects data to pass to the KDF, includes the raw shared secret and may include the ciphertext and public keys
///  KDF - Key derivation function which accepts the fields from the combiner and output key material
///  L - Lenght of the output key
///
pub struct KemAuthWithKdf<KEM,COM,KDF,L> 
(
    PhantomData<KEM>,
    PhantomData<COM>,
    PhantomData<KDF>,
    PhantomData<L>
);



impl<KEM, COM, KDF,L> KemAuthWithKdf<KEM,COM,KDF,L>
where KEM: Kem,
    KDF: Kdf<L>+ Default + Send + Sync + 'static,
    L: ArraySize + Send + Sync + 'static,
    COM: Combiner+ Send + Sync + 'static,
    KEM::EncapsulationKey: FromKeys,
    KEM::DecapsulationKey: FromKeys + Decapsulate,
{
    pub fn encap_from_keys ( pub_key: <KEM::EncapsulationKey as FromKeys>::PublicKey, priv_key: <KEM::EncapsulationKey as FromKeys>::PrivateKey ) -> <Self as Kem>::EncapsulationKey {
        KemAuthWithKdfEncapsulator::from_keys(pub_key, priv_key)
    }
    pub fn decap_from_keys ( pub_key: <KEM::DecapsulationKey as FromKeys>::PublicKey, priv_key: <KEM::DecapsulationKey as FromKeys>::PrivateKey ) -> <Self as Kem>::DecapsulationKey {
        KemAuthWithKdfDecapsulator::from_keys(pub_key, priv_key)
    }
}




pub struct KemAuthWithKdfEncapsulator<KEM,COM,KDF,N>
where KEM: Kem
{
    pub encapsulator: KEM::EncapsulationKey,
    kdf: KDF,
    phantom: PhantomData<N>,
    phantom2: PhantomData<COM>
}

impl<KEM,COM,KDF,N> FromKey for KemAuthWithKdfEncapsulator<KEM,COM,KDF,N> 
where KEM: Kem,
    KEM::EncapsulationKey: FromKey,
    KDF: Default,
{
    type Key = <KEM::EncapsulationKey as FromKey>::Key;

    fn from_key(key: Self::Key) -> Self {
        Self{encapsulator: KEM::EncapsulationKey::from_key(key), kdf: KDF::default(), phantom: PhantomData, phantom2: PhantomData}
    }
}

impl<KEM,COM,KDF,N> SetKdf for KemAuthWithKdfEncapsulator<KEM,COM,KDF,N> 
where KEM: Kem,
{
    type Kdf = KDF;

    fn set_kdf(&mut self, kdf: Self::Kdf) {
        self.kdf = kdf
    }
}

impl<KEM,COM,KDF,N> FromKeys for KemAuthWithKdfEncapsulator<KEM,COM,KDF,N> 
where KEM: Kem,
    KEM::EncapsulationKey: FromKeys,
    KDF: Default,
{
    type PrivateKey = <KEM::EncapsulationKey as FromKeys>::PrivateKey;
    type PublicKey = <KEM::EncapsulationKey as FromKeys>::PublicKey;
    
    fn from_keys ( pub_key: Self::PublicKey, priv_key: Self::PrivateKey ) -> Self {
        Self{encapsulator: KEM::EncapsulationKey::from_keys(pub_key, priv_key), kdf: KDF::default(), phantom: PhantomData, phantom2: PhantomData}
    }
}

impl<KEM,COM,KDF,N> KemAuthWithKdfEncapsulator<KEM,COM,KDF,N>
where KEM: Kem,
    KDF: Default
{
    pub fn from_encapsulator(encapsulator: KEM::EncapsulationKey) -> Self {
        Self{encapsulator, kdf: KDF::default(), phantom: PhantomData, phantom2: PhantomData}
    }
}




///
/// Wrapper for an authentication key decapsulation mechanism which applies a key derivation function to the raw shared secret
///  KEM - Underlying key encapsulation mechanism
///  COM - Combiner, which selects the fields to include in the key derivation - raw shared secret, public keys and/or ciphertext
///  KDF - Key derivation function to use for converting the combiner values into key material
///  L - Length of the output key material
pub struct KemAuthWithKdfDecapsulator<KEM,COM,KDF,L>
where KEM: Kem
{
    pub decapsulator: KEM::DecapsulationKey,
    kdf: KDF,
    phantom: PhantomData<L>,
    phantom2: PhantomData<COM>,
}

impl<KEM,COM,KDF,N> FromKey for KemAuthWithKdfDecapsulator<KEM,COM,KDF,N> 
where KEM: Kem,
    KEM::DecapsulationKey: FromKey,
    KDF: Default,
{
    type Key = <KEM::DecapsulationKey as FromKey>::Key;

    fn from_key(key: Self::Key) -> Self {
        Self{decapsulator: KEM::DecapsulationKey::from_key(key), kdf: KDF::default(), phantom: PhantomData, phantom2: PhantomData}
    }
}

impl<KEM,COM,KDF,N> KemAuthWithKdfDecapsulator<KEM,COM,KDF,N>
where KEM: Kem,
    KDF: Default
{
    pub fn from_decapsulator(decapsulator: KEM::DecapsulationKey) -> Self {
        Self{decapsulator, kdf: KDF::default(), phantom: PhantomData, phantom2: PhantomData}
    }
    pub fn from_decapsulator_and_kdf(decapsulator: KEM::DecapsulationKey, kdf: KDF) -> Self {
        Self{decapsulator, kdf, phantom: PhantomData, phantom2: PhantomData}
    }
}

impl<KEM,COM,KDF,N> SetKdf for KemAuthWithKdfDecapsulator<KEM,COM,KDF,N> 
where KEM: Kem,
{
    type Kdf = KDF;

    fn set_kdf(&mut self, kdf: Self::Kdf) {
        self.kdf = kdf
    }
}


impl<KEM,COM,KDF,N> FromKeys for KemAuthWithKdfDecapsulator<KEM,COM,KDF,N> 
where KEM: Kem,
    KEM::DecapsulationKey: FromKeys,
    KDF: Default,
{
    type PrivateKey = <KEM::DecapsulationKey as FromKeys>::PrivateKey;
    type PublicKey = <KEM::DecapsulationKey as FromKeys>::PublicKey;
    
    fn from_keys ( pub_key: Self::PublicKey, priv_key: Self::PrivateKey ) -> Self {
        Self{decapsulator: KEM::DecapsulationKey::from_keys(pub_key, priv_key), kdf: KDF::default(), phantom: PhantomData, phantom2: PhantomData}
    }
}













































impl<KEM, COM, KDF,L> Kem for KemAuthWithKdf<KEM,COM,KDF,L>
where KEM: kem::Kem + Kem,
    KDF: Kdf<L>+ Default+ Send + Sync + 'static,
    L: ArraySize + Send + Sync + 'static,
    COM: Combiner + Send + Sync + 'static,
    KEM::DecapsulationKey: Decapsulate, 
    
{
    type EncapsulationKey = KemAuthWithKdfEncapsulator<KEM, COM, KDF, L>;
    type DecapsulationKey = KemAuthWithKdfDecapsulator<KEM, COM, KDF, L>;
    type SharedKeySize = L;
    type CiphertextSize = KEM::CiphertextSize;
}


impl<KEM, COM, KDF,L> Eq for KemAuthWithKdf<KEM,COM,KDF,L>
{}
impl<KEM, COM, KDF,L> PartialEq for KemAuthWithKdf<KEM,COM,KDF,L>
{
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0 && self.1 == other.1 && self.2 == other.2 && self.3 == other.3
    }
}
impl<KEM, COM, KDF,L> Ord for KemAuthWithKdf<KEM,COM,KDF,L>
{
    fn cmp(&self, _other: &Self) -> std::cmp::Ordering {
        todo!()
    }
}
impl<KEM, COM, KDF,L> PartialOrd for KemAuthWithKdf<KEM,COM,KDF,L>
{
    fn partial_cmp(&self, _other: &Self) -> Option<std::cmp::Ordering> {
        todo!()
    }
}
impl<KEM, COM, KDF,L> std::fmt::Debug for KemAuthWithKdf<KEM,COM,KDF,L>
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("KemAuthWithKdf").field(&self.0).field(&self.1).field(&self.2).field(&self.3).finish()
    }
}

impl<KEM, COM, KDF,L> Clone for KemAuthWithKdf<KEM,COM,KDF,L>
{
    fn clone(&self) -> Self {
        Self(self.0.clone(), self.1.clone(), self.2.clone(), self.3.clone())
    }
}
impl<KEM, COM, KDF,L> Copy for KemAuthWithKdf<KEM,COM,KDF,L>
{

}
impl<KEM, COM, KDF,L> Default for KemAuthWithKdf<KEM,COM,KDF,L>
{
    fn default() -> Self {
        Self(Default::default(), Default::default(), Default::default(), Default::default())
    }
}



impl<KEM, COM, KDF,L> Decapsulator for KemAuthWithKdfDecapsulator<KEM,COM,KDF,L>
where KEM: Kem,
    KDF: Kdf<L>+ Default+ Send + Sync + 'static,
    L: ArraySize + Send + Sync + 'static,
    COM: Combiner + Send + Sync + 'static,
    KEM::DecapsulationKey: Decapsulate,
{
    type Kem = KemAuthWithKdf<KEM,COM,KDF,L>;

    fn encapsulation_key(&self) -> &kem::EncapsulationKey<Self::Kem> {
        todo!()
    }
}
impl<KEM, COM, KDF,L> Decapsulate for KemAuthWithKdfDecapsulator<KEM,COM,KDF,L>
where KEM: Kem,
    KDF: Default + Kdf<L> + Send + Sync + 'static,
    L: ArraySize + Send + Sync + 'static,
    COM: Combiner + Send + Sync + 'static,
    KEM::DecapsulationKey: Decapsulate,
{
    fn decapsulate(&self, ct: &kem::Ciphertext<Self::Kem>) -> kem::SharedKey<Self::Kem> {
        let raw_shared_secret = self.decapsulator.decapsulate(ct.as_slice().try_into().unwrap());
        COM::combine(raw_shared_secret, ct, self.decapsulator.encapsulation_key(), &self.kdf).unwrap()
    }
}

impl<KEM, COM, KDF,L> kem::Generate for KemAuthWithKdfDecapsulator<KEM,COM,KDF,L>
where KEM: Kem
{
    fn try_generate_from_rng<R: rand::TryCryptoRng + ?Sized>(_rng: &mut R) -> Result<Self, R::Error> {
        todo!()
    }
}


impl<KEM, COM, KDF,L> Encapsulate for KemAuthWithKdfEncapsulator<KEM,COM,KDF,L>
where KEM: Kem,
    KDF: Kdf<L> + Default+ Send + Sync + 'static,
    L: ArraySize + Send + Sync + 'static,
    COM: Combiner + Send + Sync + 'static,
    <KEM as Kem>::DecapsulationKey: Decapsulate,
{
    type Kem = KemAuthWithKdf<KEM,COM,KDF,L>;

    fn encapsulate_with_rng<R>(&self, _rng: &mut R) -> (kem::Ciphertext<Self::Kem>, kem::SharedKey<Self::Kem>)
    where
        R: rand::prelude::CryptoRng + ?Sized {

        let (ciphertext, raw_shared_secret) = self.encapsulator.encapsulate_with_rng(_rng);
        let shared_secret = COM::combine(raw_shared_secret, &ciphertext, &self.encapsulator, &self.kdf).unwrap();
        (ciphertext, shared_secret)   
    }
}
impl<KEM, COM, KDF,L> EncapsulateDeterministic for KemAuthWithKdfEncapsulator<KEM,COM,KDF,L>
where KEM: kem::Kem + Kem,
    KDF: Kdf<L>+ Default+ Send + Sync + 'static,
    L: ArraySize + Send + Sync + 'static,
    COM: Combiner + Send + Sync + 'static,
    KEM::DecapsulationKey: Decapsulate,
    KEM::EncapsulationKey: EncapsulateDeterministic<Kem=KEM>,
{
    type Kem = KemAuthWithKdf<KEM,COM,KDF,L>;
    type SeedSize = <KEM::EncapsulationKey as EncapsulateDeterministic>::SeedSize;
    
    fn encapsulate_deterministic(&self, seed: &[u8]) -> (kem::Ciphertext<Self::Kem>, kem::SharedKey<Self::Kem>) {
        let (ciphertext, raw_shared_secret) = self.encapsulator.encapsulate_deterministic(seed);
        let shared_secret = COM::combine(raw_shared_secret, &ciphertext, &self.encapsulator, &self.kdf).unwrap();
        (ciphertext, shared_secret)
    }
}

impl<KEM, COM, KDF,L> Clone for KemAuthWithKdfEncapsulator<KEM,COM,KDF,L>
where KEM: Kem
{
    fn clone(&self) -> Self {
        todo!()
    }
}

impl<KEM, COM, KDF,L> KeySizeUser for KemAuthWithKdfEncapsulator<KEM,COM,KDF,L>
where KEM: Kem
{
    type KeySize = cipher::consts::U32;
}

impl<KEM, COM, KDF,L> TryKeyInit for KemAuthWithKdfEncapsulator<KEM,COM,KDF,L>
where KEM: Kem
{
    fn new(_key: &kem::Key<Self>) -> Result<Self, kem::InvalidKey> {
        todo!()
    }
}

impl<KEM, COM, KDF,L> KeyExport for KemAuthWithKdfEncapsulator<KEM,COM,KDF,L>
where KEM: Kem
{
    fn to_bytes(&self) -> kem::Key<Self> {
        todo!()
    }
}

impl<KEM, COM, KDF,L> std::fmt::Debug for KemAuthWithKdfEncapsulator<KEM,COM,KDF,L>
where KEM: Kem
{
    fn fmt(&self, _f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        todo!()
    }
}

impl<KEM, COM, KDF,L> Eq for KemAuthWithKdfEncapsulator<KEM,COM,KDF,L>
where KEM: Kem
{

}
impl<KEM, COM, KDF,L> PartialEq for KemAuthWithKdfEncapsulator<KEM,COM,KDF,L>
where KEM: Kem
{
    fn eq(&self, _other: &Self) -> bool {
        todo!()
    }
}
impl<KEM, COM, KDF,L> Ord for KemAuthWithKdfEncapsulator<KEM,COM,KDF,L>
where KEM: Kem
{
    fn cmp(&self, _other: &Self) -> std::cmp::Ordering {
        todo!()
    }
}
impl<KEM, COM, KDF,L> PartialOrd for KemAuthWithKdfEncapsulator<KEM,COM,KDF,L>
where KEM: Kem
{
    fn partial_cmp(&self, _other: &Self) -> Option<std::cmp::Ordering> {
        todo!()
    }
}



