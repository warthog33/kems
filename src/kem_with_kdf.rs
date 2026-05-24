use std::marker::PhantomData;
use cipher::{Array, array::ArraySize};
use generic_array::GenericArray;
use kdfs::Kdf;
use crate::{Capsulator, Decapsulate, DecodeGenericArray, Encapsulate, EncapsulateDeterministic2, EncodedSizeUser2, FromKey, FromKeys, GenerateCapsulatorFromSeed, GetEncapsulator, GetRecipientPublicKeyBytes, GetSenderPublicKeyBytes, SetKdf};


///
/// JwaKdf is the KDF used as part of JSON Web Algorithms, specifically in the ECDH-ES Key Agreement 
/// RFC 7518 references the Concat KDF as defined in NIST SP 800-56A
/// The structure includes some fields set at init time which means the object can be passed around to functions 
/// accepting the KdfWithContext trait and it will derive keys properly 
///
/// The following example is from Appendix C of RFC 7518. The curve parameter is not strictly needed for this example, as the secret derivation is not required.
/// ```
/// use kems::kem_with_kdf::JwaKdf;
/// use kdfs::nistsp800_56::ConcatKdf;
/// use kdfs::Kdf;
/// use sha2::Sha256;
/// use p256::NistP256;
/// use kems::generic_array::typenum::consts::*;
/// 
/// let secret = [158, 86, 217, 29, 129, 113, 53, 211, 114, 131, 66, 131, 191, 132, 38, 156, 251, 49, 110, 163, 218, 128, 106, 72, 246, 218, 167, 121, 140, 254, 144, 196];
/// let algorithm_id = b"A128GCM";
/// let party_u_info = b"Alice";
/// let party_v_info = b"Bob";
/// let exp_result = [86, 170, 141, 234, 248, 35, 109, 32, 92, 34, 40, 205, 113, 167, 16, 26];
/// 
/// let mut kdf = JwaKdf::<ConcatKdf<Sha256>,true>::new(algorithm_id, party_u_info, party_v_info);
/// let result = kdf.derive_self_secret_other::<U16> ( &secret, &[]).unwrap();
/// 
/// assert! ( result == exp_result)
/// ```
#[derive(Clone)]
//pub struct JwaKdf<'a, H: Digest>{
pub struct JwaKdf<'a, K: Kdf, const INCLUDE_KEY_LEN: bool> {
    algorithm_id: &'a [u8],
    party_u_info: &'a [u8],
    party_v_info: &'a [u8],
    phantom: PhantomData<K>,
}


//impl<'a, H: Digest> JwaKdf<'a, H> {
impl<'a, K: Kdf, const INCLUDE_KEY_LEN: bool> JwaKdf<'a, K, INCLUDE_KEY_LEN> {
    /// Create a new object with the static fields recorded for later use in derivation
    pub fn new(algorithm_id: &'a [u8], party_u_info: &'a [u8], party_v_info: &'a [u8] ) -> Self{
        return JwaKdf { algorithm_id, party_u_info, party_v_info, phantom: PhantomData }
    }
}
//impl<'a, H: Digest + FixedOutputReset> Default for JwaKdf<'a, H>
impl<'a, K: Kdf, const INCLUDE_KEY_LEN: bool> Default for JwaKdf<'a, K, INCLUDE_KEY_LEN>
{
    fn default() -> Self {
        Self { algorithm_id: Default::default(), party_u_info: Default::default(), party_v_info: Default::default(), phantom: Default::default() }
    }
}

//impl<'c, H: Digest + FixedOutputReset> Kdf for JwaKdf<'c, H>
impl<'c, K: Kdf + Default, const INCLUDE_KEY_LEN: bool> Kdf for JwaKdf<'c, K, INCLUDE_KEY_LEN>
{
    fn derive_self_secrets_others_into<'a,'b> ( &self, secret: impl IntoIterator<Item=&'a[u8]> + Clone, _other_data: impl IntoIterator<Item=&'b[u8]> + Clone, out: &mut [u8]) -> Result<(), kdfs::Error> {
        let algorithm_id_len = (self.algorithm_id.len() as u32 ).to_be_bytes();
        let party_u_info_len = (self.party_u_info.len() as u32 ).to_be_bytes();
        let party_v_info_len = (self.party_v_info.len() as u32 ).to_be_bytes();
        if INCLUDE_KEY_LEN {
            let key_len = ((out.len() as u32 )* 8).to_be_bytes();
            K::default().derive_self_secrets_others_into ( secret, [&algorithm_id_len, self.algorithm_id, &party_u_info_len, self.party_u_info, &party_v_info_len, self.party_v_info, &key_len], out )
        } else {
            K::default().derive_self_secrets_others_into ( secret, [&algorithm_id_len, self.algorithm_id, &party_u_info_len, self.party_u_info, &party_v_info_len, self.party_v_info], out )
        }
    }
}






pub struct CombinerNoKeys;
pub struct CombinerEphemOnly;
pub struct CombinerAllPubKeys;

pub trait Combiner {
    fn combine<L: ArraySize, K: Kdf, E>(raw_shared_secret: impl AsRef<[u8]>, ephemeral_pub: impl AsRef<[u8]>, encapsulator: &E, kdf: &K ) -> Result<Array<u8, L>, ()>
    where E: GetRecipientPublicKeyBytes;
}
pub trait AuthCombiner {
    fn combine<L: ArraySize, K: Kdf, E>(raw_shared_secret: impl AsRef<[u8]>, ephemeral_pub: impl AsRef<[u8]>, encapsulator: &E, kdf: &K ) -> Result<Array<u8, L>, ()>
    where E: GetSenderPublicKeyBytes + GetRecipientPublicKeyBytes;
}



impl Combiner for CombinerNoKeys {
    fn combine<L: ArraySize, K: Kdf, E>(raw_shared_secret: impl AsRef<[u8]>, _ephemeral_pub: impl AsRef<[u8]>, _encapsulator: &E, kdf: &K ) -> Result<Array<u8, L>, ()> {
        kdf.derive_self_secret_other(raw_shared_secret.as_ref(), &[]).map_err(|_|())
    }
}
impl AuthCombiner for CombinerNoKeys {
    fn combine<L: ArraySize, K: Kdf, E>(raw_shared_secret: impl AsRef<[u8]>, _ephemeral_pub: impl AsRef<[u8]>, _encapsulator: &E, kdf: &K ) -> Result<Array<u8, L>, ()> {
        kdf.derive_self_secret_other(raw_shared_secret.as_ref(), &[]).map_err(|_|())
    }
}
impl Combiner for CombinerEphemOnly {
    fn combine<L: ArraySize, K: Kdf, E>(raw_shared_secret: impl AsRef<[u8]>, ephemeral_pub: impl AsRef<[u8]>, _encapsulator: &E, kdf: &K ) -> Result<Array<u8, L>, ()> {
        kdf.derive_self_secret_other(raw_shared_secret.as_ref(), ephemeral_pub.as_ref()).map_err(|_|())
    }
}

impl Combiner for CombinerAllPubKeys {
    fn combine<L: ArraySize, K: Kdf, E: GetRecipientPublicKeyBytes>(raw_shared_secret: impl AsRef<[u8]>, ephemeral_pub: impl AsRef<[u8]>, encapsulator: &E, kdf: &K ) -> Result<Array<u8, L>,()> {
        kdf.derive_self_secret_others(raw_shared_secret.as_ref(), [ephemeral_pub.as_ref(), &encapsulator.get_recipient_public_key_bytes()]).map_err(|_|())
    }
}
impl AuthCombiner for CombinerAllPubKeys {
    fn combine<L: ArraySize, K: Kdf, E>(raw_shared_secret: impl AsRef<[u8]>, ephemeral_pub: impl AsRef<[u8]>, encapsulator: &E, kdf: &K ) -> Result<Array<u8, L>,()> 
    where E: GetSenderPublicKeyBytes + GetRecipientPublicKeyBytes
    {
        let sender_public_key_bytes = encapsulator.get_sender_public_key_bytes(); //GetSenderPublicKeyBytes
        let recipient_public_key_bytes = encapsulator.get_recipient_public_key_bytes(); //GetSenderPublicKeyBytes

        kdf.derive_self_secret_others(raw_shared_secret.as_ref(), [ephemeral_pub.as_ref(), &recipient_public_key_bytes, &sender_public_key_bytes ]).map_err(|_|())
    }
}

///
/// Elliptic Curve Combiner as used by the OpenPgp standard, RFC 9580
/// Two KDFs are mentioned in RFC 9580
/// - Concat KDF 
/// - HKDF
/// This implementation has a generic parameter which allows for any regular Kdf to be used
/// 
pub struct EcCombinerOpenPgp<K:Kdf> (PhantomData<K>);
impl<K: Kdf + Default> Default for EcCombinerOpenPgp<K>{
    fn default() -> Self {
        Self(Default::default())
    }
}

impl<K:Kdf + Default> Kdf for EcCombinerOpenPgp<K>
{
    fn derive_self_secrets_others_into<'a,'b> ( &self, secret: impl IntoIterator<Item=&'a[u8]> + Clone, other_data: impl IntoIterator<Item=&'b[u8]> + Clone, out: &mut [u8]) -> Result<(), kdfs::Error> {
        let secrets : Vec<_>= secret.into_iter().collect();
        let other_data: Vec<_> = other_data.into_iter().collect();
        K::default().derive_self_secrets_other_into([other_data[0], other_data[1], secrets[0]], b"OpenPGP X25519", out)
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
pub struct KemWithKdf<KEM,COM,KDF,L> 
(
    PhantomData<KEM>,
    PhantomData<COM>,
    PhantomData<KDF>,
    PhantomData<L>
);



impl<KEM, COM, KDF,L> Capsulator for KemWithKdf<KEM,COM,KDF,L>
where KEM: Capsulator,
    KDF: Kdf + Default,
    L: ArraySize,
    COM: Combiner,
    <KEM as Capsulator>::Encapsulator: GetRecipientPublicKeyBytes,
    <KEM as Capsulator>::Decapsulator: GetRecipientPublicKeyBytes,
{
    type Encapsulator = KemWithKdfEncapsulator<KEM, COM, KDF, L>;
    type Decapsulator = KemWithKdfDecapsulator<KEM, COM, KDF, L>;
    type SharedKeySize = L;
    type CiphertextSize = KEM::CiphertextSize;

    fn generate ( rng: &mut impl rand_core::CryptoRngCore ) -> (Self::Encapsulator, Self::Decapsulator) {
        let (encapsulator, decapsulator) = KEM::generate(rng);
        (Self::Encapsulator{encapsulator, kdf: KDF::default(), phantom:PhantomData, phantom2: PhantomData}, Self::Decapsulator{decapsulator, kdf: KDF::default(), phantom: PhantomData, phantom2: PhantomData})
    }
}


impl<KEM, COM, KDF, L> GenerateCapsulatorFromSeed for KemWithKdf<KEM,COM,KDF,L>
where KEM: GenerateCapsulatorFromSeed,
    KDF: Kdf + Default,
    L: ArraySize,
    COM: Combiner,
    <KEM as Capsulator>::Encapsulator: GetRecipientPublicKeyBytes,
    <KEM as Capsulator>::Decapsulator: GetRecipientPublicKeyBytes,
{
    type SeedSize = KEM::SeedSize;

    fn derive_from_seed(seed: &Array::<u8, Self::SeedSize>) -> (Self::Encapsulator, Self::Decapsulator) {
        let (encapsulator, decapsulator) = KEM::derive_from_seed(seed);
        (Self::Encapsulator{encapsulator, kdf: KDF::default(), phantom:PhantomData, phantom2: PhantomData}, Self::Decapsulator{decapsulator, kdf: KDF::default(), phantom: PhantomData, phantom2: PhantomData})
    }
}


///
/// Wrapper struct which appends a KDF onto the output of a shared secret
///  KEM is the type of the raw key encapsulation mechanism used
///  COM is the combiner type, which defines the inputs to the KDF, which always includes the shared secret and may also include the ciphertext and/or public key/s
///  KDF is the key derivation function to use
///  N is the size of the output from the key derivation
/// 
pub struct KemWithKdfEncapsulator<KEM,COM,KDF,N>
where KEM: Capsulator
{
    pub encapsulator: KEM::Encapsulator,
    kdf: KDF,
    phantom: PhantomData<N>,
    phantom2: PhantomData<COM>
}
impl<KEM, COM, KDF, N> Encapsulate<GenericArray::<u8, KEM::CiphertextSize>, Array::<u8, N>> for KemWithKdfEncapsulator<KEM,COM,KDF,N>
where KEM: Capsulator,
    KDF: Kdf,
    N: ArraySize,
    COM: Combiner,
    KEM::Encapsulator: GetRecipientPublicKeyBytes
{
    type Error = ();
    
    fn encapsulate(&self, rng: &mut impl rand_core::CryptoRngCore) -> Result<(GenericArray::<u8, KEM::CiphertextSize>, Array::<u8, N>), Self::Error> {
        let (ciphertext, raw_shared_secret) = self.encapsulator.encapsulate(rng).unwrap();
        let shared_secret = COM::combine(raw_shared_secret, &ciphertext, &self.encapsulator, &self.kdf)?;
        Ok((ciphertext, shared_secret))
    }
}
impl<KEM,COM,KDF,N> EncapsulateDeterministic2<GenericArray::<u8, KEM::CiphertextSize>, Array::<u8, N>> for KemWithKdfEncapsulator<KEM,COM,KDF,N>
where KEM: Capsulator,
    KDF: Kdf,
    N: ArraySize,
    COM: Combiner,
    KEM::Encapsulator: GetRecipientPublicKeyBytes + EncapsulateDeterministic2<GenericArray::<u8, KEM::CiphertextSize>, Array::<u8, KEM::SharedKeySize>>,
    <KEM::Encapsulator as EncapsulateDeterministic2<GenericArray<u8, <KEM as Capsulator>::CiphertextSize>, Array<u8, KEM::SharedKeySize>>>::Error: std::fmt::Debug,
{
    type Error = ();
    type SeedSize = <<KEM as Capsulator>::Encapsulator as EncapsulateDeterministic2<GenericArray::<u8, KEM::CiphertextSize>, Array::<u8, KEM::SharedKeySize>>>::SeedSize;
    
    fn encapsulate_deterministic(&self, seed: &[u8]) -> Result<(GenericArray::<u8, KEM::CiphertextSize>, Array::<u8, N>), Self::Error> {
        let Ok((ciphertext, raw_shared_secret)) = self.encapsulator.encapsulate_deterministic(seed) else { return Err(())};
        let shared_secret = COM::combine(raw_shared_secret, &ciphertext, &self.encapsulator, &self.kdf)?;
        Ok((ciphertext, shared_secret))
    }
}


impl<KEM,COM,KDF,N> FromKey for KemWithKdfEncapsulator<KEM,COM,KDF,N> 
where KEM: Capsulator,
    KEM::Encapsulator: FromKey,
    KDF: Default,
{
    type Key = <KEM::Encapsulator as FromKey>::Key;

    fn from_key(key: Self::Key) -> Self {
        Self{encapsulator: KEM::Encapsulator::from_key(key), kdf: KDF::default(), phantom: PhantomData, phantom2: PhantomData}
    }
}


impl<KEM,COM,KDF,N> SetKdf for KemWithKdfEncapsulator<KEM,COM,KDF,N> 
where KEM: Capsulator,
{
    type Kdf = KDF;

    fn set_kdf(&mut self, kdf: Self::Kdf) {
        self.kdf = kdf
    }
}

impl<KEM,COM,KDF,N> FromKeys for KemWithKdfEncapsulator<KEM,COM,KDF,N> 
where KEM: Capsulator,
    KEM::Encapsulator: FromKeys,
    KDF: Default,
{
    type PrivateKey = <KEM::Encapsulator as FromKeys>::PrivateKey;
    type PublicKey = <KEM::Encapsulator as FromKeys>::PublicKey;
    
    fn from_keys ( pub_key: Self::PublicKey, priv_key: Self::PrivateKey ) -> Self {
        Self{encapsulator: KEM::Encapsulator::from_keys(pub_key, priv_key), kdf: KDF::default(), phantom: PhantomData, phantom2: PhantomData}
    }
}

impl<KEM,COM,KDF,N> KemWithKdfEncapsulator<KEM,COM,KDF,N>
where KEM: Capsulator,
    KDF: Default
{
    pub fn from_encapsulator(encapsulator: KEM::Encapsulator) -> Self {
        Self{encapsulator, kdf: KDF::default(), phantom: PhantomData, phantom2: PhantomData}
    }
    pub fn from_encapsulator_and_kdf(encapsulator: KEM::Encapsulator, kdf: KDF) -> Self {
        Self{encapsulator, kdf, phantom: PhantomData, phantom2: PhantomData}
    }
}




impl<KEM,COM,KDF,N> EncodedSizeUser2 for KemWithKdfEncapsulator<KEM,COM,KDF,N> 
where KEM: Capsulator,
    KEM::Encapsulator: EncodedSizeUser2,
    KDF: Default,
{
    type EncodedSize = <KEM::Encapsulator as EncodedSizeUser2>::EncodedSize;

    fn from_bytes(enc: &crate::Encoded<Self>) -> Self {
        Self{encapsulator: KEM::Encapsulator::from_bytes(enc), kdf: KDF::default(), phantom: PhantomData, phantom2: PhantomData}
    }

    fn as_bytes(&self) -> crate::Encoded<Self> {
        self.encapsulator.as_bytes()
    }
}





impl<KEM,COM,KDF,N> GetRecipientPublicKeyBytes for KemWithKdfEncapsulator<KEM,COM,KDF,N> 
where KEM: Capsulator,
    <KEM as Capsulator>::Encapsulator: GetRecipientPublicKeyBytes,
    KEM::Encapsulator: EncodedSizeUser2,
    KDF: Default,
{
    type EncodedLen = <KEM::Encapsulator as GetRecipientPublicKeyBytes>::EncodedLen;

    fn get_recipient_public_key_bytes(&self) -> GenericArray<u8, Self::EncodedLen> {
        self.encapsulator.get_recipient_public_key_bytes()
    }
}


pub struct KemWithKdfDecapsulator<KEM,COM,KDF,L>
where KEM: Capsulator
{
    pub decapsulator: KEM::Decapsulator,
    kdf: KDF,
    phantom: PhantomData<L>,
    phantom2: PhantomData<COM>,
}

impl<KEM,COM,KDF,N> Decapsulate<GenericArray::<u8, KEM::CiphertextSize>, Array::<u8, N>> for KemWithKdfDecapsulator<KEM,COM,KDF,N>
where KEM: Capsulator,
    KDF: Kdf,
    N: ArraySize,  
    COM: Combiner,
    <KEM as Capsulator>::Decapsulator: GetRecipientPublicKeyBytes,
{
    type Error = ();
    fn decapsulate(&self, encapsulated_key: &GenericArray::<u8, KEM::CiphertextSize>) -> Result<Array::<u8, N>, Self::Error> {
        let raw_shared_secret = self.decapsulator.decapsulate(encapsulated_key).unwrap();
        COM::combine(raw_shared_secret, encapsulated_key, &self.decapsulator, &self.kdf)
    }
}

impl<KEM,COM,KDF,N> FromKey for KemWithKdfDecapsulator<KEM,COM,KDF,N> 
where KEM: Capsulator,
    KEM::Decapsulator: FromKey,
    KDF: Default,
{
    type Key = <KEM::Decapsulator as FromKey>::Key;

    fn from_key(key: Self::Key) -> Self {
        Self{decapsulator: KEM::Decapsulator::from_key(key), kdf: KDF::default(), phantom: PhantomData, phantom2: PhantomData}
    }
}

impl<KEM,COM,KDF,N> KemWithKdfDecapsulator<KEM,COM,KDF,N>
where KEM: Capsulator,
    KDF: Default
{
    pub fn from_decapsulator_and_kdf(decapsulator: KEM::Decapsulator, kdf: KDF) -> Self {
        Self{decapsulator, kdf, phantom: PhantomData, phantom2: PhantomData}
    }
}

impl<KEM,COM,KDF,N> SetKdf for KemWithKdfDecapsulator<KEM,COM,KDF,N> 
where KEM: Capsulator,
    KDF: Default,
{
    type Kdf = KDF;

    fn set_kdf(&mut self, kdf: Self::Kdf) {
        self.kdf = kdf
    }
}
impl<KEM,COM,KDF,N> GetEncapsulator for KemWithKdfDecapsulator<KEM,COM,KDF,N> 
where KEM: Capsulator,
    KEM::Decapsulator: GetEncapsulator<Encapsulator=KEM::Encapsulator>,
    KDF: Default,
{
    type Encapsulator = KemWithKdfEncapsulator<KEM,COM,KDF,N>;

    fn get_encapsulator(&self) -> Self::Encapsulator {
        Self::Encapsulator{encapsulator: self.decapsulator.get_encapsulator(), kdf: KDF::default(), phantom: PhantomData, phantom2: PhantomData}
    }
}

impl<KEM,COM,KDF,N> EncodedSizeUser2 for KemWithKdfDecapsulator<KEM,COM,KDF,N> 
where KEM: Capsulator,
    KEM::Decapsulator: EncodedSizeUser2,
    KDF: Default,
{
    type EncodedSize = <KEM::Decapsulator as EncodedSizeUser2>::EncodedSize;

    fn from_bytes(enc: &crate::Encoded<Self>) -> Self {
        Self{decapsulator: KEM::Decapsulator::from_bytes(enc), kdf: KDF::default(), phantom: PhantomData, phantom2: PhantomData}
    }

    fn as_bytes(&self) -> crate::Encoded<Self> {
        self.decapsulator.as_bytes()
    }
}


impl<KEM,COM,KDF,N> DecodeGenericArray<Self> for KemWithKdfDecapsulator<KEM,COM,KDF,N> 
where KEM: Capsulator,
    //KEM::Decapsulator: EncodedSizeUser2,
    KEM::Decapsulator: DecodeGenericArray<KEM::Decapsulator>,
    KDF: Default,
{
    type EncodedLen = <KEM::Decapsulator as DecodeGenericArray<KEM::Decapsulator>>::EncodedLen;
    
    type Error = ();
    
    fn decode(encoded_bytes: &GenericArray<u8, Self::EncodedLen>) -> Result<Self, Self::Error> {
        let Ok(decapsulator) = KEM::Decapsulator::decode(encoded_bytes) else { return Err(())};
        Ok(Self{decapsulator, kdf: KDF::default(), phantom: PhantomData, phantom2: PhantomData})
    }
}
impl<KEM,COM,KDF,N> GetRecipientPublicKeyBytes for KemWithKdfDecapsulator<KEM,COM,KDF,N> 
where KEM: Capsulator,
    <KEM as Capsulator>::Decapsulator: GetRecipientPublicKeyBytes,
    KEM::Encapsulator: EncodedSizeUser2,
    KDF: Default,
{
    type EncodedLen = <KEM::Decapsulator as GetRecipientPublicKeyBytes>::EncodedLen;

    fn get_recipient_public_key_bytes(&self) -> GenericArray<u8, Self::EncodedLen> {
        self.decapsulator.get_recipient_public_key_bytes()
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



impl<KEM, COM, KDF,L> Capsulator for KemAuthWithKdf<KEM,COM,KDF,L>
where KEM: Capsulator,
    KDF: Kdf + Default,
    L: ArraySize,
    COM: AuthCombiner,
    <KEM as Capsulator>::Encapsulator: GetSenderPublicKeyBytes + GetRecipientPublicKeyBytes,
    <KEM as Capsulator>::Decapsulator: GetSenderPublicKeyBytes + GetRecipientPublicKeyBytes,
{
    type Encapsulator = KemAuthWithKdfEncapsulator<KEM, COM, KDF, L>;
    type Decapsulator = KemAuthWithKdfDecapsulator<KEM, COM, KDF, L>;
    type SharedKeySize = L;
    type CiphertextSize = KEM::CiphertextSize;

    fn generate ( rng: &mut impl rand_core::CryptoRngCore ) -> (Self::Encapsulator, Self::Decapsulator) {
        let (encapsulator, decapsulator) = KEM::generate(rng);
        // (Self::Encapsulator{encapsulator, kdf: KDF::default(), phantom:PhantomData, phantom2: PhantomData}, 
        //     Self::Decapsulator{decapsulator, kdf: KDF::default(), phantom: PhantomData, phantom2: PhantomData})
        (Self::Encapsulator::from_encapsulator(encapsulator), Self::Decapsulator::from_decapsulator(decapsulator))
    }
}


impl<KEM, COM, KDF,L> GenerateCapsulatorFromSeed for KemAuthWithKdf<KEM,COM,KDF,L>
where KEM: GenerateCapsulatorFromSeed,
    KDF: Kdf + Default,
    L: ArraySize,
    COM: AuthCombiner,
    <KEM as Capsulator>::Encapsulator: GetSenderPublicKeyBytes + GetRecipientPublicKeyBytes,
    <KEM as Capsulator>::Decapsulator: GetSenderPublicKeyBytes + GetRecipientPublicKeyBytes,
{
    type SeedSize = KEM::SeedSize;

    fn derive_from_seed(seed: &Array::<u8, Self::SeedSize>) -> (Self::Encapsulator, Self::Decapsulator) {
        let (encapsulator, decapsulator) = KEM::derive_from_seed(seed);
        (Self::Encapsulator::from_encapsulator(encapsulator), Self::Decapsulator::from_decapsulator(decapsulator))//{encapsulator, kdf: KDF::default(), phantom:PhantomData, phantom2: PhantomData}, 
            //Self::Decapsulator{decapsulator, kdf: KDF::default(), phantom: PhantomData, phantom2: PhantomData})
    }
}


impl<KEM, COM, KDF,L> KemAuthWithKdf<KEM,COM,KDF,L>
where KEM: Capsulator,
    KDF: Kdf + Default,
    L: ArraySize,
    COM: AuthCombiner,
    <KEM as Capsulator>::Encapsulator: FromKeys + GetRecipientPublicKeyBytes + GetSenderPublicKeyBytes,
    <KEM as Capsulator>::Decapsulator: FromKeys + GetRecipientPublicKeyBytes + GetSenderPublicKeyBytes,
{
    pub fn encap_from_keys ( pub_key: <KEM::Encapsulator as FromKeys>::PublicKey, priv_key: <KEM::Encapsulator as FromKeys>::PrivateKey ) -> <Self as Capsulator>::Encapsulator {
        KemAuthWithKdfEncapsulator::from_keys(pub_key, priv_key)
    }
    pub fn decap_from_keys ( pub_key: <KEM::Decapsulator as FromKeys>::PublicKey, priv_key: <KEM::Decapsulator as FromKeys>::PrivateKey ) -> <Self as Capsulator>::Decapsulator {
        KemAuthWithKdfDecapsulator::from_keys(pub_key, priv_key)
    }
}




pub struct KemAuthWithKdfEncapsulator<KEM,COM,KDF,N>
where KEM: Capsulator
{
    pub encapsulator: KEM::Encapsulator,
    kdf: KDF,
    phantom: PhantomData<N>,
    phantom2: PhantomData<COM>
}
impl<KEM,COM,KDF,N> Encapsulate<GenericArray::<u8, KEM::CiphertextSize>, Array::<u8, N>> for KemAuthWithKdfEncapsulator<KEM,COM,KDF,N>
where KEM: Capsulator,
    KDF: Kdf,
    N: ArraySize,
    COM: AuthCombiner,
    //<KEM as Capsulator>::Encapsulator: EncodedSizeUser2,
    <KEM as Capsulator>::Encapsulator: GetSenderPublicKeyBytes + GetRecipientPublicKeyBytes,
{
    type Error = ();
    
    fn encapsulate(&self, rng: &mut impl rand_core::CryptoRngCore) -> Result<(GenericArray::<u8, KEM::CiphertextSize>, Array::<u8, N>), Self::Error> {
        let (ciphertext, raw_shared_secret) = self.encapsulator.encapsulate(rng).unwrap();
        let shared_secret = COM::combine(raw_shared_secret, &ciphertext, &self.encapsulator, &self.kdf)?;
        Ok((ciphertext, shared_secret))
    }
}
impl<KEM,COM,KDF,N> EncapsulateDeterministic2<GenericArray::<u8, KEM::CiphertextSize>, Array::<u8, N>> for KemAuthWithKdfEncapsulator<KEM,COM,KDF,N>
where KEM: Capsulator,
    KDF: Kdf,
    N: ArraySize,
    COM: AuthCombiner,
    KEM::Encapsulator: GetSenderPublicKeyBytes + GetRecipientPublicKeyBytes + EncapsulateDeterministic2<GenericArray::<u8, KEM::CiphertextSize>, Array::<u8, KEM::SharedKeySize>>,
    <KEM::Encapsulator as EncapsulateDeterministic2<GenericArray<u8, <KEM as Capsulator>::CiphertextSize>, cipher::Array<u8, KEM::SharedKeySize>>>::Error: std::fmt::Debug,
{
    type Error = ();
    type SeedSize = <<KEM as Capsulator>::Encapsulator as EncapsulateDeterministic2<GenericArray::<u8, KEM::CiphertextSize>, Array::<u8, KEM::SharedKeySize>>>::SeedSize;
        
    fn encapsulate_deterministic(&self, seed: &[u8]) -> Result<(GenericArray::<u8, KEM::CiphertextSize>, Array::<u8, N>), Self::Error> {
        let Ok((ciphertext, raw_shared_secret)) = self.encapsulator.encapsulate_deterministic(seed) else { return Err(())};
        let shared_secret = COM::combine(raw_shared_secret, &ciphertext, &self.encapsulator, &self.kdf)?;
        Ok((ciphertext, shared_secret))
    }
}

impl<KEM,COM,KDF,N> FromKey for KemAuthWithKdfEncapsulator<KEM,COM,KDF,N> 
where KEM: Capsulator,
    KEM::Encapsulator: FromKey,
    KDF: Default,
{
    type Key = <KEM::Encapsulator as FromKey>::Key;

    fn from_key(key: Self::Key) -> Self {
        Self{encapsulator: KEM::Encapsulator::from_key(key), kdf: KDF::default(), phantom: PhantomData, phantom2: PhantomData}
    }
}

impl<KEM,COM,KDF,N> SetKdf for KemAuthWithKdfEncapsulator<KEM,COM,KDF,N> 
where KEM: Capsulator,
{
    type Kdf = KDF;

    fn set_kdf(&mut self, kdf: Self::Kdf) {
        self.kdf = kdf
    }
}

impl<KEM,COM,KDF,N> FromKeys for KemAuthWithKdfEncapsulator<KEM,COM,KDF,N> 
where KEM: Capsulator,
    KEM::Encapsulator: FromKeys,
    KDF: Default,
{
    type PrivateKey = <KEM::Encapsulator as FromKeys>::PrivateKey;
    type PublicKey = <KEM::Encapsulator as FromKeys>::PublicKey;
    
    fn from_keys ( pub_key: Self::PublicKey, priv_key: Self::PrivateKey ) -> Self {
        Self{encapsulator: KEM::Encapsulator::from_keys(pub_key, priv_key), kdf: KDF::default(), phantom: PhantomData, phantom2: PhantomData}
    }
}

impl<KEM,COM,KDF,N> KemAuthWithKdfEncapsulator<KEM,COM,KDF,N>
where KEM: Capsulator,
    KDF: Default
{
    pub fn from_encapsulator(encapsulator: KEM::Encapsulator) -> Self {
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
where KEM: Capsulator
{
    pub decapsulator: KEM::Decapsulator,
    kdf: KDF,
    phantom: PhantomData<L>,
    phantom2: PhantomData<COM>,
}

impl<KEM,COM,KDF,N> Decapsulate<GenericArray::<u8, KEM::CiphertextSize>, Array::<u8, N>> for KemAuthWithKdfDecapsulator<KEM,COM,KDF,N>
where KEM: Capsulator,
    KDF: Kdf,
    N: ArraySize,  
    COM: AuthCombiner ,
    <KEM as Capsulator>::Decapsulator: GetRecipientPublicKeyBytes + GetSenderPublicKeyBytes
{
    type Error = ();
    fn decapsulate(&self, encapsulated_key: &GenericArray::<u8, KEM::CiphertextSize>) -> Result<Array::<u8, N>, Self::Error> {
        let Ok(raw_shared_secret) = self.decapsulator.decapsulate(encapsulated_key) else { return Err(())};
        COM::combine(raw_shared_secret, encapsulated_key, &self.decapsulator, &self.kdf)
    }
}

impl<KEM,COM,KDF,N> FromKey for KemAuthWithKdfDecapsulator<KEM,COM,KDF,N> 
where KEM: Capsulator,
    KEM::Decapsulator: FromKey,
    KDF: Default,
{
    type Key = <KEM::Decapsulator as FromKey>::Key;

    fn from_key(key: Self::Key) -> Self {
        Self{decapsulator: KEM::Decapsulator::from_key(key), kdf: KDF::default(), phantom: PhantomData, phantom2: PhantomData}
    }
}

impl<KEM,COM,KDF,N> KemAuthWithKdfDecapsulator<KEM,COM,KDF,N>
where KEM: Capsulator,
    KDF: Default
{
    pub fn from_decapsulator(decapsulator: KEM::Decapsulator) -> Self {
        Self{decapsulator, kdf: KDF::default(), phantom: PhantomData, phantom2: PhantomData}
    }
    pub fn from_decapsulator_and_kdf(decapsulator: KEM::Decapsulator, kdf: KDF) -> Self {
        Self{decapsulator, kdf, phantom: PhantomData, phantom2: PhantomData}
    }
}

impl<KEM,COM,KDF,N> SetKdf for KemAuthWithKdfDecapsulator<KEM,COM,KDF,N> 
where KEM: Capsulator,
{
    type Kdf = KDF;

    fn set_kdf(&mut self, kdf: Self::Kdf) {
        self.kdf = kdf
    }
}



impl<KEM,COM,KDF,N> EncodedSizeUser2 for KemAuthWithKdfDecapsulator<KEM,COM,KDF,N> 
where KEM: Capsulator,
    KEM::Decapsulator: EncodedSizeUser2,
    KDF: Default,
{
    type EncodedSize = <KEM::Decapsulator as EncodedSizeUser2>::EncodedSize;

    fn from_bytes(enc: &crate::Encoded<Self>) -> Self {
        Self{decapsulator: KEM::Decapsulator::from_bytes(enc), kdf: KDF::default(), phantom: PhantomData, phantom2: PhantomData}
    }

    fn as_bytes(&self) -> crate::Encoded<Self> {
        self.decapsulator.as_bytes()
    }
}

impl<KEM,COM,KDF,N> FromKeys for KemAuthWithKdfDecapsulator<KEM,COM,KDF,N> 
where KEM: Capsulator,
    KEM::Decapsulator: FromKeys,
    KDF: Default,
{
    type PrivateKey = <KEM::Decapsulator as FromKeys>::PrivateKey;
    type PublicKey = <KEM::Decapsulator as FromKeys>::PublicKey;
    
    fn from_keys ( pub_key: Self::PublicKey, priv_key: Self::PrivateKey ) -> Self {
        Self{decapsulator: KEM::Decapsulator::from_keys(pub_key, priv_key), kdf: KDF::default(), phantom: PhantomData, phantom2: PhantomData}
    }
}



// impl<KEM,COM,KDF,N> DecodeGenericArray<Self> for KemWithKdfEncapsulator<KEM,COM,KDF,N> 
// where KEM: Capsulator,
//     KEM::Encapsulator: EncodedSizeUser2,
//     KDF: Default,
// {
//     type EncodedLen = <KEM::Encapsulator as EncodedSizeUser2>::EncodedSize;
//     type Error = ();
    
//     fn decode(encoded_bytes: &GenericArray<u8, Self::EncodedLen>) -> Result<Self, Self::Error> {
//         Ok(Self{encapsulator: KEM::Encapsulator::from_bytes(encoded_bytes), kdf: KDF::default(), phantom: PhantomData, phantom2: PhantomData})
//     }
// }















//
// 
// 
// 



// pub struct KemWithKdfWithCiphertextAndPublicKey<KEM,KDF,L> 
// (
//     PhantomData<KEM>,
//     PhantomData<KDF>,
//     PhantomData<L>
// );



// impl<KEM, KDF,L> Capsulator for KemWithKdfWithCiphertextAndPublicKey<KEM,KDF,L>
// where KEM: Capsulator,
//     KDF: Kdf + Default,
//     L: ArraySize,
//     <KEM as Capsulator>::Encapsulator: EncodedSizeUser2,
//     <KEM as Capsulator>::Decapsulator: GetEncapsulator,
//     <<KEM as Capsulator>::Decapsulator as GetEncapsulator>::Encapsulator: EncodedSizeUser2,
// {
//     type Encapsulator = KemWithKdfWithCiphertextAndPublicKeyEncapsulator<KEM, KDF, L>;
//     type Decapsulator = KemWithKdfWithCiphertextAndPublicKeyDecapsulator<KEM, KDF, L>;
//     type SharedKeySize = L;
//     type CiphertextSize = KEM::CiphertextSize;

//     fn generate ( rng: &mut impl rand_core::CryptoRngCore ) -> (Self::Encapsulator, Self::Decapsulator) {
//         let (encapsulator, decapsulator) = KEM::generate(rng);
//         (Self::Encapsulator{encapsulator, kdf: KDF::default(), phantom:PhantomData}, Self::Decapsulator{decapsulator, kdf: KDF::default(), phantom: PhantomData})
//     }
// }

// impl<KEM, KDF, L> GenerateCapsulatorFromSeed for KemWithKdfWithCiphertextAndPublicKey<KEM,KDF,L>
// where KEM: GenerateCapsulatorFromSeed,
//     KDF: Kdf + Default,
//     L: ArraySize,
//     <KEM as Capsulator>::Encapsulator: EncodedSizeUser2,
//     <KEM as Capsulator>::Decapsulator: GetEncapsulator,
//     <<KEM as Capsulator>::Decapsulator as GetEncapsulator>::Encapsulator: EncodedSizeUser2,
// {
//     type SeedSize = KEM::SeedSize;

//     fn derive_from_seed(seed: &Array::<u8, Self::SeedSize>) -> (Self::Encapsulator, Self::Decapsulator) {
//         let (encapsulator, decapsulator) = KEM::derive_from_seed(seed);
//         (Self::Encapsulator{encapsulator, kdf: KDF::default(), phantom:PhantomData}, Self::Decapsulator{decapsulator, kdf: KDF::default(), phantom: PhantomData})
//     }
// }




// pub struct KemWithKdfWithCiphertextAndPublicKeyEncapsulator<KEM,KDF,N>
// where KEM: Capsulator
// {
//     pub encapsulator: KEM::Encapsulator,
//     pub kdf: KDF,
//     phantom: PhantomData<N>
// }
// impl<KEM,KDF,N> Encapsulate<GenericArray::<u8, KEM::CiphertextSize>, Array::<u8, N>> for KemWithKdfWithCiphertextAndPublicKeyEncapsulator<KEM,KDF,N>
// where KEM: Capsulator,
//     KEM::Encapsulator: EncodedSizeUser2,
//     KDF: Kdf,
//     N: ArraySize
// {
//     type Error = ();
    
//     fn encapsulate(&self, rng: &mut impl rand_core::CryptoRngCore) -> Result<(GenericArray::<u8, KEM::CiphertextSize>, Array::<u8, N>), Self::Error> {
//         let (ciphertext, shared_secret) = self.encapsulator.encapsulate(rng).unwrap();
//         let public_key = self.encapsulator.as_bytes();
//         let derived_shared_secret = self.kdf.derive_self_secret_others(&shared_secret, [ciphertext.as_slice(), public_key.as_slice()]);
//         Ok((ciphertext, derived_shared_secret))
//     }
// }
// impl<KEM,KDF,N> FromKey for KemWithKdfWithCiphertextAndPublicKeyEncapsulator<KEM,KDF,N> 
// where KEM: Capsulator,
//     KEM::Encapsulator: FromKey,
//     KDF: Default,
// {
//     type Key = <KEM::Encapsulator as FromKey>::Key;

//     fn from_key(key: Self::Key) -> Self {
//         Self{encapsulator: KEM::Encapsulator::from_key(key), kdf: KDF::default(), phantom: PhantomData}
//     }
// }
// impl<KEM,KDF,N> KemWithKdfWithCiphertextAndPublicKeyEncapsulator<KEM,KDF,N>
// where KEM: Capsulator,
//     KDF: Default
// {
//     pub fn from_encapsulator(encapsulator: KEM::Encapsulator) -> Self {
//         Self{encapsulator, kdf: KDF::default(), phantom: PhantomData}
//     }
// }
// impl<KEM,KDF,N> EncodedSizeUser2 for KemWithKdfWithCiphertextAndPublicKeyEncapsulator<KEM,KDF,N> 
// where KEM: Capsulator,
//     KEM::Encapsulator: EncodedSizeUser2,
//     KEM::Encapsulator: FromKey,
//     KDF: Default,
// {
//     type EncodedSize = <KEM::Encapsulator as EncodedSizeUser2>::EncodedSize;

//     fn from_bytes(enc: &crate::Encoded<Self>) -> Self {
//         Self{encapsulator: KEM::Encapsulator::from_bytes(enc), kdf: KDF::default(), phantom: PhantomData}
//     }

//     fn as_bytes(&self) -> crate::Encoded<Self> {
//         self.encapsulator.as_bytes()
//     }
// }


// pub struct KemWithKdfWithCiphertextAndPublicKeyDecapsulator<KEM,KDF,L>
// where KEM: Capsulator
// {
//     pub decapsulator: KEM::Decapsulator,
//     pub kdf: KDF,
//     phantom: PhantomData<L>
// }

// impl<KEM,KDF,N> FromKey for KemWithKdfWithCiphertextAndPublicKeyDecapsulator<KEM,KDF,N> 
// where KEM: Capsulator,
//     KEM::Decapsulator: FromKey,
//     KDF: Default,
// {
//     type Key = <KEM::Decapsulator as FromKey>::Key;

//     fn from_key(key: Self::Key) -> Self {
//         Self{decapsulator: KEM::Decapsulator::from_key(key), kdf: KDF::default(), phantom: PhantomData}
//     }
// }

// impl<KEM,KDF,N> KemWithKdfWithCiphertextAndPublicKeyDecapsulator<KEM,KDF,N>
// where KEM: Capsulator,
//     KDF: Default
// {
//     pub fn from_decapsulator_and_kdf(decapsulator: KEM::Decapsulator, kdf: KDF) -> Self {
//         Self{decapsulator, kdf, phantom: PhantomData}
//     }
// }
// impl<KEM,KDF,N> Decapsulate<GenericArray::<u8, KEM::CiphertextSize>, Array::<u8, N>> for KemWithKdfWithCiphertextAndPublicKeyDecapsulator<KEM,KDF,N>
// where KEM: Capsulator,
//     KEM::Decapsulator: GetEncapsulator,
//     <KEM::Decapsulator as GetEncapsulator>::Encapsulator: EncodedSizeUser2,
//     KDF: Kdf,
//     N: ArraySize,    
// {
//     type Error = ();
//     fn decapsulate(&self, encapsulated_key: &GenericArray::<u8, KEM::CiphertextSize>) -> Result<Array::<u8, N>, Self::Error> {
//         let shared_secret = self.decapsulator.decapsulate(encapsulated_key).unwrap();
//         let public_key = self.decapsulator.get_encapsulator().as_bytes();
//         Ok(self.kdf.derive_self_secret_others(&shared_secret, [encapsulated_key.as_slice(), public_key.as_slice()]))
//     }
// }


// impl<KEM,KDF,N> GetEncapsulator for KemWithKdfWithCiphertextAndPublicKeyDecapsulator<KEM,KDF,N>
// where KEM: Capsulator,
//     KEM::Decapsulator: GetEncapsulator<Encapsulator=KEM::Encapsulator>,
//     KDF: Default
// {
//     type Encapsulator = KemWithKdfWithCiphertextAndPublicKeyEncapsulator<KEM,KDF,N>;

//     fn get_encapsulator(&self) -> Self::Encapsulator {
//         Self::Encapsulator{ encapsulator: self.decapsulator.get_encapsulator(), kdf: KDF::default(), phantom: PhantomData }
//     }
// }

// impl<KEM,KDF,N> EncodedSizeUser2 for KemWithKdfWithCiphertextAndPublicKeyDecapsulator<KEM,KDF,N> 
// where KEM: Capsulator,
//     KEM::Decapsulator: EncodedSizeUser2,
//     KEM::Decapsulator: FromKey,
//     KDF: Default,
// {
//     type EncodedSize = <KEM::Decapsulator as EncodedSizeUser2>::EncodedSize;

//     fn from_bytes(enc: &crate::Encoded<Self>) -> Self {
//         Self{decapsulator: KEM::Decapsulator::from_bytes(enc), kdf: KDF::default(), phantom: PhantomData}
//     }

//     fn as_bytes(&self) -> crate::Encoded<Self> {
//         self.decapsulator.as_bytes()
//     }
// }
// impl<KEM,KDF,N> FromKeys for KemWithKdfWithCiphertextAndPublicKeyEncapsulator<KEM,KDF,N> 
// where KEM: Capsulator,
//     KEM::Encapsulator: FromKeys,
//     KDF: Default,
// {
//     type PrivateKey = <KEM::Encapsulator as FromKeys>::PrivateKey;
//     type PublicKey = <KEM::Encapsulator as FromKeys>::PublicKey;
    
//     fn from_keys ( pub_key: Self::PublicKey, priv_key: Self::PrivateKey ) -> Self {
//         Self{encapsulator: KEM::Encapsulator::from_keys(pub_key, priv_key), kdf: KDF::default(), phantom: PhantomData}
//     }
// }


//
// 
// 
// 



// pub struct KemWithKdfWithCiphertext<KEM,KDF,L> 
// (
//     PhantomData<KEM>,
//     PhantomData<KDF>,
//     PhantomData<L>
// );



// impl<KEM, KDF,L> Capsulator for KemWithKdfWithCiphertext<KEM,KDF,L>
// where KEM: Capsulator,
//     KDF: Kdf + Default,
//     L: ArraySize
// {
//     type Encapsulator = KemWithKdfWithCiphertextEncapsulator<KEM, KDF, L>;
//     type Decapsulator = KemWithKdfWithCiphertextDecapsulator<KEM, KDF, L>;
//     type SharedKeySize = L;
//     type CiphertextSize = KEM::CiphertextSize;

//     fn generate ( rng: &mut impl rand_core::CryptoRngCore ) -> (Self::Encapsulator, Self::Decapsulator) {
//         let (encapsulator, decapsulator) = KEM::generate(rng);
//         (Self::Encapsulator{encapsulator, kdf: KDF::default(), phantom:PhantomData}, Self::Decapsulator{decapsulator, kdf: KDF::default(), phantom: PhantomData})
//     }
// }


// pub struct KemWithKdfWithCiphertextEncapsulator<KEM,KDF,N>
// where KEM: Capsulator
// {
//     encapsulator: KEM::Encapsulator,
//     kdf: KDF,
//     phantom: PhantomData<N>
// }
// impl<KEM,KDF,N> Encapsulate<GenericArray::<u8, KEM::CiphertextSize>, Array::<u8, N>> for KemWithKdfWithCiphertextEncapsulator<KEM,KDF,N>
// where KEM: Capsulator,
//     KDF: Kdf,
//     N: ArraySize
// {
//     type Error = ();
    
//     fn encapsulate(&self, rng: &mut impl rand_core::CryptoRngCore) -> Result<(GenericArray::<u8, KEM::CiphertextSize>, Array::<u8, N>), Self::Error> {
//         let (ciphertext, shared_secret) = self.encapsulator.encapsulate(rng).unwrap();
//         let derived_shared_secret = self.kdf.derive_self_secret_other(&shared_secret, &ciphertext);
//         Ok((ciphertext, derived_shared_secret))
//     }
// }
// impl<KEM,KDF,N> FromKey for KemWithKdfWithCiphertextEncapsulator<KEM,KDF,N> 
// where KEM: Capsulator,
//     KEM::Encapsulator: FromKey,
//     KDF: Default,
// {
//     type Key = <KEM::Encapsulator as FromKey>::Key;

//     fn from_key(key: Self::Key) -> Self {
//         Self{encapsulator: KEM::Encapsulator::from_key(key), kdf: KDF::default(), phantom: PhantomData}
//     }
// }
// impl<KEM,KDF,N> KemWithKdfWithCiphertextEncapsulator<KEM,KDF,N>
// where KEM: Capsulator,
//     KDF: Default
// {
//     pub fn from_encapsulator(encapsulator: KEM::Encapsulator) -> Self {
//         Self{encapsulator, kdf: KDF::default(), phantom: PhantomData}
//     }
// }


// pub struct KemWithKdfWithCiphertextDecapsulator<KEM,KDF,L>
// where KEM: Capsulator
// {
//     decapsulator: KEM::Decapsulator,
//     kdf: KDF,
//     phantom: PhantomData<L>
// }

// impl<KEM,KDF,N> FromKey for KemWithKdfWithCiphertextDecapsulator<KEM,KDF,N> 
// where KEM: Capsulator,
//     KEM::Decapsulator: FromKey,
//     KDF: Default,
// {
//     type Key = <KEM::Decapsulator as FromKey>::Key;

//     fn from_key(key: Self::Key) -> Self {
//         Self{decapsulator: KEM::Decapsulator::from_key(key), kdf: KDF::default(), phantom: PhantomData}
//     }
// }

// impl<KEM,KDF,N> KemWithKdfWithCiphertextDecapsulator<KEM,KDF,N>
// where KEM: Capsulator,
//     KDF: Default
// {
//     pub fn from_decapsulator_and_kdf(decapsulator: KEM::Decapsulator, kdf: KDF) -> Self {
//         Self{decapsulator, kdf, phantom: PhantomData}
//     }
// }
// impl<KEM,KDF,N> Decapsulate<GenericArray::<u8, KEM::CiphertextSize>, Array::<u8, N>> for KemWithKdfWithCiphertextDecapsulator<KEM,KDF,N>
// where KEM: Capsulator,
//     KDF: Kdf,
//     N: ArraySize,    
// {
//     type Error = ();
//     fn decapsulate(&self, encapsulated_key: &GenericArray::<u8, KEM::CiphertextSize>) -> Result<Array::<u8, N>, Self::Error> {
//         let shared_secret = self.decapsulator.decapsulate(encapsulated_key).unwrap();
//         Ok(self.kdf.derive_self_secret_other(&shared_secret, encapsulated_key))
//     }
// }








// impl<KEM,COM,KDF,N> EncodeGenericArray<Self> for KemWithKdfDecapsulator<KEM,COM,KDF,N> 
// where KEM: Capsulator,
//     //KEM::Decapsulator: EncodedSizeUser2,
//     KEM::Decapsulator: EncodeGenericArray<KEM::Decapsulator>,
//     KDF: Default,
// {
//     type EncodedLen = <KEM::Decapsulator as EncodeGenericArray<KEM::Decapsulator>>::EncodedLen;
    
//     fn encode(source: &Self) -> GenericArray<u8, Self::EncodedLen> {
//         <KEM as Capsulator>::Decapsulator::encode(&source.decapsulator)
//     }
// }
