use std::marker::PhantomData;

use cipher::KeySizeUser;
use cipher::common::KeyExport;
use cipher::typenum::{IsLessOrEqual, Prod};
use digest::OutputSizeUser;
use kdfs::ansi_x9_63::X963Kdf;
//use kdfs::{KdfSlice};
use kdfs::{BoundedTypeNum, Kdf};
use kdfs::hybrid_array::{Array, ArraySize};
use kem::consts::{U16, U96};
use kem::{Ciphertext, Decapsulate, Decapsulator, Encapsulate, Generate, Kem, SharedKey, TryDecapsulate, TryKeyInit};
use kems::rfc5753::{DhSinglePassStdDhSha256KdfScheme, DhSinglePassStdDhSha384KdfScheme, DhSinglePassStdDhSha512KdfScheme};
use ml_kem::{MlKem768};
use p256::{NistP256, U32};
use p384::{NistP384, U48};
use p521::NistP521;

use sha2::Sha256;


/// 
/// Implementation of a two pass, implicit mutually authenticated key exchange with weak forward secrecy
/// 
/// Each side holds the public KEM belonging to the peer. The initiator generates a new encapsulated key and shared secret 1.
/// The encapsulated key is sent to the recipient 
/// 
/// The recipient recovers shared secret 1 from the message and generates shared secret 2 using the 
/// initiators public key. An overall shared secret is derived from the two shared secrets.
/// 
/// The initiator decrypts and recovers shared secret 2 and derives the overall shared secret.
/// 
struct TwoPassKem2S<K1, K2, L> (PhantomData<K1>, PhantomData<K2>, PhantomData<L>);

impl<K1, K2, L> TwoPassKem2S<K1,K2,L>
where K1: Kem, K2: Kem, L: ArraySize
{
    fn new_encapsulator(encapsulator: K1::EncapsulationKey, decapsulator: K2::DecapsulationKey) -> TwoPassKemEncapsulator2S<K1, K2, L>
    {
        TwoPassKemEncapsulator2S { encapsulator, decapsulator, phantom: PhantomData }
    }
    fn new_decapsulator(decapsulator: K1::DecapsulationKey, encapsulator: K2::EncapsulationKey
    
    
    ) -> TwoPassKemDecapsulator2S<K1, K2, L>
    {
        TwoPassKemDecapsulator2S { encapsulator, decapsulator, phantom: PhantomData }
    }
}

struct TwoPassKemEncapsulator2S <K1: Kem, K2: Kem, L: ArraySize> 
{
    encapsulator: K1::EncapsulationKey,
    decapsulator: K2::DecapsulationKey,
    phantom: PhantomData<L>
}


impl<K1: Kem, K2: Kem, L: ArraySize> TwoPassKemEncapsulator2S<K1,K2,L>
{
    fn encapsulate1(&self) -> Result<(Array<u8, K1::CiphertextSize>, TwoPassKemEncapsulator2S2<'_,K1,K2,L>),()>
    {
        let (ek, ss) = self.encapsulator.encapsulate();
        let decapsulator = TwoPassKemEncapsulator2S2{decapsulator: &self.decapsulator, intermediate_key: ss, phantom: PhantomData};
        Ok((ek, decapsulator))
    }
}

struct TwoPassKemEncapsulator2S2<'a, K1: Kem, K2: Kem, L: ArraySize>
{
    decapsulator: &'a K2::DecapsulationKey,
    intermediate_key: Array<u8, K1::SharedKeySize>,
    phantom: PhantomData<L>
}

impl<'a, K1: Kem, K2: Kem, L: ArraySize> TwoPassKemEncapsulator2S2<'a, K1,K2,L>
where L: ArraySize + IsLessOrEqual<Prod<<Sha256 as OutputSizeUser>::OutputSize, <u32 as BoundedTypeNum>::Max>, Output=hybrid_array::typenum::True>,
{
    

    fn decapsulate2(&self, encapsulated_key: &Array<u8, K2::CiphertextSize>) -> Result<Array<u8, L>, ()>
    {
        let ss = self.decapsulator.try_decapsulate(encapsulated_key).unwrap();
        let ss3 = X963Kdf::<Sha256>::derive_secrets_others([self.intermediate_key.as_slice(), &ss], None);
        Ok(ss3)
    }
}


struct TwoPassKemDecapsulator2S <K1: Kem, K2: Kem, L: ArraySize> 
{
    decapsulator: K1::DecapsulationKey,
    encapsulator: K2::EncapsulationKey,
    phantom: PhantomData<L>
}
impl<'a, K1: Kem, K2: Kem, L: ArraySize> TwoPassKemDecapsulator2S<K1,K2,L>
where L: ArraySize + IsLessOrEqual<Prod<<Sha256 as OutputSizeUser>::OutputSize, <u32 as BoundedTypeNum>::Max>, Output=hybrid_array::typenum::True>,
{
    fn recapsulate(&self, encapsulated_key: &Array<u8, K1::CiphertextSize>)
     -> Result<(Array<u8, L>, Array<u8, K2::CiphertextSize>), ()> 
        //<K2::Decapsulator as Decapsulate<GenericArray<u8, K2::CiphertextSize>, Array<u8, K2::SharedKeySize>>>::Error>
    {
        let ss = self.decapsulator.try_decapsulate(encapsulated_key).map_err(|_e|())?;
        let (ek2, ss2) = self.encapsulator.encapsulate();
        let ss3 = X963Kdf::<Sha256>::derive_secrets_others([ss.as_slice(), &ss2], None);
        Ok((ss3, ek2))
    }
}


#[test]
fn test_mkem_1() 
{
    type DhTwoPassStdDhSha256KdfScheme = TwoPassKem2S<DhSinglePassStdDhSha256KdfScheme<NistP256,U32>,DhSinglePassStdDhSha256KdfScheme<NistP256,U32>, U16>;

    let (decapsulator1, encapsulator1) = DhSinglePassStdDhSha256KdfScheme::<NistP256,U32>::generate_keypair();
    let (decapsulator2, encapsulator2 ) = DhSinglePassStdDhSha256KdfScheme::<NistP256,U32>::generate_keypair();

    let u = DhTwoPassStdDhSha256KdfScheme::new_encapsulator(encapsulator1, decapsulator2);
    let v = DhTwoPassStdDhSha256KdfScheme::new_decapsulator(decapsulator1, encapsulator2);

    let (ek_u, u_decap) = u.encapsulate1().unwrap();
    
    let (ss_u, ek_v) = v.recapsulate(&ek_u).unwrap();
    let ss_v = u_decap.decapsulate2(&ek_v).unwrap();

    assert_eq!( ss_u, ss_v);
}

#[test]
fn test_mkem_2() 
{
    type DhTwoPassStdDhSha256KdfScheme = TwoPassKem2S<DhSinglePassStdDhSha256KdfScheme<NistP256,U32>,DhSinglePassStdDhSha384KdfScheme<NistP384,U48>, U16>;

    let (decapsulator_u, encapsulator_u ) = DhSinglePassStdDhSha256KdfScheme::<NistP256,U32>::generate_keypair();
    let (decapsulator_v, encapsulator_v ) = DhSinglePassStdDhSha384KdfScheme::<NistP384,U48>::generate_keypair();

    let u = DhTwoPassStdDhSha256KdfScheme::new_encapsulator(encapsulator_u, decapsulator_v );
    let v = DhTwoPassStdDhSha256KdfScheme::new_decapsulator(decapsulator_u, encapsulator_v);

    let (ek_u, decap_u) = u.encapsulate1().unwrap();
    let (ss_u, ek_v) = v.recapsulate(&ek_u).unwrap();
    let ss_v = decap_u.decapsulate2(&ek_v).unwrap();

    assert_eq!( ss_u, ss_v);
}

///////////////////////
/// 
/// Implementation of a two pass, implicit mutually authenticated key exchange with forward secrecy
/// 
/// Each side holds the public KEM belonging to the peer. The initiator generates a new ephemeral key pair
/// and sends the public key to the recipient. The initiator also uses the recipient static public key to encapsulate
/// shared secret 1.
/// 
/// The recipient recovers shared secret 1 from the message and generates shared secret 2 and 3 using the 
/// initiators public key and ephemeral public key. An overall shared secret is derived from the three shared secrets.
/// 
/// The initiator decrypts and recovers shared secret 2 and 3 and derives the overall shared secret.
/// 
struct TwoPassKem2S1E<K1, K2, K3,L> (PhantomData<K1>, PhantomData<K2>, PhantomData<K3>, PhantomData<L>);

impl<K1, K2, K3, L> TwoPassKem2S1E<K1,K2,K3,L>
where K1: Kem, K2: Kem, K3: Kem, L: ArraySize
{
    fn new_encapsulator_u(encapsulator: K1::EncapsulationKey, decapsulator: K2::DecapsulationKey) -> TwoPassKemEncapsulator2S1E<K1, K2, K3, L>
    {
        TwoPassKemEncapsulator2S1E { encapsulator, decapsulator, phantom: PhantomData, phantom2: PhantomData }
    }
    fn new_decapsulator_v(self_private: K1::DecapsulationKey, peer_public: K2::EncapsulationKey) -> TwoPassKemDecapsulator2S1E<K1, K2, K3, L>
    {
        TwoPassKemDecapsulator2S1E { self_private, peer_public, phantom: PhantomData, phantom2: PhantomData }
    }
}

struct TwoPassKemEncapsulator2S1E <K1: Kem, K2: Kem, K3: Kem, L: ArraySize> 
{
    encapsulator: K1::EncapsulationKey,
    decapsulator: K2::DecapsulationKey,
    phantom: PhantomData<L>,
    phantom2: PhantomData<K3>
}



impl<K1: Kem, K2: Kem, K3: Kem, L: ArraySize> TwoPassKemEncapsulator2S1E<K1,K2,K3,L>
where K3::EncapsulationKey: KeyExport, //EncodedSizeUser2 
{
    //fn encapsulate(&self, rng: &mut impl CryptoRngCore) -> Result<(EK, SS), Self::Error>;
    //fn encapsulate(&self, rng: &mut impl CryptoRngCore) -> Result<(GenericArray<u8, K1::CiphertextSize>, MutualKemDecapsulator<'_,K1,K2,L>),()>
    fn encapsulate1(&self) -> Result<(Array<u8, K1::CiphertextSize>, 
        Array<u8, <<K3 as Kem>::EncapsulationKey as KeySizeUser>::KeySize>,
        TwoPassKemEncapsulator2S1E2<'_,K1,K2,K3,L>),
        ()>
    {
        let (ek, ss) = self.encapsulator.encapsulate();
        let (ephem_decap, ephem_encap ) = K3::generate_keypair();
        let ephem_encap_bytes: Array<u8, <<K3 as Kem>::EncapsulationKey as KeySizeUser>::KeySize> = ephem_encap.to_bytes();
        let decapsulator = TwoPassKemEncapsulator2S1E2{decapsulator: &self.decapsulator, ss_uv: ss, ephem_decap, phantom: PhantomData};
        Ok((ek, ephem_encap_bytes, decapsulator))
    }
}

struct TwoPassKemEncapsulator2S1E2<'a, K1: Kem, K2: Kem, K3: Kem, L: ArraySize>
{
    decapsulator: &'a K2::DecapsulationKey,
    ss_uv: Array<u8, K1::SharedKeySize>,
    phantom: PhantomData<L>,
    ephem_decap: K3::DecapsulationKey,
}

impl<'a, K1: Kem, K2: Kem, K3: Kem, L: ArraySize> TwoPassKemEncapsulator2S1E2<'a, K1,K2,K3,L>
where L: ArraySize + IsLessOrEqual<Prod<<Sha256 as OutputSizeUser>::OutputSize, <u32 as BoundedTypeNum>::Max>, Output=hybrid_array::typenum::True>,
{
    fn encapsulate2(&self, encapsulated_key: &Array<u8, K2::CiphertextSize>, 
        encapsulated_ephem_key: &Array<u8, K3::CiphertextSize>) -> Result<Array<u8, L>, 
        ()>
    {
        let ss_vu = self.decapsulator.try_decapsulate(encapsulated_key).unwrap();
        let ss_ephem = self.ephem_decap.try_decapsulate(encapsulated_ephem_key).unwrap();

        let ss = kdfs::ansi_x9_63::X963Kdf::<sha2::Sha256>::derive_secrets_others([self.ss_uv.as_slice(), &ss_vu, &ss_ephem], None);
        Ok(ss)
    }
}

struct TwoPassKemDecapsulator2S1E <K1: Kem, K2: Kem, K3: Kem, L: ArraySize> 
{
    peer_public: K2::EncapsulationKey,
    self_private: K1::DecapsulationKey,
    phantom: PhantomData<L>,
    phantom2: PhantomData<K3>
}

impl<K1: Kem, K2: Kem, K3: Kem, L: ArraySize> TwoPassKemDecapsulator2S1E<K1,K2,K3,L>
where K3::EncapsulationKey: TryKeyInit,
    L: ArraySize + IsLessOrEqual<Prod<<Sha256 as OutputSizeUser>::OutputSize, <u32 as BoundedTypeNum>::Max>, Output=hybrid_array::typenum::True>,
{
    fn decapsulate(&self, 
        encapsulated_key: &Array<u8, K1::CiphertextSize>, 
        encapsulated_ephem_key: &Array<u8, <K3::EncapsulationKey as KeySizeUser>::KeySize>) 
        -> Result<(Array<u8, L>, 
            Array<u8, K2::CiphertextSize>,
            Array<u8, K3::CiphertextSize>),
            ()>
    {
        let ss_uv = self.self_private.try_decapsulate(encapsulated_key).map_err(|_|())?;
        //let ephem_ss = self.ephem_decap.decapsulate(encapsulated_ephem_key).unwrap();
        let ephem_encapsulator = <K3::EncapsulationKey as TryKeyInit>::new(encapsulated_ephem_key).unwrap();
        let (ek_ephem, ss_ephem) = ephem_encapsulator.encapsulate();

        let (ek_vu, ss_vu) = self.peer_public.encapsulate();

        println! ( "ss2={:02X?}", ss_uv);
        
        let ss3 = kdfs::ansi_x9_63::X963Kdf::<sha2::Sha256>::derive_secrets_others([ss_uv.as_slice(), &ss_vu, ss_ephem.as_slice()], None);
        Ok((ss3, ek_vu, ek_ephem))
    }
}

#[test]
fn test_mkem_12() 
{
    type DhTwoPassStdDhSha256KdfScheme = TwoPassKem2S1E<DhSinglePassStdDhSha256KdfScheme<NistP256,U32>,DhSinglePassStdDhSha256KdfScheme<NistP256,U32>,DhSinglePassStdDhSha256KdfScheme<NistP256,U32>, U16>;

    let (decapsulator1, encapsulator1 ) = DhSinglePassStdDhSha256KdfScheme::<NistP256,U32>::generate_keypair();
    let (decapsulator2, encapsulator2 ) = DhSinglePassStdDhSha256KdfScheme::<NistP256,U32>::generate_keypair();

    //let mut u = MutualKem2::<DhSinglePassStdDhSha256KdfScheme::<NistP256,U32>, DhSinglePassStdDhSha256KdfScheme::<NistP256,U32>, U16>{encapsulator: encapsulator1, decapsulator: decapsulator2, intermediate_key: None, phantom: PhantomData};
    let u = DhTwoPassStdDhSha256KdfScheme::new_encapsulator_u(encapsulator1, decapsulator2 );
    //let mut v = MutualKem2::<DhSinglePassStdDhSha256KdfScheme::<NistP256,U32>, DhSinglePassStdDhSha256KdfScheme::<NistP256,U32>, U16>{encapsulator: encapsulator2, decapsulator: decapsulator1, intermediate_key: None, phantom: PhantomData};
    let v = DhTwoPassStdDhSha256KdfScheme::new_decapsulator_v(decapsulator1, encapsulator2);

    let (ek_u, pk_e, u_decap) = u.encapsulate1().unwrap();

    let (ss_v, ek_v, ek_e) = v.decapsulate(&ek_u, &pk_e).unwrap();

    // let ss_u = u.decapsulate(&ek_v, false);
    // let ss_v = v.decapsulate(&ek_u, true);
    let ss_u = u_decap.encapsulate2(&ek_v, &ek_e).unwrap();
    
    println! ( "ss_u={:02X?}", ss_u);
    println! ( "ss_v={:02X?}", ss_v);
    assert_eq!( ss_u, ss_v);
}
#[cfg(all(feature="rustcrypto-sha2", feature="rustcrypto-p256", feature="rustcrypto-p384", feature="rustcrypto-p521"))]
#[test]
fn test_mkem_22() 
{
    use kem::consts::U64;
use p384::U48;

    type DhTwoPassStdDhSha256KdfScheme = TwoPassKem2S1E<DhSinglePassStdDhSha256KdfScheme<NistP256,U32>,DhSinglePassStdDhSha384KdfScheme<NistP384,U48>,DhSinglePassStdDhSha512KdfScheme<NistP521,U64>, U16>;

    let (decapsulator_u, encapsulator_u ) = DhSinglePassStdDhSha384KdfScheme::<NistP384,U48>::generate_keypair();
    let (decapsulator_v, encapsulator_v ) = DhSinglePassStdDhSha256KdfScheme::<NistP256,U32>::generate_keypair();

    // let u = MutualKemEncapsulator::<DhSinglePassStdDhSha256KdfScheme::<NistP256,U32>, DhSinglePassStdDhSha384KdfScheme::<NistP384,U48>, U16>{encapsulator: encapsulator1, decapsulator: decapsulator2, phantom: PhantomData};
    // let v = MutualKemEncapsulator::<DhSinglePassStdDhSha384KdfScheme::<NistP384,U48>, DhSinglePassStdDhSha256KdfScheme::<NistP256,U32>, U16>{encapsulator: encapsulator2, decapsulator: decapsulator1, phantom: PhantomData};
    let u = DhTwoPassStdDhSha256KdfScheme::new_encapsulator_u(encapsulator_v, decapsulator_u );
    let v = DhTwoPassStdDhSha256KdfScheme::new_decapsulator_v(decapsulator_v, encapsulator_u );

    let (ek_u, pk_u, encap_u) = u.encapsulate1().unwrap();
    
    let (ss_u, ek_v, ek_e) = v.decapsulate(&ek_u, &pk_u).unwrap();
    
    let ss_v = encap_u.encapsulate2(&ek_v, &ek_e).unwrap();

    println! ( "ss_u={:02X?}", ss_u);
    println! ( "ss_v={:02X?}", ss_v);
    assert_eq!( ss_u, ss_v);
}

#[derive(PartialEq, PartialOrd, Ord, Eq, Debug, Default, Copy, Clone)]
struct ClassicMcElieceWrapper();

//impl<'a> Kem for ClassicMcElieceWrapper<'a>
impl Kem for ClassicMcElieceWrapper
{
    type DecapsulationKey = ClassicMcElieceDecapsulationKey;
    type EncapsulationKey = ClassicMcElieceEncapsulationKey;
    type SharedKeySize = U32;
    type CiphertextSize = U96;
}

use classic_mceliece_rust::{encapsulate_boxed, decapsulate_boxed};


struct ClassicMcElieceDecapsulationKey {secret: classic_mceliece_rust::SecretKey<'static>, public: ClassicMcElieceEncapsulationKey}

impl Generate for ClassicMcElieceDecapsulationKey
{
    fn try_generate_from_rng<R: rand::TryCryptoRng + ?Sized>(rng: &mut R) -> Result<Self, R::Error> {
        // Seed a deterministic CSPRNG
        let mut rng = <rand_chacha::ChaCha20Rng as rand_chacha::rand_core::SeedableRng>::from_seed([0x11u8; 32]);
        let (public_key, secret_key) = classic_mceliece_rust::keypair_boxed(&mut rng);
        Ok(Self { secret: secret_key, public: ClassicMcElieceEncapsulationKey(public_key)})
    }
}
impl<'a> Decapsulator for ClassicMcElieceDecapsulationKey
{
    type Kem = ClassicMcElieceWrapper;
    
    fn encapsulation_key(&self) -> &kem::EncapsulationKey<Self::Kem> {
        &self.public
    }

}

impl Decapsulate for ClassicMcElieceDecapsulationKey
{
    fn decapsulate(&self, ct: &kem::Ciphertext<Self::Kem>) -> kem::SharedKey<Self::Kem> {
        //let scheme = KemScheme::ClassicMcEliece348864;
        let ct2 = classic_mceliece_rust::Ciphertext::from(ct.0);
        let shared_secret = decapsulate_boxed(&ct2, &self.secret);
        shared_secret.as_array().as_slice().try_into().unwrap()
    }
}

#[derive(Debug)]
struct ClassicMcElieceEncapsulationKey (classic_mceliece_rust::PublicKey<'static>);
impl Encapsulate for ClassicMcElieceEncapsulationKey
{
    type Kem = ClassicMcElieceWrapper;

    fn encapsulate_with_rng<R>(&self, rng: &mut R) -> (Ciphertext<Self::Kem>, SharedKey<Self::Kem>)
    where
        R: rand::prelude::CryptoRng + ?Sized 
    {
        let mut rng = rand8::thread_rng();
        let (ciphertext, shared_secret) = encapsulate_boxed(&self.0, &mut rng);
        (ciphertext.as_array().as_slice().try_into().unwrap(), shared_secret.as_array().as_slice().try_into().unwrap())
        
    }
}
impl KeySizeUser for ClassicMcElieceEncapsulationKey
{
    type KeySize = U32;
}
impl KeyExport for ClassicMcElieceEncapsulationKey
{
    fn to_bytes(&self) -> kem::Key<Self> {
        todo!()
    }
}
impl TryKeyInit for ClassicMcElieceEncapsulationKey
{
    fn new(_key: &kem::Key<Self>) -> Result<Self, kem::InvalidKey> {
        todo!()
    }
}
impl Eq for ClassicMcElieceEncapsulationKey
{}
impl PartialEq for ClassicMcElieceEncapsulationKey
{
    fn eq(&self, _other: &Self) -> bool {
        todo!()
    }
}
impl Ord for ClassicMcElieceEncapsulationKey
{
    fn cmp(&self, _other: &Self) -> std::cmp::Ordering {
        todo!()
    }
}
impl PartialOrd for ClassicMcElieceEncapsulationKey
{
    fn partial_cmp(&self, _other: &Self) -> Option<std::cmp::Ordering> {
        todo!()
    }
}
impl Clone for ClassicMcElieceEncapsulationKey
{
    fn clone(&self) -> Self {
        let b = Box::new(self.0.as_array().clone());
        ClassicMcElieceEncapsulationKey(b.into())
    }
}



#[test]
fn test_mkem_23()
{
    //type DhTwoPassStdDhSha256KdfScheme = TwoPassKem2S1E<MlKem1024,DhSinglePassStdDhSha384KdfScheme<NistP384,U48>,DhSinglePassStdDhSha512KdfScheme<NistP521,U64>, U16>;
    type TwoPassMlKemCMEEcdh = TwoPassKem2S1E<ClassicMcElieceWrapper,MlKem768,DhSinglePassStdDhSha384KdfScheme<NistP384,p384::U48>, U16>;

    //let (decapsulator_u, encapsulator_u ) = DhSinglePassStdDhSha384KdfScheme::<NistP384,U48>::generate_keypair();
    let (decapsulator_v, encapsulator_v) = ClassicMcElieceWrapper::generate_keypair();
    let (decapsulator_u, encapsulator_u ) = <MlKem768 as kem::FromSeed>::from_seed(&[0x12;64].into());

    let u = TwoPassMlKemCMEEcdh::new_encapsulator_u(encapsulator_v, decapsulator_u );
    let v = TwoPassMlKemCMEEcdh::new_decapsulator_v(decapsulator_v, encapsulator_u );

    let (ek_u, pk_u, encap_u) = u.encapsulate1().unwrap();

    println! ( "a->b ek_u=({}){:02X?}...", ek_u.len(), &ek_u[..10]);
    println! ( "a->b pk_u=({}){:02X?}...", pk_u.len(), &pk_u[..10]);
    
    let (ss_u, ek_v, ek_e) = v.decapsulate(&ek_u, &pk_u).unwrap();
    println! ( "ss_u={:02X?}", ss_u);
    println! ( "b->a ek_v=({}){:02X?}...", ek_v.len(), &ek_v[..10]);
    println! ( "b->a ek_e=({}){:02X?}...", ek_e.len(), &ek_e[..10]);
        
    let ss_v = encap_u.encapsulate2(&ek_v, &ek_e).unwrap();
    println! ( "ss_v={:02X?}", ss_v);
    assert_eq!( ss_u, ss_v);
}


/// 
/// Implementation of a two pass, initiator authenticated key exchange with forward secrecy
/// THe initiator generates an ephemeral key pair and sends the public key to the recipient
/// THe recipient uses its static initial public key and ephemeral public key to generate shared secret 1 and 2
/// THe two encapsulated keys are returned to the intiator and the recipient derives a single shared secret from secrest 1 and 2
/// 
/// The initiator decrypts and recovers shared secret 1 and 2 and derives the overall shared secret.
/// 
struct TwoPassKem1S1E<K1, K2, L> (PhantomData<K1>, PhantomData<K2>, PhantomData<L>);

impl<K1, K2, L> TwoPassKem1S1E<K1,K2,L>
where K1: Kem, K2: Kem, L: ArraySize
{
    fn new_encapsulator(decapsulator: K1::DecapsulationKey) -> TwoPassKemEncapsulator1S1E<K1, K2, L>
    {
        TwoPassKemEncapsulator1S1E { decapsulator, phantom: PhantomData, phantom2: PhantomData }
    }
    fn new_decapsulator(encapsulator: K1::EncapsulationKey) -> TwoPassKemDecapsulator1S1E<K1, K2, L>
    {
        TwoPassKemDecapsulator1S1E { encapsulator, phantom: PhantomData, phantom2: PhantomData }
    }
}

struct TwoPassKemEncapsulator1S1E <K1: Kem, K2: Kem, L: ArraySize> 
{
    //encapsulator: K1::Encapsulator,
    decapsulator: K1::DecapsulationKey,
    phantom: PhantomData<L>,
    phantom2: PhantomData<K2>,
}


impl<K1: Kem, K2: Kem, L: ArraySize> TwoPassKemEncapsulator1S1E<K1,K2,L>
where K2::EncapsulationKey: KeySizeUser + KeyExport
{
    fn encapsulate1(&'_ self)
        -> Result<(Array<u8, <<K2 as Kem>::EncapsulationKey as KeySizeUser>::KeySize>,
                   TwoPassKemEncapsulator1S1E2<'_, K1,K2,L>),
                ()>
    {
        //let (ek, ss) = self.encapsulator.encapsulate(rng)?;
        let (ephem_decapsulator,ephem_encapsulator) = K2::generate_keypair();
        //let decapsulator = TwoPassKemENcapsulator2S2{decapsulator: &self.decapsulator, intermediate_key: ss, phantom: PhantomData};
        let encapsulator_as_bytes = ephem_encapsulator.to_bytes();

        Ok((encapsulator_as_bytes, TwoPassKemEncapsulator1S1E2{decapsulator: &self.decapsulator, ephem_decapsulator, phantom: PhantomData}))
    }
}

struct TwoPassKemEncapsulator1S1E2<'a, K1: Kem, K2: Kem, L: ArraySize>
{
    decapsulator: &'a K1::DecapsulationKey,
    ephem_decapsulator: K2::DecapsulationKey,
    phantom: PhantomData<L>
}


impl<'a, K1: Kem, K2: Kem, L: ArraySize> TwoPassKemEncapsulator1S1E2<'a, K1,K2,L>
where L: ArraySize + IsLessOrEqual<Prod<<Sha256 as OutputSizeUser>::OutputSize, <u32 as BoundedTypeNum>::Max>, Output=hybrid_array::typenum::True>,
{
    fn decapsulate2(&self, encapsulated_key_static: &Array<u8, K1::CiphertextSize>, encapsulated_key_ephem: &Array<u8, K2::CiphertextSize>) -> Result<Array<u8, L>, 
         ()>
    //fn encapsulate2(&self, ephem_public_key: &GenericArray<u8, <<K2 as Capsulator>::Encapsulator as EncodedSizeUser2>::EncodedSize>) -> Result<Array<u8, L>, 
    {
        let ss1 = self.decapsulator.try_decapsulate(encapsulated_key_static).unwrap();
        let ss2 = self.ephem_decapsulator.try_decapsulate(encapsulated_key_ephem).unwrap();
        let ss3 = X963Kdf::<Sha256>::derive_secrets_others([ss1.as_slice(), &ss2], None);
        Ok(ss3)
    }
}

struct TwoPassKemDecapsulator1S1E <K1: Kem, K2: Kem, L: ArraySize> 
{
    encapsulator: K1::EncapsulationKey,
    phantom: PhantomData<L>,
    phantom2: PhantomData<K2>,
}

impl<'a, K1: Kem, K2: Kem, L: ArraySize> TwoPassKemDecapsulator1S1E<K1,K2,L>
where K2::EncapsulationKey: TryKeyInit,
    L: ArraySize + IsLessOrEqual<Prod<<Sha256 as OutputSizeUser>::OutputSize, <u32 as BoundedTypeNum>::Max>, Output=hybrid_array::typenum::True>,
{
    fn recapsulate(&self, ephem_public_key: &Array<u8, <<K2 as Kem>::EncapsulationKey as KeySizeUser>::KeySize>)
     -> Result<(Array<u8, L>, Array<u8, K1::CiphertextSize>, Array<u8, K2::CiphertextSize>), ()> 
        //<K2::Decapsulator as Decapsulate<GenericArray<u8, K2::CiphertextSize>, Array<u8, K2::SharedKeySize>>>::Error>
    {
        let (ek1, ss1) = self.encapsulator.encapsulate();
        let ephem_public = <K2::EncapsulationKey as TryKeyInit>::new(ephem_public_key).unwrap();
        let (ek2, ss2) = ephem_public.encapsulate();
        
        let ss3 = X963Kdf::<Sha256>::derive_secrets_others([ss1.as_slice(), &ss2], None);
        Ok((ss3, ek1, ek2))
    }
}

#[cfg(all(feature="rustcrypto-sha2", feature="rustcrypto-p256", feature="rustcrypto-p384"))]
#[test]
fn test_mkem_1s1e_1() 
{
    type DhTwoPassStdDhSha256KdfScheme = TwoPassKem1S1E<DhSinglePassStdDhSha256KdfScheme<NistP256,U32>,DhSinglePassStdDhSha256KdfScheme<NistP256,U32>, U16>;

    let (decapsulator1, encapsulator1 ) = DhSinglePassStdDhSha256KdfScheme::<NistP256,U32>::generate_keypair();
    //let (encapsulator2, decapsulator2) = DhSinglePassStdDhSha256KdfScheme::<NistP256,U32>::generate(&mut OsRng);

    //let mut u = MutualKem2::<DhSinglePassStdDhSha256KdfScheme::<NistP256,U32>, DhSinglePassStdDhSha256KdfScheme::<NistP256,U32>, U16>{encapsulator: encapsulator1, decapsulator: decapsulator2, intermediate_key: None, phantom: PhantomData};
    let u = DhTwoPassStdDhSha256KdfScheme::new_encapsulator(decapsulator1);
    //let mut v = MutualKem2::<DhSinglePassStdDhSha256KdfScheme::<NistP256,U32>, DhSinglePassStdDhSha256KdfScheme::<NistP256,U32>, U16>{encapsulator: encapsulator2, decapsulator: decapsulator1, intermediate_key: None, phantom: PhantomData};
    let v = DhTwoPassStdDhSha256KdfScheme::new_decapsulator(encapsulator1);

    let (pk_ephem, u_decap) = u.encapsulate1().unwrap();
    //let (ek_v, v_decap) = v.encapsulate1(&mut OsRng).unwrap();

    // let ss_u = u.decapsulate(&ek_v, false);
    // let ss_v = v.decapsulate(&ek_u, true);
    let (ss_u, ek_v, ek_ephem) = v.recapsulate(&pk_ephem).unwrap();
    let ss_v = u_decap.decapsulate2(&ek_v, &ek_ephem).unwrap();

    println! ( "ss_u={:02X?}", ss_u);
    println! ( "ss_v={:02X?}", ss_v);
    assert_eq!( ss_u, ss_v);
}

#[test]
fn test_mkem_1s1e_2() 
{
    type DhTwoPassStdDhSha256KdfScheme = TwoPassKem1S1E<DhSinglePassStdDhSha256KdfScheme<NistP256,U32>,DhSinglePassStdDhSha384KdfScheme<NistP384,U48>, U16>;

    let (decapsulator_u, encapsulator_u ) = DhSinglePassStdDhSha256KdfScheme::<NistP256,U32>::generate_keypair();
    //let (encapsulator_v, decapsulator_v) = DhSinglePassStdDhSha384KdfScheme::<NistP384,U48>::generate(&mut OsRng);

    // let u = MutualKemEncapsulator::<DhSinglePassStdDhSha256KdfScheme::<NistP256,U32>, DhSinglePassStdDhSha384KdfScheme::<NistP384,U48>, U16>{encapsulator: encapsulator1, decapsulator: decapsulator2, phantom: PhantomData};
    // let v = MutualKemEncapsulator::<DhSinglePassStdDhSha384KdfScheme::<NistP384,U48>, DhSinglePassStdDhSha256KdfScheme::<NistP256,U32>, U16>{encapsulator: encapsulator2, decapsulator: decapsulator1, phantom: PhantomData};
    let u = DhTwoPassStdDhSha256KdfScheme::new_encapsulator(decapsulator_u );
    let v = DhTwoPassStdDhSha256KdfScheme::new_decapsulator(encapsulator_u);

    let (ek_u, decap_u) = u.encapsulate1().unwrap();

    let (ss_u, ek_v, ek_ephem) = v.recapsulate(&ek_u).unwrap();
    let ss_v = decap_u.decapsulate2(&ek_v, &ek_ephem).unwrap();

    assert_eq!( ss_u, ss_v);
}
