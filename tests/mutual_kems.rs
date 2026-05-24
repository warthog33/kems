use std::marker::PhantomData;

//use cipher::KeySizeUser;
use kdfs::{Kdf};
use kdfs::hybrid_array::{Array, ArraySize};
use kems::{Capsulator, CryptoRngCore, EncodedSizeUser2, Decapsulate, Encapsulate};
#[cfg(feature="rustcrypto-sha2")]
use kems::rfc5753::{DhSinglePassStdDhSha256KdfScheme, DhSinglePassStdDhSha384KdfScheme, DhSinglePassStdDhSha512KdfScheme};
use kems::generic_array::{ GenericArray, typenum::{U16, U32, U48, U64}};
#[cfg(all(feature="rustcrypto-p256"))]
use p256::NistP256;
#[cfg(all(feature="rustcrypto-p384"))]
use p384::NistP384;
#[cfg(all(feature="rustcrypto-p521"))]
use p521::NistP521;

use rand_core::OsRng;


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
where K1: Capsulator, K2: Capsulator, L: ArraySize
{
    fn new_encapsulator(encapsulator: K1::Encapsulator, decapsulator: K2::Decapsulator) -> TwoPassKemEncapsulator2S<K1, K2, L>
    {
        TwoPassKemEncapsulator2S { encapsulator, decapsulator, phantom: PhantomData }
    }
    fn new_decapsulator(decapsulator: K1::Decapsulator, encapsulator: K2::Encapsulator) -> TwoPassKemDecapsulator2S<K1, K2, L>
    {
        TwoPassKemDecapsulator2S { encapsulator, decapsulator, phantom: PhantomData }
    }
}

struct TwoPassKemEncapsulator2S <K1: Capsulator, K2: Capsulator, L: ArraySize> 
{
    encapsulator: K1::Encapsulator,
    decapsulator: K2::Decapsulator,
    phantom: PhantomData<L>
}


impl<K1: Capsulator, K2: Capsulator, L: ArraySize> TwoPassKemEncapsulator2S<K1,K2,L>
{
    fn encapsulate1(&self, rng: &mut impl CryptoRngCore) -> Result<(GenericArray<u8, K1::CiphertextSize>, TwoPassKemENcapsulator2S2<'_,K1,K2,L>),
        <K1::Encapsulator as Encapsulate<GenericArray<u8, K1::CiphertextSize>, Array<u8, K1::SharedKeySize>>>::Error>
    {
        let (ek, ss) = self.encapsulator.encapsulate(rng)?;
        let decapsulator = TwoPassKemENcapsulator2S2{decapsulator: &self.decapsulator, intermediate_key: ss, phantom: PhantomData};
        Ok((ek, decapsulator))
    }
}

struct TwoPassKemENcapsulator2S2<'a, K1: Capsulator, K2: Capsulator, L: ArraySize>
{
    decapsulator: &'a K2::Decapsulator,
    intermediate_key: Array<u8, K1::SharedKeySize>,
    phantom: PhantomData<L>
}

#[cfg(feature="rustcrypto-sha2")]
impl<'a, K1: Capsulator, K2: Capsulator, L: ArraySize> TwoPassKemENcapsulator2S2<'a, K1,K2,L>
{
    fn encapsulate2(&self, encapsulated_key: &GenericArray<u8, K2::CiphertextSize>) -> Result<Array<u8, L>, 
        <K2::Decapsulator as Decapsulate<GenericArray<u8, K2::CiphertextSize>, Array<u8, K2::SharedKeySize>>>::Error>
    {
        let ss = self.decapsulator.decapsulate(encapsulated_key)?;
        let ss3 = kdfs::ansi_x9_63::X963Kdf::<sha2::Sha256>::derive_secrets_other([self.intermediate_key.as_slice(), &ss], &[]);
        Ok(ss3)
    }
}


struct TwoPassKemDecapsulator2S <K1: Capsulator, K2: Capsulator, L: ArraySize> 
{
    decapsulator: K1::Decapsulator,
    encapsulator: K2::Encapsulator,
    phantom: PhantomData<L>
}
#[cfg(feature="rustcrypto-sha2")]
impl<'a, K1: Capsulator, K2: Capsulator, L: ArraySize> TwoPassKemDecapsulator2S<K1,K2,L>
{
    fn decapsulate(&self, rng: &mut impl CryptoRngCore, encapsulated_key: &GenericArray<u8, K1::CiphertextSize>)
     -> Result<(Array<u8, L>, GenericArray<u8, K2::CiphertextSize>), ()> 
        //<K2::Decapsulator as Decapsulate<GenericArray<u8, K2::CiphertextSize>, Array<u8, K2::SharedKeySize>>>::Error>
    {
        let ss = self.decapsulator.decapsulate(encapsulated_key).map_err(|_e|())?;
        let (ek2, ss2) = self.encapsulator.encapsulate(rng).map_err(|_e|())?;
        let ss3 = kdfs::ansi_x9_63::X963Kdf::<sha2::Sha256>::derive_secrets_other([ss.as_slice(), &ss2], &[]);
        Ok((ss3, ek2))
    }
}


#[cfg(all(feature="rustcrypto-sha2", feature="rustcrypto-p256"))]
#[test]
fn test_mkem_1() 
{
    type DhTwoPassStdDhSha256KdfScheme = TwoPassKem2S<DhSinglePassStdDhSha256KdfScheme<NistP256,U32>,DhSinglePassStdDhSha256KdfScheme<NistP256,U32>, U16>;

    let (encapsulator1, decapsulator1) = DhSinglePassStdDhSha256KdfScheme::<NistP256,U32>::generate(&mut OsRng);
    let (encapsulator2, decapsulator2) = DhSinglePassStdDhSha256KdfScheme::<NistP256,U32>::generate(&mut OsRng);

    //let mut u = MutualKem2::<DhSinglePassStdDhSha256KdfScheme::<NistP256,U32>, DhSinglePassStdDhSha256KdfScheme::<NistP256,U32>, U16>{encapsulator: encapsulator1, decapsulator: decapsulator2, intermediate_key: None, phantom: PhantomData};
    let u = DhTwoPassStdDhSha256KdfScheme::new_encapsulator(encapsulator1, decapsulator2);
    //let mut v = MutualKem2::<DhSinglePassStdDhSha256KdfScheme::<NistP256,U32>, DhSinglePassStdDhSha256KdfScheme::<NistP256,U32>, U16>{encapsulator: encapsulator2, decapsulator: decapsulator1, intermediate_key: None, phantom: PhantomData};
    let v = DhTwoPassStdDhSha256KdfScheme::new_decapsulator(decapsulator1, encapsulator2);

    let (ek_u, u_decap) = u.encapsulate1(&mut OsRng).unwrap();
    //let (ek_v, v_decap) = v.encapsulate1(&mut OsRng).unwrap();

    // let ss_u = u.decapsulate(&ek_v, false);
    // let ss_v = v.decapsulate(&ek_u, true);
    let (ss_u, ek_v) = v.decapsulate(&mut OsRng, &ek_u).unwrap();
    let ss_v = u_decap.encapsulate2(&ek_v).unwrap();

    println! ( "ss_u={:02X?}", ss_u);
    println! ( "ss_v={:02X?}", ss_v);
    assert_eq!( ss_u, ss_v);
}

#[cfg(all(feature="rustcrypto-sha2", feature="rustcrypto-p256", feature="rustcrypto-p384"))]
#[test]
fn test_mkem_2() 
{
    type DhTwoPassStdDhSha256KdfScheme = TwoPassKem2S<DhSinglePassStdDhSha256KdfScheme<NistP256,U32>,DhSinglePassStdDhSha384KdfScheme<NistP384,U48>, U16>;

    let (encapsulator_u, decapsulator_u) = DhSinglePassStdDhSha256KdfScheme::<NistP256,U32>::generate(&mut OsRng);
    let (encapsulator_v, decapsulator_v) = DhSinglePassStdDhSha384KdfScheme::<NistP384,U48>::generate(&mut OsRng);

    // let u = MutualKemEncapsulator::<DhSinglePassStdDhSha256KdfScheme::<NistP256,U32>, DhSinglePassStdDhSha384KdfScheme::<NistP384,U48>, U16>{encapsulator: encapsulator1, decapsulator: decapsulator2, phantom: PhantomData};
    // let v = MutualKemEncapsulator::<DhSinglePassStdDhSha384KdfScheme::<NistP384,U48>, DhSinglePassStdDhSha256KdfScheme::<NistP256,U32>, U16>{encapsulator: encapsulator2, decapsulator: decapsulator1, phantom: PhantomData};
    let u = DhTwoPassStdDhSha256KdfScheme::new_encapsulator(encapsulator_u, decapsulator_v );
    let v = DhTwoPassStdDhSha256KdfScheme::new_decapsulator(decapsulator_u, encapsulator_v);

    let (ek_u, decap_u) = u.encapsulate1(&mut OsRng).unwrap();
    //let (ek_v, decap_v) = v.encapsulate1(&mut OsRng).unwrap();

    // let ss_u = u.decapsulate(&ek_v, false);
    // let ss_v = v.decapsulate(&ek_u, true);
    let (ss_u, ek_v) = v.decapsulate(&mut OsRng, &ek_u).unwrap();
    let ss_v = decap_u.encapsulate2(&ek_v).unwrap();

    println! ( "ss_u={:02X?}", ss_u);
    println! ( "ss_v={:02X?}", ss_v);
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
where K1: Capsulator, K2: Capsulator, K3: Capsulator, L: ArraySize
{
    fn new_encapsulator_u(encapsulator: K1::Encapsulator, decapsulator: K2::Decapsulator) -> TwoPassKemEncapsulator2S1E<K1, K2, K3, L>
    {
        TwoPassKemEncapsulator2S1E { encapsulator, decapsulator, phantom: PhantomData, phantom2: PhantomData }
    }
    fn new_decapsulator_v(self_private: K1::Decapsulator, peer_public: K2::Encapsulator) -> TwoPassKemDecapsulator2S1E<K1, K2, K3, L>
    {
        TwoPassKemDecapsulator2S1E { self_private, peer_public, phantom: PhantomData, phantom2: PhantomData }
    }
}

struct TwoPassKemEncapsulator2S1E <K1: Capsulator, K2: Capsulator, K3: Capsulator, L: ArraySize> 
{
    encapsulator: K1::Encapsulator,
    decapsulator: K2::Decapsulator,
    phantom: PhantomData<L>,
    phantom2: PhantomData<K3>
}



impl<K1: Capsulator, K2: Capsulator, K3: Capsulator, L: ArraySize> TwoPassKemEncapsulator2S1E<K1,K2,K3,L>
where K3::Encapsulator: EncodedSizeUser2 
{
    //fn encapsulate(&self, rng: &mut impl CryptoRngCore) -> Result<(EK, SS), Self::Error>;
    //fn encapsulate(&self, rng: &mut impl CryptoRngCore) -> Result<(GenericArray<u8, K1::CiphertextSize>, MutualKemDecapsulator<'_,K1,K2,L>),()>
    fn encapsulate1(&self, rng: &mut impl CryptoRngCore) -> Result<(GenericArray<u8, K1::CiphertextSize>, 
        GenericArray<u8, <<K3 as Capsulator>::Encapsulator as EncodedSizeUser2>::EncodedSize>,
        TwoPassKemEncapsulator2S1E2<'_,K1,K2,K3,L>),
        <K1::Encapsulator as Encapsulate<GenericArray<u8, K1::CiphertextSize>, Array<u8, K1::SharedKeySize>>>::Error>
    {
        let (ek, ss) = self.encapsulator.encapsulate(rng)?;
        let (ephem_encap, ephem_decap) = K3::generate(rng);
        let ephem_encap_bytes: GenericArray<u8, <<K3 as Capsulator>::Encapsulator as EncodedSizeUser2>::EncodedSize> = ephem_encap.as_bytes();
        let decapsulator = TwoPassKemEncapsulator2S1E2{decapsulator: &self.decapsulator, ss_uv: ss, ephem_decap, phantom: PhantomData};
        Ok((ek, ephem_encap_bytes, decapsulator))
    }
}

struct TwoPassKemEncapsulator2S1E2<'a, K1: Capsulator, K2: Capsulator, K3: Capsulator, L: ArraySize>
{
    decapsulator: &'a K2::Decapsulator,
    ss_uv: Array<u8, K1::SharedKeySize>,
    phantom: PhantomData<L>,
    ephem_decap: K3::Decapsulator,
}

#[cfg(feature="rustcrypto-sha2")]
impl<'a, K1: Capsulator, K2: Capsulator, K3: Capsulator, L: ArraySize> TwoPassKemEncapsulator2S1E2<'a, K1,K2,K3,L>
{
    fn encapsulate2(&self, encapsulated_key: &GenericArray<u8, K2::CiphertextSize>, 
        encapsulated_ephem_key: &GenericArray<u8, K3::CiphertextSize>) -> Result<Array<u8, L>, 
        <K2::Decapsulator as Decapsulate<GenericArray<u8, K2::CiphertextSize>, Array<u8, K2::SharedKeySize>>>::Error>
    {
        let ss_vu = self.decapsulator.decapsulate(encapsulated_key)?;
        let ss_ephem = self.ephem_decap.decapsulate(encapsulated_ephem_key).unwrap();

        let ss = kdfs::ansi_x9_63::X963Kdf::<sha2::Sha256>::derive_secrets_other([self.ss_uv.as_slice(), &ss_vu, &ss_ephem], &[]);
        Ok(ss)
    }
}

struct TwoPassKemDecapsulator2S1E <K1: Capsulator, K2: Capsulator, K3: Capsulator, L: ArraySize> 
{
    peer_public: K2::Encapsulator,
    self_private: K1::Decapsulator,
    phantom: PhantomData<L>,
    phantom2: PhantomData<K3>
}

#[cfg(feature="rustcrypto-sha2")]
impl<K1: Capsulator, K2: Capsulator, K3: Capsulator, L: ArraySize> TwoPassKemDecapsulator2S1E<K1,K2,K3,L>
where K3::Encapsulator: EncodedSizeUser2 
{
    fn decapsulate(&self, 
        rng: &mut impl CryptoRngCore,
        encapsulated_key: &GenericArray<u8, K1::CiphertextSize>, 
        encapsulated_ephem_key: &GenericArray<u8, <K3::Encapsulator as EncodedSizeUser2>::EncodedSize>) 
        -> Result<(Array<u8, L>, 
            GenericArray<u8, K2::CiphertextSize>,
            GenericArray<u8, K3::CiphertextSize>),
            <K1::Decapsulator as Decapsulate<GenericArray<u8, K1::CiphertextSize>, Array<u8, K1::SharedKeySize>>>::Error>
    {
        let ss_uv = self.self_private.decapsulate(encapsulated_key)?;
        //let ephem_ss = self.ephem_decap.decapsulate(encapsulated_ephem_key).unwrap();
        let ephem_encapsulator = K3::Encapsulator::from_bytes(encapsulated_ephem_key);
        let (ek_ephem, ss_ephem) = ephem_encapsulator.encapsulate(rng).unwrap();

        let (ek_vu, ss_vu) = self.peer_public.encapsulate(rng).unwrap();

        println! ( "ss2={:02X?}", ss_uv);
        
        let ss3 = kdfs::ansi_x9_63::X963Kdf::<sha2::Sha256>::derive_secrets_other([ss_uv.as_slice(), &ss_vu, ss_ephem.as_slice()], &[]);
        Ok((ss3, ek_vu, ek_ephem))
    }
}

#[cfg(all(feature="rustcrypto-sha2", feature="rustcrypto-p256"))]
#[test]
fn test_mkem_12() 
{
    type DhTwoPassStdDhSha256KdfScheme = TwoPassKem2S1E<DhSinglePassStdDhSha256KdfScheme<NistP256,U32>,DhSinglePassStdDhSha256KdfScheme<NistP256,U32>,DhSinglePassStdDhSha256KdfScheme<NistP256,U32>, U16>;

    let (encapsulator1, decapsulator1) = DhSinglePassStdDhSha256KdfScheme::<NistP256,U32>::generate(&mut OsRng);
    let (encapsulator2, decapsulator2) = DhSinglePassStdDhSha256KdfScheme::<NistP256,U32>::generate(&mut OsRng);

    //let mut u = MutualKem2::<DhSinglePassStdDhSha256KdfScheme::<NistP256,U32>, DhSinglePassStdDhSha256KdfScheme::<NistP256,U32>, U16>{encapsulator: encapsulator1, decapsulator: decapsulator2, intermediate_key: None, phantom: PhantomData};
    let u = DhTwoPassStdDhSha256KdfScheme::new_encapsulator_u(encapsulator1, decapsulator2 );
    //let mut v = MutualKem2::<DhSinglePassStdDhSha256KdfScheme::<NistP256,U32>, DhSinglePassStdDhSha256KdfScheme::<NistP256,U32>, U16>{encapsulator: encapsulator2, decapsulator: decapsulator1, intermediate_key: None, phantom: PhantomData};
    let v = DhTwoPassStdDhSha256KdfScheme::new_decapsulator_v(decapsulator1, encapsulator2);

    let (ek_u, pk_e, u_decap) = u.encapsulate1(&mut OsRng).unwrap();

    let (ss_v, ek_v, ek_e) = v.decapsulate(&mut OsRng, &ek_u, &pk_e).unwrap();

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
    type DhTwoPassStdDhSha256KdfScheme = TwoPassKem2S1E<DhSinglePassStdDhSha256KdfScheme<NistP256,U32>,DhSinglePassStdDhSha384KdfScheme<NistP384,U48>,DhSinglePassStdDhSha512KdfScheme<NistP521,U64>, U16>;

    let (encapsulator_u, decapsulator_u) = DhSinglePassStdDhSha384KdfScheme::<NistP384,U48>::generate(&mut OsRng);
    let (encapsulator_v, decapsulator_v) = DhSinglePassStdDhSha256KdfScheme::<NistP256,U32>::generate(&mut OsRng);

    // let u = MutualKemEncapsulator::<DhSinglePassStdDhSha256KdfScheme::<NistP256,U32>, DhSinglePassStdDhSha384KdfScheme::<NistP384,U48>, U16>{encapsulator: encapsulator1, decapsulator: decapsulator2, phantom: PhantomData};
    // let v = MutualKemEncapsulator::<DhSinglePassStdDhSha384KdfScheme::<NistP384,U48>, DhSinglePassStdDhSha256KdfScheme::<NistP256,U32>, U16>{encapsulator: encapsulator2, decapsulator: decapsulator1, phantom: PhantomData};
    let u = DhTwoPassStdDhSha256KdfScheme::new_encapsulator_u(encapsulator_v, decapsulator_u );
    let v = DhTwoPassStdDhSha256KdfScheme::new_decapsulator_v(decapsulator_v, encapsulator_u );

    let (ek_u, pk_u, encap_u) = u.encapsulate1(&mut OsRng).unwrap();
    
    let (ss_u, ek_v, ek_e) = v.decapsulate(&mut OsRng, &ek_u, &pk_u).unwrap();
    
    let ss_v = encap_u.encapsulate2(&ek_v, &ek_e).unwrap();

    println! ( "ss_u={:02X?}", ss_u);
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
where K1: Capsulator, K2: Capsulator, L: ArraySize
{
    fn new_encapsulator(decapsulator: K1::Decapsulator) -> TwoPassKemEncapsulator1S1E<K1, K2, L>
    {
        TwoPassKemEncapsulator1S1E { decapsulator, phantom: PhantomData, phantom2: PhantomData }
    }
    fn new_decapsulator(encapsulator: K1::Encapsulator) -> TwoPassKemDecapsulator1S1E<K1, K2, L>
    {
        TwoPassKemDecapsulator1S1E { encapsulator, phantom: PhantomData, phantom2: PhantomData }
    }
}

struct TwoPassKemEncapsulator1S1E <K1: Capsulator, K2: Capsulator, L: ArraySize> 
{
    //encapsulator: K1::Encapsulator,
    decapsulator: K1::Decapsulator,
    phantom: PhantomData<L>,
    phantom2: PhantomData<K2>,
}


impl<K1: Capsulator, K2: Capsulator, L: ArraySize> TwoPassKemEncapsulator1S1E<K1,K2,L>
where K2::Encapsulator: EncodedSizeUser2
{
    fn encapsulate1(&'_ self, rng: &mut impl CryptoRngCore)
        -> Result<(GenericArray<u8, <<K2 as Capsulator>::Encapsulator as EncodedSizeUser2>::EncodedSize>,
                   TwoPassKemEncapsulator1S1E2<'_, K1,K2,L>),
                ()>
    {
        //let (ek, ss) = self.encapsulator.encapsulate(rng)?;
        let (ephem_encapsulator, ephem_decapsulator) = K2::generate(rng);
        //let decapsulator = TwoPassKemENcapsulator2S2{decapsulator: &self.decapsulator, intermediate_key: ss, phantom: PhantomData};
        let encapsulator_as_bytes = ephem_encapsulator.as_bytes();

        Ok((encapsulator_as_bytes, TwoPassKemEncapsulator1S1E2{decapsulator: &self.decapsulator, ephem_decapsulator, phantom: PhantomData}))
    }
}

struct TwoPassKemEncapsulator1S1E2<'a, K1: Capsulator, K2: Capsulator, L: ArraySize>
{
    decapsulator: &'a K1::Decapsulator,
    ephem_decapsulator: K2::Decapsulator,
    phantom: PhantomData<L>
}

#[cfg(feature="rustcrypto-sha2")]
impl<'a, K1: Capsulator, K2: Capsulator, L: ArraySize> TwoPassKemEncapsulator1S1E2<'a, K1,K2,L>
{
    fn encapsulate2(&self, encapsulated_key_static: &GenericArray<u8, K1::CiphertextSize>, encapsulated_key_ephem: &GenericArray<u8, K2::CiphertextSize>) -> Result<Array<u8, L>, 
         <K2::Decapsulator as Decapsulate<GenericArray<u8, K2::CiphertextSize>, Array<u8, K2::SharedKeySize>>>::Error>
    //fn encapsulate2(&self, ephem_public_key: &GenericArray<u8, <<K2 as Capsulator>::Encapsulator as EncodedSizeUser2>::EncodedSize>) -> Result<Array<u8, L>, 
    {
        let ss1 = self.decapsulator.decapsulate(encapsulated_key_static).unwrap();
        let ss2 = self.ephem_decapsulator.decapsulate(encapsulated_key_ephem).unwrap();
        let ss3 = kdfs::ansi_x9_63::X963Kdf::<sha2::Sha256>::derive_secrets_other([ss1.as_slice(), &ss2], &[]);
        Ok(ss3)
    }
}

struct TwoPassKemDecapsulator1S1E <K1: Capsulator, K2: Capsulator, L: ArraySize> 
{
    encapsulator: K1::Encapsulator,
    phantom: PhantomData<L>,
    phantom2: PhantomData<K2>,
}
#[cfg(feature="rustcrypto-sha2")]
impl<'a, K1: Capsulator, K2: Capsulator, L: ArraySize> TwoPassKemDecapsulator1S1E<K1,K2,L>
where K2::Encapsulator: EncodedSizeUser2
{
    fn decapsulate(&self, rng: &mut impl CryptoRngCore, ephem_public_key: &GenericArray<u8, <<K2 as Capsulator>::Encapsulator as EncodedSizeUser2>::EncodedSize>)
     -> Result<(Array<u8, L>, GenericArray<u8, K1::CiphertextSize>, GenericArray<u8, K2::CiphertextSize>), ()> 
        //<K2::Decapsulator as Decapsulate<GenericArray<u8, K2::CiphertextSize>, Array<u8, K2::SharedKeySize>>>::Error>
    {
        let (ek1, ss1) = self.encapsulator.encapsulate(rng).map_err(|_e|())?;
        let ephem_public = K2::Encapsulator::from_bytes(ephem_public_key);
        let (ek2, ss2) = ephem_public.encapsulate(rng).unwrap();
        
        let ss3 = kdfs::ansi_x9_63::X963Kdf::<sha2::Sha256>::derive_secrets_other([ss1.as_slice(), &ss2], &[]);
        Ok((ss3, ek1, ek2))
    }
}

#[cfg(all(feature="rustcrypto-sha2", feature="rustcrypto-p256", feature="rustcrypto-p384"))]
#[test]
fn test_mkem_1s1e_1() 
{
    type DhTwoPassStdDhSha256KdfScheme = TwoPassKem1S1E<DhSinglePassStdDhSha256KdfScheme<NistP256,U32>,DhSinglePassStdDhSha256KdfScheme<NistP256,U32>, U16>;

    let (encapsulator1, decapsulator1) = DhSinglePassStdDhSha256KdfScheme::<NistP256,U32>::generate(&mut OsRng);
    //let (encapsulator2, decapsulator2) = DhSinglePassStdDhSha256KdfScheme::<NistP256,U32>::generate(&mut OsRng);

    //let mut u = MutualKem2::<DhSinglePassStdDhSha256KdfScheme::<NistP256,U32>, DhSinglePassStdDhSha256KdfScheme::<NistP256,U32>, U16>{encapsulator: encapsulator1, decapsulator: decapsulator2, intermediate_key: None, phantom: PhantomData};
    let u = DhTwoPassStdDhSha256KdfScheme::new_encapsulator(decapsulator1);
    //let mut v = MutualKem2::<DhSinglePassStdDhSha256KdfScheme::<NistP256,U32>, DhSinglePassStdDhSha256KdfScheme::<NistP256,U32>, U16>{encapsulator: encapsulator2, decapsulator: decapsulator1, intermediate_key: None, phantom: PhantomData};
    let v = DhTwoPassStdDhSha256KdfScheme::new_decapsulator(encapsulator1);

    let (pk_ephem, u_decap) = u.encapsulate1(&mut OsRng).unwrap();
    //let (ek_v, v_decap) = v.encapsulate1(&mut OsRng).unwrap();

    // let ss_u = u.decapsulate(&ek_v, false);
    // let ss_v = v.decapsulate(&ek_u, true);
    let (ss_u, ek_v, ek_ephem) = v.decapsulate(&mut OsRng, &pk_ephem).unwrap();
    let ss_v = u_decap.encapsulate2(&ek_v, &ek_ephem).unwrap();

    println! ( "ss_u={:02X?}", ss_u);
    println! ( "ss_v={:02X?}", ss_v);
    assert_eq!( ss_u, ss_v);
}

#[cfg(all(feature="rustcrypto-sha2", feature="rustcrypto-p256", feature="rustcrypto-p384"))]
#[test]
fn test_mkem_1s1e_2() 
{
    type DhTwoPassStdDhSha256KdfScheme = TwoPassKem1S1E<DhSinglePassStdDhSha256KdfScheme<NistP256,U32>,DhSinglePassStdDhSha384KdfScheme<NistP384,U48>, U16>;

    let (encapsulator_u, decapsulator_u) = DhSinglePassStdDhSha256KdfScheme::<NistP256,U32>::generate(&mut OsRng);
    //let (encapsulator_v, decapsulator_v) = DhSinglePassStdDhSha384KdfScheme::<NistP384,U48>::generate(&mut OsRng);

    // let u = MutualKemEncapsulator::<DhSinglePassStdDhSha256KdfScheme::<NistP256,U32>, DhSinglePassStdDhSha384KdfScheme::<NistP384,U48>, U16>{encapsulator: encapsulator1, decapsulator: decapsulator2, phantom: PhantomData};
    // let v = MutualKemEncapsulator::<DhSinglePassStdDhSha384KdfScheme::<NistP384,U48>, DhSinglePassStdDhSha256KdfScheme::<NistP256,U32>, U16>{encapsulator: encapsulator2, decapsulator: decapsulator1, phantom: PhantomData};
    let u = DhTwoPassStdDhSha256KdfScheme::new_encapsulator(decapsulator_u );
    let v = DhTwoPassStdDhSha256KdfScheme::new_decapsulator(encapsulator_u);

    let (ek_u, decap_u) = u.encapsulate1(&mut OsRng).unwrap();
    //let (ek_v, decap_v) = v.encapsulate1(&mut OsRng).unwrap();

    // let ss_u = u.decapsulate(&ek_v, false);
    // let ss_v = v.decapsulate(&ek_u, true);
    let (ss_u, ek_v, ek_ephem) = v.decapsulate(&mut OsRng, &ek_u).unwrap();
    let ss_v = decap_u.encapsulate2(&ek_v, &ek_ephem).unwrap();

    println! ( "ss_u={:02X?}", ss_u);
    println! ( "ss_v={:02X?}", ss_v);
    assert_eq!( ss_u, ss_v);
}
