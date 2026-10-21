use std::iter::once;
use std::marker::PhantomData;
use std::ops::{Add, Sub};

use cipher::consts::U16;
use cipher::common::KeyExport;
use cipher::typenum::{IsLessOrEqual, Sum, U32, U48};
use digest::OutputSizeUser;
use elliptic_curve::point::AffineCoordinates;
use hex_literal::hex;
use hmac::{HmacReset};
use kdfs::{BoundedTypeNum, Kdf, SaltedKdf, Label};
use kdfs::iso11770_6::Ktf1;
use kdfs::misc::{Kmac128Kdf, Kmac256Kdf};
use kdfs::nistsp800_56::SskdfMac;
use kdfs::rfc5869_hkdf::Hkdf;
use kem::consts::True;
use kem::{Decapsulate, FromSeed, TryDecapsulate};
use kems::{Array, ArraySize, KemExtensions, eckem::EcRaw2Encoder, SetKdf};
use kems::x25519kem::X25519Kem;
use kems::eckem::EcdhKem;
use kems::hybrid::{HybridCombiner, HybridKem};
use ml_kem::MlKem768;
use p256::NistP256;
use sha2::{Digest, Sha256, Sha384};

fn concatenate_and_hash(inputs: &[&[u8]]) -> Array<u8, U32> {
    let mut hasher = Sha256::new();
    for input in inputs {
        hasher.update((input.len() as u32).to_be_bytes());
        hasher.update(input);
    }
    hasher.finalize()
}

fn concatenate(inputs: &[&[u8]]) -> Vec<u8> {
    let mut result = Vec::new();
    for input in inputs {
        result.extend_from_slice(&(input.len() as u32).to_be_bytes());
        result.extend_from_slice(input);
    }
    result
}

fn message_format (cid: &[u8], other: &[&[u8]]) -> Vec<u8> {
    let mut message = Vec::new();
    message.extend_from_slice(cid);
    for input in other {
        message.extend_from_slice(&(input.len() as u32 * 2).to_be_bytes());
        message.extend_from_slice(input);
    }
    message
}

pub struct EtsiTestVectorsLabel;
impl Label for EtsiTestVectorsLabel { const LABEL: &'static[u8] = b"ETSI_QSHKE_TEST_VECTORS_V_1_2"; }

pub struct EtsiCatKdfCombiner</*K,*/ LB: Label, const CID: u16, const HASH: bool> 
{   
    //kdf: K, 
    phantom: PhantomData<LB>,
    label_a: Vec<u8>,
    label_b: Vec<u8>,
}

impl</*K: Default,*/ LB: Label, const CID: u16, const HASH: bool> EtsiCatKdfCombiner</*K,*/ LB, CID, HASH> {
    pub fn new_with_labels(label_a: &[u8], label_b: &[u8]) -> Self {
        return Self{ /*kdf: K::default(),*/ phantom: PhantomData, label_a: label_a.to_vec(), label_b: label_b.to_vec()}
    }
}
impl</*K: Default,*/ LB: Label, const CID: u16, const HASH: bool> Default for EtsiCatKdfCombiner</*K,*/ LB, CID, HASH> {
    fn default() -> Self {
        return Self{ /*kdf: K::default(),*/ phantom: PhantomData, label_a: Vec::new(), label_b: Vec::new()}
    }
}
impl</*K: Default,*/ LB: Label, const CID: u16, const HASH: bool> Clone for EtsiCatKdfCombiner</*K,*/ LB, CID, HASH> {
    fn clone(&self) -> Self {
        todo!()
    }
}

//#[repr(u8)]
#[allow(non_snake_case)]
mod CID0 {
    pub const HKDFwSHA256:u8 = 1u8;
    pub const HKDFwSHA384:u8 = 2u8;
    pub const HMACwSHA256:u8 = 4u8;
    pub const HMACwSHA384:u8 = 5u8;
    pub const KMAC128:u8 = 7u8;
    pub const KMAC256:u8 = 8u8;
}

enum CID1 {
    P256 = 1,
    P384 = 2,
    PBP256 = 4,
    PBP384 = 5,
    X25519 = 7,
    X448 = 8
}

enum CID2 {
    MLKEM512 = 1,
    MLKEM768 = 2,
    MLKEM1024 = 3,
}

enum CID3 {
    CatKDF = 1,
    CasKDF = 2,
}



#[allow(non_snake_case)]
impl<'a, /*K: Kdf<L> + Default + InitSalt,*/ LB: Label, L: ArraySize, const CID: u16, const HASH: bool> HybridCombiner<L> for EtsiCatKdfCombiner</*K,*/ LB, CID, HASH>
    where L: ArraySize + IsLessOrEqual<cipher::typenum::Prod<<HmacReset<Sha256> as OutputSizeUser>::OutputSize, <u32 as BoundedTypeNum>::Max>, Output=True>
                        + IsLessOrEqual<cipher::typenum::Prod<<HmacReset<Sha384> as OutputSizeUser>::OutputSize, <u32 as BoundedTypeNum>::Max>, Output=True>,
{
    fn combine ( &self, ss1: impl AsRef<[u8]>, ct1: impl AsRef<[u8]>, pk1: impl AsRef<[u8]>, ss2: impl AsRef<[u8]>, ct2: impl AsRef<[u8]>, pk2: impl AsRef<[u8]> ) -> Array<u8, L> {
        let label = self.label_a.iter().zip(self.label_b.iter()).map(|(a, b)| a ^ b).collect::<Vec<u8>>();

        let MA = message_format(&CID.to_be_bytes(), &[&self.label_a, pk1.as_ref(), pk2.as_ref()]);
        println! ( "MA = {}", hex::encode(&MA));
        let MB = message_format(&CID.to_be_bytes(), &[&self.label_b, ct1.as_ref(), ct2.as_ref()]);
        println! ( "MB = {}", hex::encode(&MB));

        let CID0 = ((CID & 0xF000 ) >> 12) as u8;

        return match CID0 {
            CID0::HKDFwSHA256=> Hkdf::<Sha256>::derive_secrets_salt_other ([ss1.as_ref(), ss2.as_ref()], &label, &concatenate_and_hash(&[LB::LABEL, &MA, &MB])),
            CID0::HKDFwSHA384=> Hkdf::<Sha384>::derive_secrets_salt_other ([ss1.as_ref(), ss2.as_ref()], &label, &concatenate_and_hash(&[LB::LABEL, &MA, &MB])),
            CID0::HMACwSHA256=> SskdfMac::<HmacReset<Sha256>>::derive_secrets_salt_other ([ss1.as_ref(), ss2.as_ref()], &label, &concatenate_and_hash(&[LB::LABEL, &MA, &MB])),
            CID0::HMACwSHA384=> SskdfMac::<HmacReset<Sha384>>::derive_secrets_salt_other ([ss1.as_ref(), ss2.as_ref()], &label, &concatenate_and_hash(&[LB::LABEL, &MA, &MB])),
            CID0::KMAC128 => Kmac128Kdf::derive_secrets_salt_others ( [label.as_slice()], b"KDF", [1u32.to_be_bytes().as_slice(), ss1.as_ref(), &ss2.as_ref(), 
                         /* context */ &(LB::LABEL.len() as u32).to_be_bytes(), LB::LABEL, &(MA.len() as u32).to_be_bytes(), &MA, &(MB.len() as u32).to_be_bytes(), &MB]),
            CID0::KMAC256 => Kmac256Kdf::derive_secrets_salt_others ( [label.as_slice()], b"KDF", [1u32.to_be_bytes().as_slice(), ss1.as_ref(), &ss2.as_ref(), 
                         /* context */ &(LB::LABEL.len() as u32).to_be_bytes(), LB::LABEL, &(MA.len() as u32).to_be_bytes(), &MA, &(MB.len() as u32).to_be_bytes(), &MB]),
            _ => panic! ( "Unhandled CID")
            
        }
        // if CID0 <= CID0::HMACwSHA384 as u8 {
        //     K::derive_secrets_salt_other([ss1.as_ref(), ss2.as_ref()], &label, &concatenate_and_hash(&[LB::LABEL, &MA, &MB]))
        // } else {
        //     K::derive_secrets_salt_others ( [label.as_slice()], b"KDF", [1u32.to_be_bytes().as_slice(), ss1.as_ref(), &ss2.as_ref(), 
        //             /* context */ &(LB::LABEL.len() as u32).to_be_bytes(), LB::LABEL, &(MA.len() as u32).to_be_bytes(), &MA, &(MB.len() as u32).to_be_bytes(), &MB])
        // }
    }
}


pub struct EtsiCasKdfCombiner<K, LB: Label, const CID: u16> 
{ 
    kdf: K, 
    phantom: PhantomData<LB>,
    label_a1: Vec<u8>,
    label_a2: Vec<u8>,
    label_b1: Vec<u8>,
    label_b2: Vec<u8>,
}
impl<K: Default, LB: Label, const CID: u16> Default for EtsiCasKdfCombiner<K, LB, CID> {
    fn default() -> Self {
        return Self{ kdf: K::default(), phantom: PhantomData, label_a1: Vec::new(), label_a2: Vec::new(), label_b1: Vec::new(), label_b2: Vec::new() }
    }
}
impl<K: Default, LB: Label, const CID: u16> Clone for EtsiCasKdfCombiner<K, LB, CID> {
    fn clone(&self) -> Self {
        todo!()
    }
}
impl<K: Default, LB: Label, const CID: u16> EtsiCasKdfCombiner<K, LB, CID> {
    pub fn new_with_labels(label_a1: &[u8], label_a2: &[u8], label_b1: &[u8], label_b2: &[u8]) -> Self {
        return Self{ kdf: K::default(), phantom: PhantomData, label_a1: label_a1.to_vec(), label_a2: label_a2.to_vec(), label_b1: label_b1.to_vec(), label_b2: label_b2.to_vec()}
    }
}


#[allow(non_snake_case)]
impl<'c, K: Kdf<Sum<U32, L>> + Default, LB: Label, L: ArraySize, const CID: u16> HybridCombiner<L> for EtsiCasKdfCombiner<K, LB, CID>
where U32: Add<L>,
    Sum<U32, L>: ArraySize + Sub<U32, Output=L>,
    //for<'a> K: InitSalt2<'a>
    //K: InitSalt2<'c>
    K: SaltedKdf<Sum<U32, L>>
{
    fn combine ( &self, ss1: impl AsRef<[u8]>, ct1: impl AsRef<[u8]>, pk1: impl AsRef<[u8]>, ss2: impl AsRef<[u8]>, ct2: impl AsRef<[u8]>, pk2: impl AsRef<[u8]> ) -> Array<u8, L> {
        let context = b"ETSI_QSHKE_TEST_VECTORS_V_1_2";
        let context2 = b"ETSI_QSHKE_TEST_VECTORS_V_1_2";
        
        let label1 = self.label_a1.iter().zip(self.label_b1.iter()).map(|(a, b)| a ^ b).collect::<Vec<u8>>();
        let label2 = self.label_a2.iter().zip(self.label_b2.iter()).map(|(a, b)| a ^ b).collect::<Vec<u8>>();

        let MA1 = message_format(&CID.to_be_bytes(), &[&self.label_a1, pk1.as_ref()]);
        let MB1 = message_format(&CID.to_be_bytes(), &[&self.label_b1, ct1.as_ref()]);
        
        let CID0 = ((CID & 0xF000 ) >> 12) as u8;

        // let chain_secret_key_mat1: Array<u8, Sum<U32, L>> = if HASH {
        //     let round_secret1 = Ktf1::<HmacReset<Sha256>>::derive_secret_salt_other(&[], &[], &concatenate_and_hash(&[ss1.as_ref(), &MA1, &MB1]));
        //     K::derive_secret_salt_other ( &round_secret1, &label1, context)
        // } else {
        //      let round_secret1: Array<u8, U32> = Kmac128KdfStatic::derive_secrets_salt_others(once([0u8; 32].as_slice()), b"",
        //          [(ss1.as_ref().len() as u32).to_be_bytes().as_slice(), ss1.as_ref(), &(MA1.len() as u32).to_be_bytes(), &MA1, &(MB1.len() as u32).to_be_bytes(), &MB1]);
        //     Kmac128KdfStatic::derive_secrets_salt_others ( [label1.as_slice()], b"KDF", [1u32.to_be_bytes().as_slice(), &round_secret1, context])
        // };
        let chain_secret_key_mat1: Array<u8, Sum<U32, L>> = match CID0 {
            CID0::HKDFwSHA256 | CID0::HKDFwSHA384 | CID0::HMACwSHA256 | CID0::HMACwSHA384 =>
            {
                let round_secret1 = Ktf1::<HmacReset<Sha256>>::derive_secret_salt_other(&[], &[], &concatenate_and_hash(&[ss1.as_ref(), &MA1, &MB1]));
                K::derive_secrets_salt_others ( Some(round_secret1.as_slice()), &label1, Some(context.as_slice()))
                //Array::default()
            },
            CID0::KMAC128 => {
                let round_secret1: Array<u8, U32> = Kmac128Kdf::derive_secrets_salt_others(once([0u8; 32].as_slice()), b"",
                [(ss1.as_ref().len() as u32).to_be_bytes().as_slice(), ss1.as_ref(), &(MA1.len() as u32).to_be_bytes(), &MA1, &(MB1.len() as u32).to_be_bytes(), &MB1]);
                Kmac128Kdf::derive_secrets_salt_others ( [label1.as_slice()], b"KDF", [1u32.to_be_bytes().as_slice(), &round_secret1, context])
            },
            _ => panic! ( "Unhandled CID")
        };

        println! ( "*chain_secret_key_mat={:02X?}", chain_secret_key_mat1);
        
        let (chain_secret1, _key_material1) = Array::split::<U32>(chain_secret_key_mat1);

        let MA2 = message_format(&CID.to_be_bytes(), &[&self.label_a2, pk2.as_ref()]);
        println! ( "*MA2={:02X?}", MA2);
        let MB2 = message_format(&CID.to_be_bytes(), &[&self.label_b2, ct2.as_ref()]);
        println! ( "*MB2={:02X?}", MB2);

        // let chain_secret_key_mat: Array<u8, Sum<U32,L>> = if HASH {
        //     let round_secret2 = Ktf1::<HmacReset<Sha256>>::derive_secret_salt_other(&[], &chain_secret1, &concatenate_and_hash(&[&ss2.as_ref(), &MA2, &MB2]));
        //     K::derive_secret_salt_other ( &round_secret2, &label2, context2)
        // } else {
        //     let round_secret2: Array<u8, U32> = Kmac128KdfStatic::derive_secrets_salt_others(once(chain_secret1.as_slice()), &[], 
        //         [(ss2.as_ref().len() as u32).to_be_bytes().as_slice(), ss2.as_ref(), &(MA2.len() as u32).to_be_bytes(), &MA2, &(MB2.len() as u32).to_be_bytes(), &MB2]);
        //     Kmac128KdfStatic::derive_secrets_salt_others ( [label2.as_slice()], b"KDF", [1u32.to_be_bytes().as_slice(), &round_secret2, context2])
        // };

        let chain_secret_key_mat: Array<u8, Sum<U32, L>> = match CID0 {
            CID0::HKDFwSHA256 | CID0::HKDFwSHA384 | CID0::HMACwSHA256 | CID0::HMACwSHA384 => {
                let round_secret2 = Ktf1::<HmacReset<Sha256>>::derive_secret_salt_other(&[], &chain_secret1, &concatenate_and_hash(&[&ss2.as_ref(), &MA2, &MB2]));
                K::derive_secrets_salt_others ( Some(round_secret2.as_slice()), &label2, Some(context2.as_slice()))
                //Array::default()
                },
            CID0::KMAC128 => {
                let round_secret2: Array<u8, U32> = Kmac128Kdf::derive_secrets_salt_others(once(chain_secret1.as_slice()), &[], 
                [(ss2.as_ref().len() as u32).to_be_bytes().as_slice(), ss2.as_ref(), &(MA2.len() as u32).to_be_bytes(), &MA2, &(MB2.len() as u32).to_be_bytes(), &MB2]);
                Kmac128Kdf::derive_secrets_salt_others ( [label2.as_slice()], b"KDF", [1u32.to_be_bytes().as_slice(), &round_secret2, context2])
            },
            _ => panic!( "Unhandled")
        };
        
        println! ( "*chain_secret_key_mat2={:02X?}", chain_secret_key_mat);
        
        let (_chain_secret2, key_material2) = Array::split::<U32>(chain_secret_key_mat);
        key_material2        
    }
}


// pub struct EtsiCasKdfCombiner2<K, LB: Label, const CID: u16> 
// { 
//     kdf: K, 
//     phantom: PhantomData<LB>,
//     label_a1: Vec<u8>,
//     label_a2: Vec<u8>,
//     label_b1: Vec<u8>,
//     label_b2: Vec<u8>,
// }
// impl<K: Default, LB: Label, const CID: u16> Default for EtsiCasKdfCombiner2<K, LB, CID> {
//     fn default() -> Self {
//         return Self{ kdf: K::default(), phantom: PhantomData, label_a1: Vec::new(), label_a2: Vec::new(), label_b1: Vec::new(), label_b2: Vec::new() }
//     }
// }
// impl<K: Default, LB: Label, const CID: u16> EtsiCasKdfCombiner2<K, LB, CID> {
//     pub fn new_with_labels(label_a1: &[u8], label_a2: &[u8], label_b1: &[u8], label_b2: &[u8]) -> Self {
//         return Self{ kdf: K::default(), phantom: PhantomData, label_a1: label_a1.to_vec(), label_a2: label_a2.to_vec(), label_b1: label_b1.to_vec(), label_b2: label_b2.to_vec()}
//     }
// }
// impl<K: Kdf<U48> + Default + InitSalt, LB: Label, L: ArraySize, const CID: u16> HybridCombiner<L> for EtsiCasKdfCombiner2<K, LB, CID>
// {
//     fn combine ( &self, ss1: impl AsRef<[u8]>, ct1: impl AsRef<[u8]>, pk1: impl AsRef<[u8]>, ss2: impl AsRef<[u8]>, ct2: impl AsRef<[u8]>, pk2: impl AsRef<[u8]> ) -> Array<u8, L> {
//         //let CID = hex!("1121");
//         //let CID = hex!("4121");
//         let context1 = b"ETSI_QSHKE_TEST_VECTORS_V_1_2";
//         //let LA1 = hex!("10102030405060708090A0B0C0D0E0F10102030405060708090A0B0C0D0E0F14");
//         //let LB1 = hex!("0202030405060708090A0B0C0D0E0F14202030405060708090A0B0C0D0E0F14B");
//         //let label1 = /*LA1 ^ LB1*/ hex!("1212233445566778899AABBCCDDEEFE5212233445566778899AABBCCDDEEFE5F");
//         //let LA2 = hex!("3102030405060708090A0B0C0D0E0F110102030405060708090A0B0C0D0E0F30");
//         //let LB2 = hex!("4202030405060708090A0B0C0D0E0F1F202030405060708090A0B0C0D0E0F1F7");

//         let context2 = b"ETSI_QSHKE_TEST_VECTORS_V_1_2";
//         //let label2 = hex!("7300000000000000000000000000000E212233445566778899AABBCCDDEEFEC7");
//         let label1 = self.label_a1.iter().zip(self.label_b1.iter()).map(|(a, b)| a ^ b).collect::<Vec<u8>>();
//         let label2 = self.label_a2.iter().zip(self.label_b2.iter()).map(|(a, b)| a ^ b).collect::<Vec<u8>>();

        
//         let MA1 = message_format(&CID.to_be_bytes(), &[&self.label_a1, pk1.as_ref()]);
//         let MB1 = message_format(&CID.to_be_bytes(), &[&self.label_b1, ct1.as_ref()]);
//         let hhhh = concatenate(&[ss1.as_ref(), &MA1, &MB1]);

//         println! ( "*hhhh={:02X?}", hhhh);
//         let round_secret1: Array<u8, U32> = Kmac128KdfStatic::derive_secret_salt_other(&[0u8; 32], b"", &hhhh);
//         println! ( "*round_secret1={:02X?}", round_secret1);

//         //let chain_secret_key_mat1: Array<u8, U48> = Hkdf::<Sha256>::derive_secret_salt_other ( &round_secret1, &label1, context.as_bytes());
//         //let km_calc: Array<u8, U16> = Kmac128KdfStatic::derive_secrets_salt_others ( [label.as_slice()], b"KDF", [1u32.to_be_bytes().as_slice(), &k1, &k2, &context_calc]);
//         let chain_secret_key_mat1: Array<u8, U48> = Kmac128KdfStatic::derive_secrets_salt_others([label1.as_slice()], b"KDF", [1u32.to_be_bytes().as_slice(), &round_secret1, context1]);

//         println! ( "*chain_secret_key_mat={:02X?}", chain_secret_key_mat1);
//         let chain_secret1 = &chain_secret_key_mat1[0..32];

//         let MA2 = message_format(&CID.to_be_bytes(), &[&self.label_a2, pk2.as_ref()]);
//         println! ( "*MA2={:02X?}", MA2);
//         let MB2 = message_format(&CID.to_be_bytes(), &[&self.label_b2, ct2.as_ref()]);
//         println! ( "*MB2={:02X?}", MB2);
             
//         let hhhh2 = concatenate(&[&ss2.as_ref(), &MA2, &MB2]);
//         println! ( "*hhhh2={:02X?}", hhhh2);
       
//         let round_secret2: Array<u8, U32> = Kmac128KdfStatic::derive_secret_salt_other(&chain_secret1, &[], &hhhh2);

//         println! ( "*round_secret2={:02X?}", round_secret2);
//         println! ( "*label2={:02X?}", label2);
//         println! ( "*context2={:02X?}", context2);

    
//         let chain_secret_key_mat: Array<u8, U48> = Kmac128KdfStatic::derive_secrets_salt_others ( [label2.as_slice()], b"KDF", [1u32.to_be_bytes().as_slice(), &round_secret2, context2]);

//         println! ( "*chain_secret_key_mat2={:02X?}", chain_secret_key_mat);
//         let chain_secret2 = &chain_secret_key_mat[0..32];
//         let key_material2 = &chain_secret_key_mat[32..48];
//         key_material2.try_into().expect("key_material2 length mismatch")
        
//     }
// }








// CatKDF using HKDF with SHA256, ECDH with NIST P-256, and ML-KEM768
#[allow(non_snake_case)]
#[test]
fn test_d_2_1(){
    let CID = hex!("1121");
    let LA = hex!("10102030405060708090A0B0C0D0E0F10102030405060708090A0B0C0D0E0F14");
    let dA1 = hex!("7d7dc5f71eb29ddaf80d6214632eeae03d9058af1fb6d22ed80badb62bc1a534");
    let PA1 = hex!("EAD218590119E8876B29146FF89CA61770C4EDBBF97D38CE385ED281D8A6B23028AF61281FD35E2FA7002523ACC85A429CB0
        6EE6648325389F59EDFCE1405141");
    let zA2 = hex!("b585d4eb01085111a172a87688d0032e3381a9e9a35fdd6ef2f8aeb3b40eb5ce"); /*  */
    let dA2 = hex!("89b0c4b23019af3498a27da290892d981dd59fa08993bc05da21e1d72503664c");
    let PA2 =hex!("533145987CB33CD2C8F5AC8A73C03A97FB31D2B89D02B1576CFC77BC97656FC040FCC7569750459EE753EBD69839692B375A
        0F53165B191CA8C6185B85626282C0A4AD63B36B6A289F661D505850832248D6F39084695C028B979835848931874E037EDF
        33CD9F1521E2B478BF0C37D859572AB08C20F7687749032949AB7457B66C1206C08A78C58633BA008E8770224700B84758B2
        2B290E9ED01F750439B00B97729960940817D3BA0CE7F10EB6A0C8EBD975C85A6299A6CE486132292189F9DCC13F27591870
        4192A417E7B305834323C354213195BAD0A5AA30A3980B028A1E116E97E74ED8D053A2FA51E00068BCD69D325246E93A30AD
        493D28099AF143016BE454413256A5DA144C9985C70664EE12013DF167E228B921EA3BAC494B5D5140581A4D7E7080B4C284
        A6DAA955366EAE3217541A0B1109313F7A1AE9305D55B45CB6A5B2F3321A10DB137E92306A3B2A25FC1999495F7A732D7CD8
        3BE0923050A5562A036699F92427CB71C0CA201D958F7A3171740AB477188DB276A52E576703493E289C14BF896D5A827586
        492D23B605CDC6932A4ABF902A219F88B12D0479C91B4EE6C586A4A2061FC22D66264772359B569456111574D84606CBA282
        92C37A40B81F5A113BB9E72871E14184270FE2A87C33BA7D01E95A578950D098C48A584428BAC781BA938F13BB80F4790EC3
        6F1A394FEC97AB80054F60A90DA86ABE7D84799A604233A5A495294D13805B6CF3505DB833E9F223D102AAA9E666580B088E
        1CBABC4CB52725CB768B5E990B89411AA652E06A2BDB937B185EB924C59AF6BA9BE2BA09409DB5C262D751731461A89AAC05
        ADACC320B6AFC5C4A5FDBB2F56B2483D11779C7117707B121D0B36362B2BF8D4B28F6948F5EB1D5E41B1C8A5053D581019C3
        6AC87988803CB934027909DC4C5BD1AE2EF451D9F7945209C0E9E60AF43C50DC98646F3BB13BE6491E91930D9AA1AA315FB3
        B1A067579565D170C4E888E9042751106B72A60470A69992508E8CE3101A602A22DA7FB1A744F09488E704481F649DAB6158
        E5306F573009EC63ACF11B549D280033343FC9750BB927B931B94F9C5475A2B803AF36CC3CC30521EA2A86040E03E7CF90B3
        6D2E370856285AE4523367482E68473CA500200F75C8C423C8AB93C7BFE74DF253AF97114A3FEAC1DDD34E06747C6B386990
        428100A99351BA14A3C19B1A7A6DA5A715F6A698E9FC330C13B98D61A2A85AC0E0896CC8032490B93FEB284703F21E6D1630
        7D7886F948752FE55CEE7291C06AA7BBB79146C644AEA7C2765C5EFA535B729158EB51BC2D4C389B970B30086966D858D51B
        78EF3829F9290DAF241C6D370425D83DDD61153DD2AC0FD206120434AD6792D60B2F084A2950AAC250B4001F309EA45B09D9
        DB440D6A2C9BB3B140569C51C985A2B0BE03ABA918C2311B11069FC9A0C762CCA59C1BDAE47C0406AF0CC7BBB1821C0F8733
        563ABBE896525E1156F7D593F55C39922B6B79E462CE587189247FA045CB19FA7256B960D0B25B7B364ECE250D43E19313C7
        98CE424634DC358A0914FAF33EA2B06EAA748947C6C150E54D7BD3A4C4873B117266145833FF04CAA96424AB678B49BA94D6
        619F01BBC62961850CF25765C7627910EF8E79F9B3749086AABF75407D7AC42748BC");
    let LB = hex!("0202030405060708090A0B0C0D0E0F14202030405060708090A0B0C0D0E0F14B");
    let PB1 = hex!("700C48F77F56584C5CC632CA65640DB91B6BACCE3A4DF6B42CE7CC838833D287DB71E509E3FD9B060DDB20BA5C51DCC5948D
        46FBF640DFE0441782CAB85FA4AC");
    let PB2 = hex!("CC1160B24F3AB56D7E3EEF460A2AD73D0E5B50BC5FD6E06D74C80DF6295A5E7FED8664C9B819ABB90BF1B2481CA3958EDE01
        9E5A8D215E3C3B2FC662E6A6E5F4D6CD36C30C747745FCD8F85560645EC010987B87A7B42E619F388FDBB9DF0B916A01AD06
        40A9B761A9353DE373033EC5E2D16B59DB508BA33259B9791691FE35B2F08AFF381BFC9A74E380DFAC915B6165ED8C276DC7
        112FD36B7C21710AC6A2201179642BACA216C3D4C39EA74E75A370B9ADE85A2AD8B00EADCC4AE2B3819374FDCE01F4AF0253
        5194B88933ECE5A9B90C1886EFBCF40B1505D4D2603F7FED815F3B101664A90B239FE598E90C09069E102C500912C71F5339
        6EA1C9035682C9ECB1627193FDEE803078E4CAB436B6CACE8A861AD95B5F53E6C9757EEDD7FC9EA369089E82D2D32C952094
        60BD880C7D856DD8BD589E131C991E1148B5E4139E7F4EE32B25DA676FCB279ED94D9B28B6C4843F07A93FADC1314869D2E2
        71D90D993E4F5B654157BDBF45215D691AFAECC498E9ADB3A798029C2D68665878634E02B34006BA953DB444203C88C4523B
        EDCA14358E0B129BC712EAB69D1C253C490DD4E5F751FBA1B38BA200A3E73E78299306855237C6F72B15598B2EAB30224A22
        C2C7883C6BEDE636C4D1C06ED0B6793E4609969CF8A442614C8C547598C26CC848BC4593E24591FC85F624548A1D01EA5BE0
        4892C5C12EC07F70C8CA51C4CCD1C9F061EE1BFE07112C2577552966EB25759E77882F1B5B327964E6269E36C1D5AC9C94B0
        1D891E1B3AC2660C5D99E32364AB31015986352ABB20A228C358A548D1B413FF534550F2EE0C80E0741B7F90DC22E8D701A4
        4514810820A5A1D5EE62173283F91DAB585615E36A520FD7540FF7E7B9D6F2FB616251F1D2B6A034AF6427E66D559D7E04F1
        C7C22FEFA5F3F7B256D7225D5F683FE29238754D66E10687290675202CD15A32A7F71B5750A95BFCC183D2C26BF31D41225C
        04FBC123683FA911B994C5B9AE5172EE9847356C67302E7C405625543B7FA82D9BE737467F7C000F97FFBB647500DE9EE36A
        266F97AE83AB58D239533C8A2FB440E649ACDF6EFC8D98BAF10A1BFA0F7681EC9708BAB9D00A78FFF74AA4C7099D6DA69FBE
        E2B7C5EA7CEB04527D01CA2CCA8416181BA450C2519A8F383881FF439DEDCE45BF0117CAC0A612E52AD1A3B2F2D1C9917264
        DD131813F3D9F6D2D574D6CE9AA0943AA7E84C9BDEC515B6827921366794FE6B9058769ADCB3A14593CA49A866DC7AF5BCAF
        2A48BB06271B3948CC64572AE3A9D46A1209D3E70A02D50AC3CB0AA1B820F8EA25DA127931406AAFC9B00C0FD90C75973215
        86694E35EA291A88665A2FFBAE5C9BE45938E60027C6C6DEB384F873457B5B5C7107651AE0273DF8A23FDFF74A2A6BD67703
        854FA5E115712E84D6726F27370FDE6390B362142FCD93647BD2D7A3927DE5F5040F60E17C39D1248F6662CF441EE4B2470C
        D412050CE09EC31075001286F401A58FE6217000D6A9C8BA753C4CE9D1D8CF8B908614DF0A81");
    let k1 = hex!("46FC62106420FF012E54A434FBDD2D25CCC5852060561E68040DD7778997BD7B");
    let k2 = hex!("D71BD5A07C158C130283EF854516D290A46ADE09A63831C7B83B8FD0724C8FB0");
    let context = "ETSI_QSHKE_TEST_VECTORS_V_1_2";
    let label = /*LA ^ LB =*/ hex!("1212233445566778899AABBCCDDEEFE5212233445566778899AABBCCDDEEFE5F");
    // MA = cid || len(LA)|| LA || len(PA1) || PA1 || len(PA2) || PA2
    // MB = cid || len(LB)|| LB || len(PB1) || PB1 || len(PB2) || PB2
    let key_material = hex!("99B5DC7F166C3158043BC626DD0C4498");
    let _key_material2 = hex!("8109982E98D11BD18A791D05E430E17C"); // Output from running sample code provided by ETSI, doesn't have the *2 on the length fields

    let prvA1 = p256::SecretKey::from_bytes(&dA1.into()).unwrap();
    let pubA2 = prvA1.public_key();
    assert_eq!(pubA2.as_affine().x().concat(pubA2.as_affine().y()), PA1);

    let (d,e) = kems::eckem::EcdhKem::<NistP256,EcRaw2Encoder<NistP256>>::from_seed(&dA1.into());

    //println! ( "{:02X?}", e.as_bytes());
    assert_eq! ( e.to_bytes().as_slice(), &PA1);    // Verify public key for ECDH

    let k_calc = d.try_decapsulate(&PB1.into()).unwrap();
    assert_eq! ( k1, k_calc);
    //assert_eq! ( k2, k_calc[32..]);

    //let (prv1, pub2) = ml_kem::MlKem768::generate_deterministic(&dA2.into(), &zA2.into());
    let prv1 = ml_kem::ml_kem_768::DecapsulationKey::from_seed([dA2, zA2].concat().try_into().unwrap());
    let pub2 = prv1.encapsulation_key();
    assert_eq!( pub2.to_bytes(), PA2);  // Verify public key ML-KEM 768

    let k2_calc = prv1.decapsulate(&PB2.into());
    assert_eq!(k2_calc, k2);

    let MA = message_format(&CID, &[&LA, &PA1, &PA2]);
    println! ( "MA = {}", hex::encode(&MA));

    let MB = message_format(&CID, &[&LB, &PB1, &PB2]);
    println! ( "MB = {}", hex::encode(&MB));
    
    let context_calc = concatenate_and_hash(&[context.as_bytes(), &MA, &MB]);
    println! ( "context = {}", hex::encode(&context_calc));

    let km_calc: kems::Array<u8, U16> = Hkdf::<Sha256>::derive_secrets_salt_others([k1.as_slice(),k2.as_slice()], &label, [context_calc.as_slice() ]);
    println! ( "km_calc={:02X?}", km_calc);
    assert_eq!(km_calc, key_material);

    type EtsiHybrid = HybridKem<EcdhKem<NistP256, EcRaw2Encoder<NistP256>>, MlKem768, EtsiCatKdfCombiner</*Hkdf<Sha256>,*/ EtsiTestVectorsLabel, 0x1121, true>, U16,>;
    let mut decapsulator = EtsiHybrid::try_from_slice_decap2(&[dA1.as_slice(), &dA2, &zA2].concat()).unwrap();
    decapsulator.set_kdf(EtsiCatKdfCombiner::</*Hkdf<Sha256>,*/ EtsiTestVectorsLabel, 0x1121, true>::new_with_labels(&LA, &LB));

    let km_calc2 = decapsulator.try_decapsulate(&[PB1.as_slice(), PB2.as_slice()].concat().try_into().unwrap()).unwrap();
    assert_eq!(km_calc2.as_slice(), key_material.as_slice());

    
}


// CatKdf using HMAC with SHA245, ECDH with NIST P-256 and ML-KEM 768
#[allow(non_snake_case)]
#[test]
fn test_d_2_2(){
    let CID = hex!("4121");
    let LA = hex!("10102030405060708090A0B0C0D0E0F10102030405060708090A0B0C0D0E0F14");
    let dA1 = hex!("7d7dc5f71eb29ddaf80d6214632eeae03d9058af1fb6d22ed80badb62bc1a534");
    let PA1 = hex!("EAD218590119E8876B29146FF89CA61770C4EDBBF97D38CE385ED281D8A6B23028AF61281FD35E2FA7002523ACC85A429CB0
        6EE6648325389F59EDFCE1405141");
    let zA2 = hex!("b585d4eb01085111a172a87688d0032e3381a9e9a35fdd6ef2f8aeb3b40eb5ce");
    let dA2 = hex!("89b0c4b23019af3498a27da290892d981dd59fa08993bc05da21e1d72503664c");
    let PA2 = hex!("533145987CB33CD2C8F5AC8A73C03A97FB31D2B89D02B1576CFC77BC97656FC040FCC7569750459EE753EBD69839692B375A
        0F53165B191CA8C6185B85626282C0A4AD63B36B6A289F661D505850832248D6F39084695C028B979835848931874E037EDF
        33CD9F1521E2B478BF0C37D859572AB08C20F7687749032949AB7457B66C1206C08A78C58633BA008E8770224700B84758B2
        2B290E9ED01F750439B00B97729960940817D3BA0CE7F10EB6A0C8EBD975C85A6299A6CE486132292189F9DCC13F27591870
        4192A417E7B305834323C354213195BAD0A5AA30A3980B028A1E116E97E74ED8D053A2FA51E00068BCD69D325246E93A30AD
        493D28099AF143016BE454413256A5DA144C9985C70664EE12013DF167E228B921EA3BAC494B5D5140581A4D7E7080B4C284
        A6DAA955366EAE3217541A0B1109313F7A1AE9305D55B45CB6A5B2F3321A10DB137E92306A3B2A25FC1999495F7A732D7CD8
        3BE0923050A5562A036699F92427CB71C0CA201D958F7A3171740AB477188DB276A52E576703493E289C14BF896D5A827586
        492D23B605CDC6932A4ABF902A219F88B12D0479C91B4EE6C586A4A2061FC22D66264772359B569456111574D84606CBA282
        92C37A40B81F5A113BB9E72871E14184270FE2A87C33BA7D01E95A578950D098C48A584428BAC781BA938F13BB80F4790EC3
        6F1A394FEC97AB80054F60A90DA86ABE7D84799A604233A5A495294D13805B6CF3505DB833E9F223D102AAA9E666580B088E
        1CBABC4CB52725CB768B5E990B89411AA652E06A2BDB937B185EB924C59AF6BA9BE2BA09409DB5C262D751731461A89AAC05
        ADACC320B6AFC5C4A5FDBB2F56B2483D11779C7117707B121D0B36362B2BF8D4B28F6948F5EB1D5E41B1C8A5053D581019C3
        6AC87988803CB934027909DC4C5BD1AE2EF451D9F7945209C0E9E60AF43C50DC98646F3BB13BE6491E91930D9AA1AA315FB3
        B1A067579565D170C4E888E9042751106B72A60470A69992508E8CE3101A602A22DA7FB1A744F09488E704481F649DAB6158
        E5306F573009EC63ACF11B549D280033343FC9750BB927B931B94F9C5475A2B803AF36CC3CC30521EA2A86040E03E7CF90B3
        6D2E370856285AE4523367482E68473CA500200F75C8C423C8AB93C7BFE74DF253AF97114A3FEAC1DDD34E06747C6B386990
        428100A99351BA14A3C19B1A7A6DA5A715F6A698E9FC330C13B98D61A2A85AC0E0896CC8032490B93FEB284703F21E6D1630
        7D7886F948752FE55CEE7291C06AA7BBB79146C644AEA7C2765C5EFA535B729158EB51BC2D4C389B970B30086966D858D51B
        78EF3829F9290DAF241C6D370425D83DDD61153DD2AC0FD206120434AD6792D60B2F084A2950AAC250B4001F309EA45B09D9
        DB440D6A2C9BB3B140569C51C985A2B0BE03ABA918C2311B11069FC9A0C762CCA59C1BDAE47C0406AF0CC7BBB1821C0F8733
        563ABBE896525E1156F7D593F55C39922B6B79E462CE587189247FA045CB19FA7256B960D0B25B7B364ECE250D43E19313C7
        98CE424634DC358A0914FAF33EA2B06EAA748947C6C150E54D7BD3A4C4873B117266145833FF04CAA96424AB678B49BA94D6
        619F01BBC62961850CF25765C7627910EF8E79F9B3749086AABF75407D7AC42748BC");
    let LB = hex!("0202030405060708090A0B0C0D0E0F14202030405060708090A0B0C0D0E0F14B");
    let PB1 = hex!("700C48F77F56584C5CC632CA65640DB91B6BACCE3A4DF6B42CE7CC838833D287DB71E509E3FD9B060DDB20BA5C51DCC5948D
        46FBF640DFE0441782CAB85FA4AC");
    let PB2 = hex!("CC1160B24F3AB56D7E3EEF460A2AD73D0E5B50BC5FD6E06D74C80DF6295A5E7FED8664C9B819ABB90BF1B2481CA3958EDE01
        9E5A8D215E3C3B2FC662E6A6E5F4D6CD36C30C747745FCD8F85560645EC010987B87A7B42E619F388FDBB9DF0B916A01AD06
        40A9B761A9353DE373033EC5E2D16B59DB508BA33259B9791691FE35B2F08AFF381BFC9A74E380DFAC915B6165ED8C276DC7
        112FD36B7C21710AC6A2201179642BACA216C3D4C39EA74E75A370B9ADE85A2AD8B00EADCC4AE2B3819374FDCE01F4AF0253
        5194B88933ECE5A9B90C1886EFBCF40B1505D4D2603F7FED815F3B101664A90B239FE598E90C09069E102C500912C71F5339
        6EA1C9035682C9ECB1627193FDEE803078E4CAB436B6CACE8A861AD95B5F53E6C9757EEDD7FC9EA369089E82D2D32C952094
        60BD880C7D856DD8BD589E131C991E1148B5E4139E7F4EE32B25DA676FCB279ED94D9B28B6C4843F07A93FADC1314869D2E2
        71D90D993E4F5B654157BDBF45215D691AFAECC498E9ADB3A798029C2D68665878634E02B34006BA953DB444203C88C4523B
        EDCA14358E0B129BC712EAB69D1C253C490DD4E5F751FBA1B38BA200A3E73E78299306855237C6F72B15598B2EAB30224A22
        C2C7883C6BEDE636C4D1C06ED0B6793E4609969CF8A442614C8C547598C26CC848BC4593E24591FC85F624548A1D01EA5BE0
        4892C5C12EC07F70C8CA51C4CCD1C9F061EE1BFE07112C2577552966EB25759E77882F1B5B327964E6269E36C1D5AC9C94B0
        1D891E1B3AC2660C5D99E32364AB31015986352ABB20A228C358A548D1B413FF534550F2EE0C80E0741B7F90DC22E8D701A4
        4514810820A5A1D5EE62173283F91DAB585615E36A520FD7540FF7E7B9D6F2FB616251F1D2B6A034AF6427E66D559D7E04F1
        C7C22FEFA5F3F7B256D7225D5F683FE29238754D66E10687290675202CD15A32A7F71B5750A95BFCC183D2C26BF31D41225C
        04FBC123683FA911B994C5B9AE5172EE9847356C67302E7C405625543B7FA82D9BE737467F7C000F97FFBB647500DE9EE36A
        266F97AE83AB58D239533C8A2FB440E649ACDF6EFC8D98BAF10A1BFA0F7681EC9708BAB9D00A78FFF74AA4C7099D6DA69FBE
        E2B7C5EA7CEB04527D01CA2CCA8416181BA450C2519A8F383881FF439DEDCE45BF0117CAC0A612E52AD1A3B2F2D1C9917264
        DD131813F3D9F6D2D574D6CE9AA0943AA7E84C9BDEC515B6827921366794FE6B9058769ADCB3A14593CA49A866DC7AF5BCAF
        2A48BB06271B3948CC64572AE3A9D46A1209D3E70A02D50AC3CB0AA1B820F8EA25DA127931406AAFC9B00C0FD90C75973215
        86694E35EA291A88665A2FFBAE5C9BE45938E60027C6C6DEB384F873457B5B5C7107651AE0273DF8A23FDFF74A2A6BD67703
        854FA5E115712E84D6726F27370FDE6390B362142FCD93647BD2D7A3927DE5F5040F60E17C39D1248F6662CF441EE4B2470C
        D412050CE09EC31075001286F401A58FE6217000D6A9C8BA753C4CE9D1D8CF8B908614DF0A81");
    let k1 = hex!("46FC62106420FF012E54A434FBDD2D25CCC5852060561E68040DD7778997BD7B");
    let k2 = hex!("D71BD5A07C158C130283EF854516D290A46ADE09A63831C7B83B8FD0724C8FB0");
    let context = b"ETSI_QSHKE_TEST_VECTORS_V_1_2";
    let label = /*LA ^ LB =*/ hex!("1212233445566778899AABBCCDDEEFE5212233445566778899AABBCCDDEEFE5F");
    // MA = cid || len(LA)|| LA || len(PA1) || PA1 || len(PA2) || PA2
    // MB = cid || len(LB)|| LB || len(PB1) || PB1 || len(PB2) || PB2
    let key_material = hex!("3F0EC466248B91B18FA82A557C12E0E4");
    let _key_material2 = hex!("BA73DD7926410802A2138342E9343402"); // As retrieved from running the ETSI provided test program, doesn't have the *2 on the length fields

    let MA = message_format(&CID, &[&LA, &PA1, &PA2]);
    let MB = message_format(&CID, &[&LB, &PB1, &PB2]);

    let context_calc = concatenate_and_hash(&[context, &MA, &MB] );

    println! ( "MA = {}", hex::encode(&MA));
    println! ( "MB = {}", hex::encode(&MB));
    println! ( "context={:02X?}", context_calc );

    let km_calc: Array<u8, U16> = SskdfMac::<HmacReset<Sha256>>::derive_secrets_salt_others ( [k1.as_slice(), k2.as_slice()], &label, [context_calc.as_slice()]);
    println! ( "km_calc={:02X?}", km_calc);
    assert_eq!(km_calc, key_material);

    //type EtsiHybrid = HybridKem<EcdhKem<NistP256, EcRaw2Encoder<NistP256>>, MlKem768, EtsiCatKdfCombiner<Hkdf<Sha256>, EtsiTestVectorsLabel>, U16>;
    type EtsiHybrid = HybridKem<EcdhKem<NistP256, EcRaw2Encoder<NistP256>>, MlKem768, EtsiCatKdfCombiner</*SskdfMac::<HmacReset<Sha256>>,*/ EtsiTestVectorsLabel, 0x4121, true>, U16>;

    let mut decapsulator = EtsiHybrid::try_from_slice_decap2(&[dA1.as_slice(), &dA2, &zA2].concat()).unwrap();
    decapsulator.set_kdf(EtsiCatKdfCombiner::</*SskdfMac::<HmacReset<Sha256>>,*/ EtsiTestVectorsLabel, 0x4121, true>::new_with_labels(&LA, &LB));
    let km_calc2 = decapsulator.try_decapsulate(&[PB1.as_slice(), PB2.as_slice()].concat().try_into().unwrap()).unwrap();
    assert_eq!(km_calc2.as_slice(), key_material.as_slice());
}

// CatKdf using KMAC128, ECDH with NIST P-256 and ML-KEM 768
#[allow(non_snake_case)]
#[test]
fn test_d_2_3(){
    let CID = hex!("7121");
    let LA = hex!("10102030405060708090A0B0C0D0E0F10102030405060708090A0B0C0D0E0F14");
    let dA1 = hex!("7d7dc5f71eb29ddaf80d6214632eeae03d9058af1fb6d22ed80badb62bc1a534");
    let PA1 = hex!("EAD218590119E8876B29146FF89CA61770C4EDBBF97D38CE385ED281D8A6B23028AF61281FD35E2FA7002523ACC85A429CB0
        6EE6648325389F59EDFCE1405141");
    let zA2 = hex!("b585d4eb01085111a172a87688d0032e3381a9e9a35fdd6ef2f8aeb3b40eb5ce");
    let dA2 = hex!("89b0c4b23019af3498a27da290892d981dd59fa08993bc05da21e1d72503664c");
    let PA2 = hex!("
        533145987CB33CD2C8F5AC8A73C03A97FB31D2B89D02B1576CFC77BC97656FC040FCC7569750459EE753EBD69839692B375A
        0F53165B191CA8C6185B85626282C0A4AD63B36B6A289F661D505850832248D6F39084695C028B979835848931874E037EDF
        33CD9F1521E2B478BF0C37D859572AB08C20F7687749032949AB7457B66C1206C08A78C58633BA008E8770224700B84758B2
        2B290E9ED01F750439B00B97729960940817D3BA0CE7F10EB6A0C8EBD975C85A6299A6CE486132292189F9DCC13F27591870
        4192A417E7B305834323C354213195BAD0A5AA30A3980B028A1E116E97E74ED8D053A2FA51E00068BCD69D325246E93A30AD
        493D28099AF143016BE454413256A5DA144C9985C70664EE12013DF167E228B921EA3BAC494B5D5140581A4D7E7080B4C284
        A6DAA955366EAE3217541A0B1109313F7A1AE9305D55B45CB6A5B2F3321A10DB137E92306A3B2A25FC1999495F7A732D7CD8
        3BE0923050A5562A036699F92427CB71C0CA201D958F7A3171740AB477188DB276A52E576703493E289C14BF896D5A827586
        492D23B605CDC6932A4ABF902A219F88B12D0479C91B4EE6C586A4A2061FC22D66264772359B569456111574D84606CBA282
        92C37A40B81F5A113BB9E72871E14184270FE2A87C33BA7D01E95A578950D098C48A584428BAC781BA938F13BB80F4790EC3
        6F1A394FEC97AB80054F60A90DA86ABE7D84799A604233A5A495294D13805B6CF3505DB833E9F223D102AAA9E666580B088E
        1CBABC4CB52725CB768B5E990B89411AA652E06A2BDB937B185EB924C59AF6BA9BE2BA09409DB5C262D751731461A89AAC05
        ADACC320B6AFC5C4A5FDBB2F56B2483D11779C7117707B121D0B36362B2BF8D4B28F6948F5EB1D5E41B1C8A5053D581019C3
        6AC87988803CB934027909DC4C5BD1AE2EF451D9F7945209C0E9E60AF43C50DC98646F3BB13BE6491E91930D9AA1AA315FB3
        B1A067579565D170C4E888E9042751106B72A60470A69992508E8CE3101A602A22DA7FB1A744F09488E704481F649DAB6158
        E5306F573009EC63ACF11B549D280033343FC9750BB927B931B94F9C5475A2B803AF36CC3CC30521EA2A86040E03E7CF90B3
        6D2E370856285AE4523367482E68473CA500200F75C8C423C8AB93C7BFE74DF253AF97114A3FEAC1DDD34E06747C6B386990
        428100A99351BA14A3C19B1A7A6DA5A715F6A698E9FC330C13B98D61A2A85AC0E0896CC8032490B93FEB284703F21E6D1630
        7D7886F948752FE55CEE7291C06AA7BBB79146C644AEA7C2765C5EFA535B729158EB51BC2D4C389B970B30086966D858D51B
        78EF3829F9290DAF241C6D370425D83DDD61153DD2AC0FD206120434AD6792D60B2F084A2950AAC250B4001F309EA45B09D9
        DB440D6A2C9BB3B140569C51C985A2B0BE03ABA918C2311B11069FC9A0C762CCA59C1BDAE47C0406AF0CC7BBB1821C0F8733
        563ABBE896525E1156F7D593F55C39922B6B79E462CE587189247FA045CB19FA7256B960D0B25B7B364ECE250D43E19313C7
        98CE424634DC358A0914FAF33EA2B06EAA748947C6C150E54D7BD3A4C4873B117266145833FF04CAA96424AB678B49BA94D6
        619F01BBC62961850CF25765C7627910EF8E79F9B3749086AABF75407D7AC42748BC");
    let LB = hex!("0202030405060708090A0B0C0D0E0F14202030405060708090A0B0C0D0E0F14B");
    let PB1 =hex!("700C48F77F56584C5CC632CA65640DB91B6BACCE3A4DF6B42CE7CC838833D287DB71E509E3FD9B060DDB20BA5C51DCC5948D
        46FBF640DFE0441782CAB85FA4AC");
    let PB2 = hex!("CC1160B24F3AB56D7E3EEF460A2AD73D0E5B50BC5FD6E06D74C80DF6295A5E7FED8664C9B819ABB90BF1B2481CA3958EDE01
        9E5A8D215E3C3B2FC662E6A6E5F4D6CD36C30C747745FCD8F85560645EC010987B87A7B42E619F388FDBB9DF0B916A01AD06
        40A9B761A9353DE373033EC5E2D16B59DB508BA33259B9791691FE35B2F08AFF381BFC9A74E380DFAC915B6165ED8C276DC7
        112FD36B7C21710AC6A2201179642BACA216C3D4C39EA74E75A370B9ADE85A2AD8B00EADCC4AE2B3819374FDCE01F4AF0253
        5194B88933ECE5A9B90C1886EFBCF40B1505D4D2603F7FED815F3B101664A90B239FE598E90C09069E102C500912C71F5339
        6EA1C9035682C9ECB1627193FDEE803078E4CAB436B6CACE8A861AD95B5F53E6C9757EEDD7FC9EA369089E82D2D32C952094
        60BD880C7D856DD8BD589E131C991E1148B5E4139E7F4EE32B25DA676FCB279ED94D9B28B6C4843F07A93FADC1314869D2E2
        71D90D993E4F5B654157BDBF45215D691AFAECC498E9ADB3A798029C2D68665878634E02B34006BA953DB444203C88C4523B
        EDCA14358E0B129BC712EAB69D1C253C490DD4E5F751FBA1B38BA200A3E73E78299306855237C6F72B15598B2EAB30224A22
        C2C7883C6BEDE636C4D1C06ED0B6793E4609969CF8A442614C8C547598C26CC848BC4593E24591FC85F624548A1D01EA5BE0
        4892C5C12EC07F70C8CA51C4CCD1C9F061EE1BFE07112C2577552966EB25759E77882F1B5B327964E6269E36C1D5AC9C94B0
        1D891E1B3AC2660C5D99E32364AB31015986352ABB20A228C358A548D1B413FF534550F2EE0C80E0741B7F90DC22E8D701A4
        4514810820A5A1D5EE62173283F91DAB585615E36A520FD7540FF7E7B9D6F2FB616251F1D2B6A034AF6427E66D559D7E04F1
        C7C22FEFA5F3F7B256D7225D5F683FE29238754D66E10687290675202CD15A32A7F71B5750A95BFCC183D2C26BF31D41225C
        04FBC123683FA911B994C5B9AE5172EE9847356C67302E7C405625543B7FA82D9BE737467F7C000F97FFBB647500DE9EE36A
        266F97AE83AB58D239533C8A2FB440E649ACDF6EFC8D98BAF10A1BFA0F7681EC9708BAB9D00A78FFF74AA4C7099D6DA69FBE
        E2B7C5EA7CEB04527D01CA2CCA8416181BA450C2519A8F383881FF439DEDCE45BF0117CAC0A612E52AD1A3B2F2D1C9917264
        DD131813F3D9F6D2D574D6CE9AA0943AA7E84C9BDEC515B6827921366794FE6B9058769ADCB3A14593CA49A866DC7AF5BCAF
        2A48BB06271B3948CC64572AE3A9D46A1209D3E70A02D50AC3CB0AA1B820F8EA25DA127931406AAFC9B00C0FD90C75973215
        86694E35EA291A88665A2FFBAE5C9BE45938E60027C6C6DEB384F873457B5B5C7107651AE0273DF8A23FDFF74A2A6BD67703
        854FA5E115712E84D6726F27370FDE6390B362142FCD93647BD2D7A3927DE5F5040F60E17C39D1248F6662CF441EE4B2470C
        D412050CE09EC31075001286F401A58FE6217000D6A9C8BA753C4CE9D1D8CF8B908614DF0A81");
    let k1 = hex!("46FC62106420FF012E54A434FBDD2D25CCC5852060561E68040DD7778997BD7B");
    let k2 = hex!("D71BD5A07C158C130283EF854516D290A46ADE09A63831C7B83B8FD0724C8FB0");
    let context = b"ETSI_QSHKE_TEST_VECTORS_V_1_2";
    let label = hex!("1212233445566778899AABBCCDDEEFE5212233445566778899AABBCCDDEEFE5F");
    //MA = cid || len(LA)|| LA || len(PA1) || PA1 || len(PA2) || PA2
    //MB = cid || len(LB)|| LB || len(PB1) || PB1 || len(PB1) || PB2
    let key_material = hex!("1154D484AAB6231EE566F303C68B1EE1");


    let MA = message_format(&CID, &[&LA, &PA1, &PA2]);
    let MB = message_format(&CID, &[&LB, &PB1, &PB2]);

    let context_calc = concatenate(&[context, &MA, &MB] );

    println! ( "MA = {}", hex::encode(&MA));
    println! ( "MB = {}", hex::encode(&MB));
    println! ( "context={:02X?}", context_calc );

    let km_calc: Array<u8, U16> = Kmac128Kdf::derive_secrets_salt_others ( [label.as_slice()], b"KDF", [1u32.to_be_bytes().as_slice(), &k1, &k2, &context_calc]);

    println! ( "km_calc={:02X?}", km_calc);
    assert_eq!(km_calc, key_material);

    type EtsiHybrid<'a> = HybridKem<EcdhKem<NistP256, EcRaw2Encoder<NistP256>>, MlKem768, EtsiCatKdfCombiner</*Kmac128KdfStatic,*/ EtsiTestVectorsLabel, 0x7121, false>, U16>;

    let mut decapsulator = EtsiHybrid::try_from_slice_decap2(&[dA1.as_slice(), &dA2, &zA2].concat()).unwrap();
    decapsulator.set_kdf(EtsiCatKdfCombiner::new_with_labels(&LA, &LB));
    
    let km_calc2 = decapsulator.try_decapsulate(&[PB1.as_slice(), PB2.as_slice()].concat().try_into().unwrap()).unwrap();
    assert_eq!(km_calc2.as_slice(), key_material.as_slice());
}

// CatKdf using HKDF, ECDH with Curve25519 and ML-KEM 768
#[allow(non_snake_case)]
#[test]
fn test_d_2_4() 
{
    let CID = hex!("1721");
    let LA = hex!(" 0102030405060708090A0B0C0D0E0F1101020304050607081020304050607085");
    let dA1 = hex!("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
    let PA1 =  hex!("8520F0098930A754748B7DDCB43EF75A0DBF3A0D26381AF4EBA4A98EAA9B4E6A");
    let zA2 = hex!("a9f93c7b791356b66afcceb745a548c7f6b185e4f45ec1ff1a22acdd96e7a6d8");
    let dA2 = hex!("8d45a2ab49d8c20d4ab5680e5c9d9d0cc9ca8228484946f9afce5b8df6f39d19");
    let PA2 = hex!("06F51174F03C2FE07CC31B0659B87EBF124237811B88B980BC277F8C050B265CBEE1A4AE7145CB9253281BBC291F2808E065
        855FD91C7D14122C589FB21B45FD3B7FBB6562FD53006B565189EC983C7A0D4C21596EF3795AE22ECAD71F75395558B55220
        662BB66C389ED9AB6B784476E1788F34B28B59A4C6F71F9F6A49DA80C4D3107DB2C306968B5600E18285F8BFA293677F699F
        D2D2820DE490F530818D6667686A765FCC0009484D71629C1F148104B462325AC55EF34DD5C7098441A06757CA35C8ADFDAB
        6D36333310241F9970B1B123478DCBB75AE6CA39BB84FFCB23A593C24BC54E74B4086165BB4B10AE39F45447AA4EA5F55762
        386B11051B84B0A688C12C73336FC87164B7FBC7F0B07D2A51BB05560606D5558666CC322963AD3CA2BC1293260A94707770
        C030B2BC9C00477A8D5FF6737961480D48109F66075DA9C8AB516F70A78DA9E444AB65798A2565965A68AD9146FD9267D2A8
        0C4352A0A988157522046620A63D9BA7BBCCAFD50A61384453F8545845B25E7A05745C4B26EF7211200A916241047FDABB66
        936BB7351C04F5CD06A10AE3C459B74BB0CD85044BF8B6BF2B33294014B9D68517CB1A9813230BA08813807A2DFCC6A739B6
        AC79575F19BAB96A7CDED404D0E52508214AD43763A0A048FC36785B2C718F75B3432769C1D2A6240336A82B39D865739AF7
        8E94A92BD7B4703210297FB82E0BE57B97384DB5B24FFA5486C982AF48642D967222A28C6F83E5AD6A59CA486733808BA3BD
        86A780E59888011965A351CA949B0D6C72FB3BA0F867834D166819C252D9600207C88997318B2D204AC3619247A01829484F
        12BCA2E8F16AAC677C9E8AC209F9BCCF019BBDA66E8F073DFBD934E08CA15BE77576029654E049C1C20B1B123E5F0B501356
        28CD2C96A5D0B1EEF48FBE08AC4685247721B128F71DC748452B94A458F39B337BC2305CCC505BB18BF6ABE3EC2C825799B9
        5C13A1F6411CD3B031F3CEC3D99AFC1A28F2019C1BD129A2EA35F06415C8B717337957CAA964E794881257073FF5C12C3C62
        034861C343B7F70B9D475CCC10EA5889910E04CA7EAF0B762DB56962EC40CA47CEB4D228600595CF22421148CF02B4CFCE76
        AD27701F925C01C71C5405534ED54B0100C280DD861D89E967BED4829C568BB76CA500342803835F7983179CDA15899033F7
        97951031138A83669AB4CCB4630058088AA0845FAF7B0761B405AE866C426711EB152889D175E7B20DA03126B7419A766416
        A68AAC0FBC355DA07D6E6339BC0539CEB55711F633B8C7392627497821CB9D7174C4E655B5928BF722C84B8233A0993B6DE0
        2D7364443EA4C73A754B8190243DF936184819E1B8AB6F0B0BFBAC6C47E66DDF11757BE55E0787ADC112C63E644D1B904877
        764D856ABE78B583600CBB2119CB916C689D4543F4D553CAC33AD19B245B4948EF0BA3E7D1151179B9FB2941F3674E5F8771
        677737C435B2383119A3E75434114439506E1B9145FF16B1458879A1039962434151619B77915D033A3FAB7385FE861E4A25
        B125A205C3F1B16972470B2791534B5FB8731B20C03684CCBEB97A1FA4417655BB485C347519710522C357D50C43FC264409
        8533FE549C825F5DC8CA82A0DD908891BB4F92EAAB51CBE036CD6FB59A749269A0A3");
    let LB = hex!("202030405060708090A0B0C0D0E0F100202030405060708E020304050607080C");
    let PB1 =  hex!("DE9EDB7D7B7DC1B4D35B61C2ECE435373F8343C85B78674DADFC7E146F882B4F");
    let PB2 = hex!("DB3D4F38A49CC5C1C7766573873F3926184923F570FCDBA6D7086BEA39601FADFEBABB2F9ED0EBD86A6468BE03D3B05713DE
        50B5E5D58FFDB5500F2AF7419682BC7857870D1E624C2B48A7E0D30A91F141F0764014FBED12A9F72C958EB53A7ED4A16825
        78B4348A05C183C790FF56D66B23BD601FB372C771F52045E13CA2D6DAB80A165A2159B8F990B5BBF125883DEC0A2AF4A54C
        3F386DE4DF6EE96923E9BB2551753DDC6D1F00D7EE910835082C6260974D11FBA49951DB2E27B47362EC4EBF804327AD9682
        01EDB71BDC8C32887214FB2AAA842AABBE0A4E03FDC695B19610377B9BEA9D371016674E977E9E45382D236365EFEDF56665
        9F9936D9D14CA8595DDF121AE7ACC6056DD6FE1B58DC0F0B23CF5366D2488C4D6361B09875242B3A39374159CF3654ABD25F
        8B080BAE117A5F77D15031AD8B350C6922FFD426EC9F9F80A1918FE722CB7A4B537210EF8A5538A52048BADCE3CAF5C46454
        EEAF413819D57EFBA834D7017F9343B302679A0A28F532E93FE8C5B6AEC3C42C160A3FAD20FA2ABADD29C2564DB59FA25A11
        CA502D11421F7F080A616F9656942932E11BFDCC47B1D8EFFA81D724FFABF4613830631737EB7E52DA78A6B026DB1C4FB80B
        BF2D8F9393875330B2F9C1A124436028BF2624C1E64797ABE2E526967DD99BC21B555A5833A31ACE7969E3ECC64C1697DEC0
        B074108F6B17EFA2A517923B435D8446043FB1A96B2EF3B3D3952F08657997D1D9169FFD14316185EC30457E0FAF7EBA2B5A
        02A01993EC530BB9C44C091D2E9D9BC82951E577D76DC2757F2E04E822B6A29F840887A297202E7389A0999F9E69255DE0A3
        3AEB8CD0B21B7F3B5AA7BFD864CF8FF4FFE78FFF166CAF1B805464D5E4B60EB0277E3BA4F3F3390640F5F16E0B784CC8A679
        40977B2F0202D37A74472161589A7B9E7721CC532904A17AFF8FA86ECDC46A410BD6F9309B2CC310D7941A02A5720CD64241
        B5C13C78A86010805AC74C3B81D83348C63C410451BD2052CE764DA83CF80B2654CB1D033F259DA36039E4DF1A5C4CE3F861
        3E28CFC2B25EAE2A21B425B44D0C998977B3ADF5156BFCA1E357EC3F6B5805B2CDC4D46A4C83154AEF0F50D493BAB0BBCA13
        0E92CA21AF8BDF817F7616B55C4C24C066EBF896F39A7BF50A241561E578BDD931CB07EADD193986C455F8798AB97B8D732D
        37C796E09C1C7ABB978BF666CED961373198607AC355FCF6903B4F3047A1D97C344A2D8B73DB310769CCFB4AE3DA6C4E82DE
        B83BF4060722D9E5A9AFBD3E03B4517E3B7D563F31821D5D8EF7F06F0D92A9F401EA9BEFD52CA8DB331360E603C14A340B80
        6155DE690CD2D92EE6A8EE53BCEED7EEB308D375518C851C109A03EE61960D6CD7CD1FDEE5CC2A401039A15EE4F97A734008
        01A090FBF09BE42119662D06C3FF8217FCFC2C70CDE6E1C2F9A396A2E08A3C22AE3CE90A5C97C9F69EBC1546898A047C9DCA
        D128003A90B29B62F7B093CC90C9CD38104C1A3CE62BEA6A3646EF7E3B9FB7C4C44E78FF650C");
    let k1 = hex!(" 4A5D9D5BA4CE2DE1728E3BF480350F25E07E21C947D19E3376F09B3C1E161742");
    let k2 = hex!("E3E4F4E9D4F5C9AE03836BB9266C50B033285ACE9BC56F73817CE19679D1429A");
    let context = "ETSI_QSHKE_TEST_VECTORS_V_1_2";
    let label = /*LA ^ LB =*/ hex!("212233445566778899AABBCCDDEEFE1121223344556677861223344556677889");
    //MA = cid || len(LA)|| LA || len(PA1) || PA1 || len(PA2) || PA2
//  MB = cid || len(LB)|| LB || len(PB1) || PB1 || len(PB2) || PB2
    let key_material = hex!("701675524E4986A391AFEFBB604AA63D");

    let prvA1 = x25519_dalek::StaticSecret::from(dA1);
    let pubA2 = x25519_dalek::PublicKey::from(&prvA1);
    assert_eq!(pubA2.as_bytes(), &PA1);

    let (d,e) = X25519Kem::from_seed(&dA1.into());

    //println! ( "{:02X?}", e.as_bytes());
    assert_eq! ( e.to_bytes().as_slice(), &PA1);    // Verify public key for ECDH

    let k_calc = d.try_decapsulate(&PB1.into()).unwrap();
    assert_eq! ( k1, k_calc);
    //assert_eq! ( k2, k_calc[32..]);

    //let (prv1, pub2) = ml_kem::MlKem768::generate_deterministic(&dA2.into(), &zA2.into());
    let prv1 = ml_kem::ml_kem_768::DecapsulationKey::from_seed([dA2, zA2].concat().try_into().unwrap());
    let pub2 = prv1.encapsulation_key();
    assert_eq!( pub2.to_bytes(), PA2);  // Verify public key ML-KEM 768

    let k2_calc = prv1.decapsulate(&PB2.into());
    assert_eq!(k2_calc, k2);

    let MA = message_format(&CID, &[&LA, &PA1, &PA2]);
    println! ( "MA = {}", hex::encode(&MA));

    let MB = message_format(&CID, &[&LB, &PB1, &PB2]);
    println! ( "MB = {}", hex::encode(&MB));
    
    let context_calc = concatenate_and_hash(&[context.as_bytes(), &MA, &MB]);
    println! ( "context = {}", hex::encode(&context_calc));

    let km_calc: kems::Array<u8, U16> = Hkdf::<Sha256>::derive_secrets_salt_others([k1.as_slice(),k2.as_slice()], &label, [context_calc.as_slice() ]);
    println! ( "km_calc={:02X?}", km_calc);
    assert_eq!(km_calc, key_material);

    type EtsiHybrid = HybridKem<X25519Kem, MlKem768, EtsiCatKdfCombiner</*Hkdf<Sha256>,*/ EtsiTestVectorsLabel, 0x1721, true>, U16>;
    let mut decapsulator = EtsiHybrid::try_from_slice_decap2(&[dA1.as_slice(), &dA2, &zA2].concat()).unwrap();
    decapsulator.set_kdf(EtsiCatKdfCombiner::new_with_labels(&LA, &LB));

    let km_calc2 = decapsulator.try_decapsulate(&[PB1.as_slice(), PB2.as_slice()].concat().try_into().unwrap()).unwrap();
    assert_eq!(km_calc2.as_slice(), key_material.as_slice());
}

// CatKdf using HMAC, ECDH with Curve25519 and ML-KEM 768
#[allow(non_snake_case)]
#[test]
fn test_d_2_5()
{
    let CID = hex!("4721");
    let LA = hex!("0102030405060708090A0B0C0D0E0F1101020304050607081020304050607085");
    let dA1 = hex!("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
    let PA1 = hex!("8520F0098930A754748B7DDCB43EF75A0DBF3A0D26381AF4EBA4A98EAA9B4E6A");
    let zA2 = hex!("a9f93c7b791356b66afcceb745a548c7f6b185e4f45ec1ff1a22acdd96e7a6d8");
    let dA2 = hex!("8d45a2ab49d8c20d4ab5680e5c9d9d0cc9ca8228484946f9afce5b8df6f39d19");
    let PA2 = hex!("06F51174F03C2FE07CC31B0659B87EBF124237811B88B980BC277F8C050B265CBEE1A4AE7145CB9253281BBC291F2808E065
        855FD91C7D14122C589FB21B45FD3B7FBB6562FD53006B565189EC983C7A0D4C21596EF3795AE22ECAD71F75395558B55220
        662BB66C389ED9AB6B784476E1788F34B28B59A4C6F71F9F6A49DA80C4D3107DB2C306968B5600E18285F8BFA293677F699F
        D2D2820DE490F530818D6667686A765FCC0009484D71629C1F148104B462325AC55EF34DD5C7098441A06757CA35C8ADFDAB
        6D36333310241F9970B1B123478DCBB75AE6CA39BB84FFCB23A593C24BC54E74B4086165BB4B10AE39F45447AA4EA5F55762
        386B11051B84B0A688C12C73336FC87164B7FBC7F0B07D2A51BB05560606D5558666CC322963AD3CA2BC1293260A94707770
        C030B2BC9C00477A8D5FF6737961480D48109F66075DA9C8AB516F70A78DA9E444AB65798A2565965A68AD9146FD9267D2A8
        0C4352A0A988157522046620A63D9BA7BBCCAFD50A61384453F8545845B25E7A05745C4B26EF7211200A916241047FDABB66
        936BB7351C04F5CD06A10AE3C459B74BB0CD85044BF8B6BF2B33294014B9D68517CB1A9813230BA08813807A2DFCC6A739B6
        AC79575F19BAB96A7CDED404D0E52508214AD43763A0A048FC36785B2C718F75B3432769C1D2A6240336A82B39D865739AF7
        8E94A92BD7B4703210297FB82E0BE57B97384DB5B24FFA5486C982AF48642D967222A28C6F83E5AD6A59CA486733808BA3BD
        86A780E59888011965A351CA949B0D6C72FB3BA0F867834D166819C252D9600207C88997318B2D204AC3619247A01829484F
        12BCA2E8F16AAC677C9E8AC209F9BCCF019BBDA66E8F073DFBD934E08CA15BE77576029654E049C1C20B1B123E5F0B501356
        28CD2C96A5D0B1EEF48FBE08AC4685247721B128F71DC748452B94A458F39B337BC2305CCC505BB18BF6ABE3EC2C825799B9
        5C13A1F6411CD3B031F3CEC3D99AFC1A28F2019C1BD129A2EA35F06415C8B717337957CAA964E794881257073FF5C12C3C62
        034861C343B7F70B9D475CCC10EA5889910E04CA7EAF0B762DB56962EC40CA47CEB4D228600595CF22421148CF02B4CFCE76
        AD27701F925C01C71C5405534ED54B0100C280DD861D89E967BED4829C568BB76CA500342803835F7983179CDA15899033F7
        97951031138A83669AB4CCB4630058088AA0845FAF7B0761B405AE866C426711EB152889D175E7B20DA03126B7419A766416
        A68AAC0FBC355DA07D6E6339BC0539CEB55711F633B8C7392627497821CB9D7174C4E655B5928BF722C84B8233A0993B6DE0
        2D7364443EA4C73A754B8190243DF936184819E1B8AB6F0B0BFBAC6C47E66DDF11757BE55E0787ADC112C63E644D1B904877
        764D856ABE78B583600CBB2119CB916C689D4543F4D553CAC33AD19B245B4948EF0BA3E7D1151179B9FB2941F3674E5F8771
        677737C435B2383119A3E75434114439506E1B9145FF16B1458879A1039962434151619B77915D033A3FAB7385FE861E4A25
        B125A205C3F1B16972470B2791534B5FB8731B20C03684CCBEB97A1FA4417655BB485C347519710522C357D50C43FC264409
        8533FE549C825F5DC8CA82A0DD908891BB4F92EAAB51CBE036CD6FB59A749269A0A3");
    let LB = hex!("202030405060708090A0B0C0D0E0F100202030405060708E020304050607080C");
    let PB1 = hex!("DE9EDB7D7B7DC1B4D35B61C2ECE435373F8343C85B78674DADFC7E146F882B4F");
    let PB2 = hex!("DB3D4F38A49CC5C1C7766573873F3926184923F570FCDBA6D7086BEA39601FADFEBABB2F9ED0EBD86A6468BE03D3B05713DE
        50B5E5D58FFDB5500F2AF7419682BC7857870D1E624C2B48A7E0D30A91F141F0764014FBED12A9F72C958EB53A7ED4A16825
        78B4348A05C183C790FF56D66B23BD601FB372C771F52045E13CA2D6DAB80A165A2159B8F990B5BBF125883DEC0A2AF4A54C
        3F386DE4DF6EE96923E9BB2551753DDC6D1F00D7EE910835082C6260974D11FBA49951DB2E27B47362EC4EBF804327AD9682
        01EDB71BDC8C32887214FB2AAA842AABBE0A4E03FDC695B19610377B9BEA9D371016674E977E9E45382D236365EFEDF56665
        9F9936D9D14CA8595DDF121AE7ACC6056DD6FE1B58DC0F0B23CF5366D2488C4D6361B09875242B3A39374159CF3654ABD25F
        8B080BAE117A5F77D15031AD8B350C6922FFD426EC9F9F80A1918FE722CB7A4B537210EF8A5538A52048BADCE3CAF5C46454
        EEAF413819D57EFBA834D7017F9343B302679A0A28F532E93FE8C5B6AEC3C42C160A3FAD20FA2ABADD29C2564DB59FA25A11
        CA502D11421F7F080A616F9656942932E11BFDCC47B1D8EFFA81D724FFABF4613830631737EB7E52DA78A6B026DB1C4FB80B
        BF2D8F9393875330B2F9C1A124436028BF2624C1E64797ABE2E526967DD99BC21B555A5833A31ACE7969E3ECC64C1697DEC0
        B074108F6B17EFA2A517923B435D8446043FB1A96B2EF3B3D3952F08657997D1D9169FFD14316185EC30457E0FAF7EBA2B5A
        02A01993EC530BB9C44C091D2E9D9BC82951E577D76DC2757F2E04E822B6A29F840887A297202E7389A0999F9E69255DE0A3
        3AEB8CD0B21B7F3B5AA7BFD864CF8FF4FFE78FFF166CAF1B805464D5E4B60EB0277E3BA4F3F3390640F5F16E0B784CC8A679
        40977B2F0202D37A74472161589A7B9E7721CC532904A17AFF8FA86ECDC46A410BD6F9309B2CC310D7941A02A5720CD64241
        B5C13C78A86010805AC74C3B81D83348C63C410451BD2052CE764DA83CF80B2654CB1D033F259DA36039E4DF1A5C4CE3F861
        3E28CFC2B25EAE2A21B425B44D0C998977B3ADF5156BFCA1E357EC3F6B5805B2CDC4D46A4C83154AEF0F50D493BAB0BBCA13
        0E92CA21AF8BDF817F7616B55C4C24C066EBF896F39A7BF50A241561E578BDD931CB07EADD193986C455F8798AB97B8D732D
        37C796E09C1C7ABB978BF666CED961373198607AC355FCF6903B4F3047A1D97C344A2D8B73DB310769CCFB4AE3DA6C4E82DE
        B83BF4060722D9E5A9AFBD3E03B4517E3B7D563F31821D5D8EF7F06F0D92A9F401EA9BEFD52CA8DB331360E603C14A340B80
        6155DE690CD2D92EE6A8EE53BCEED7EEB308D375518C851C109A03EE61960D6CD7CD1FDEE5CC2A401039A15EE4F97A734008
        01A090FBF09BE42119662D06C3FF8217FCFC2C70CDE6E1C2F9A396A2E08A3C22AE3CE90A5C97C9F69EBC1546898A047C9DCA
        D128003A90B29B62F7B093CC90C9CD38104C1A3CE62BEA6A3646EF7E3B9FB7C4C44E78FF650C");
    let k1 = hex!("4A5D9D5BA4CE2DE1728E3BF480350F25E07E21C947D19E3376F09B3C1E161742");
    let k2 = hex!("E3E4F4E9D4F5C9AE03836BB9266C50B033285ACE9BC56F73817CE19679D1429A");
    let context = "ETSI_QSHKE_TEST_VECTORS_V_1_2";
    let label = /*LA ^ LB =*/ hex!("212233445566778899AABBCCDDEEFE1121223344556677861223344556677889");
    //MA = cid || len(LA)|| LA || len(PA1) || PA1 || len(PA2) || PA2
    //MB = cid || len(LB)|| LB || len(PB1) || PB1 || len(PB2) || PB2
    let key_material = hex!("56617E0EC39843C6E41935F02A5D7FFD");

    let prvA1 = x25519_dalek::StaticSecret::from(dA1);
    let pubA2 = x25519_dalek::PublicKey::from(&prvA1);
    assert_eq!(pubA2.as_bytes(), &PA1);

    let (d,e) = X25519Kem::from_seed(&dA1.into());

    //println! ( "{:02X?}", e.as_bytes());
    assert_eq! ( e.to_bytes().as_slice(), &PA1);    // Verify public key for ECDH

    let k_calc = d.try_decapsulate(&PB1.into()).unwrap();
    assert_eq! ( k1, k_calc);
    //assert_eq! ( k2, k_calc[32..]);

    //let (prv1, pub2) = ml_kem::MlKem768::generate_deterministic(&dA2.into(), &zA2.into());
    let prv1 = ml_kem::ml_kem_768::DecapsulationKey::from_seed([dA2, zA2].concat().try_into().unwrap());
    let pub2 = prv1.encapsulation_key();
    assert_eq!( pub2.to_bytes(), PA2);  // Verify public key ML-KEM 768

    let k2_calc = prv1.decapsulate(&PB2.into());
    assert_eq!(k2_calc, k2);

    let MA = message_format(&CID, &[&LA, &PA1, &PA2]);
    println! ( "MA = {}", hex::encode(&MA));

    let MB = message_format(&CID, &[&LB, &PB1, &PB2]);
    println! ( "MB = {}", hex::encode(&MB));
    
    let context_calc = concatenate_and_hash(&[context.as_bytes(), &MA, &MB]);
    println! ( "context = {}", hex::encode(&context_calc));

    let km_calc: kems::Array<u8, U16> = SskdfMac::<HmacReset<Sha256>>::derive_secrets_salt_others([k1.as_slice(),k2.as_slice()], &label, [context_calc.as_slice() ]);
    println! ( "km_calc={:02X?}", km_calc);
    assert_eq!(km_calc, key_material);

    type EtsiHybrid = HybridKem<X25519Kem, MlKem768, EtsiCatKdfCombiner</*SskdfMac::<HmacReset<Sha256>>,*/ EtsiTestVectorsLabel, 0x4721, true>, U16>;
    let mut decapsulator = EtsiHybrid::try_from_slice_decap2(&[dA1.as_slice(), &dA2, &zA2].concat()).unwrap();
    decapsulator.set_kdf(EtsiCatKdfCombiner::new_with_labels(&LA, &LB));

    let km_calc2 = decapsulator.try_decapsulate(&[PB1.as_slice(), PB2.as_slice()].concat().try_into().unwrap()).unwrap();
    assert_eq!(km_calc2.as_slice(), key_material.as_slice());
}


// CatKdf using KMAC128, ECDH with Curve25519 and ML-KEM 768
#[allow(non_snake_case)]
#[test]
fn test_d_2_6()
{
    let CID = hex!("7721");
    let LA = hex!("0102030405060708090A0B0C0D0E0F1101020304050607081020304050607085");
    let dA1 = hex!("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
    let PA1 = hex!("8520F0098930A754748B7DDCB43EF75A0DBF3A0D26381AF4EBA4A98EAA9B4E6A");
    let zA2 = hex!("a9f93c7b791356b66afcceb745a548c7f6b185e4f45ec1ff1a22acdd96e7a6d8");
    let dA2 = hex!("8d45a2ab49d8c20d4ab5680e5c9d9d0cc9ca8228484946f9afce5b8df6f39d19");
    let PA2 =hex!("06F51174F03C2FE07CC31B0659B87EBF124237811B88B980BC277F8C050B265CBEE1A4AE7145CB9253281BBC291F2808E065
        855FD91C7D14122C589FB21B45FD3B7FBB6562FD53006B565189EC983C7A0D4C21596EF3795AE22ECAD71F75395558B55220
        662BB66C389ED9AB6B784476E1788F34B28B59A4C6F71F9F6A49DA80C4D3107DB2C306968B5600E18285F8BFA293677F699F
        D2D2820DE490F530818D6667686A765FCC0009484D71629C1F148104B462325AC55EF34DD5C7098441A06757CA35C8ADFDAB
        6D36333310241F9970B1B123478DCBB75AE6CA39BB84FFCB23A593C24BC54E74B4086165BB4B10AE39F45447AA4EA5F55762
        386B11051B84B0A688C12C73336FC87164B7FBC7F0B07D2A51BB05560606D5558666CC322963AD3CA2BC1293260A94707770
        C030B2BC9C00477A8D5FF6737961480D48109F66075DA9C8AB516F70A78DA9E444AB65798A2565965A68AD9146FD9267D2A8
        0C4352A0A988157522046620A63D9BA7BBCCAFD50A61384453F8545845B25E7A05745C4B26EF7211200A916241047FDABB66
        936BB7351C04F5CD06A10AE3C459B74BB0CD85044BF8B6BF2B33294014B9D68517CB1A9813230BA08813807A2DFCC6A739B6
        AC79575F19BAB96A7CDED404D0E52508214AD43763A0A048FC36785B2C718F75B3432769C1D2A6240336A82B39D865739AF7
        8E94A92BD7B4703210297FB82E0BE57B97384DB5B24FFA5486C982AF48642D967222A28C6F83E5AD6A59CA486733808BA3BD
        86A780E59888011965A351CA949B0D6C72FB3BA0F867834D166819C252D9600207C88997318B2D204AC3619247A01829484F
        12BCA2E8F16AAC677C9E8AC209F9BCCF019BBDA66E8F073DFBD934E08CA15BE77576029654E049C1C20B1B123E5F0B501356
        28CD2C96A5D0B1EEF48FBE08AC4685247721B128F71DC748452B94A458F39B337BC2305CCC505BB18BF6ABE3EC2C825799B9
        5C13A1F6411CD3B031F3CEC3D99AFC1A28F2019C1BD129A2EA35F06415C8B717337957CAA964E794881257073FF5C12C3C62
        034861C343B7F70B9D475CCC10EA5889910E04CA7EAF0B762DB56962EC40CA47CEB4D228600595CF22421148CF02B4CFCE76
        AD27701F925C01C71C5405534ED54B0100C280DD861D89E967BED4829C568BB76CA500342803835F7983179CDA15899033F7
        97951031138A83669AB4CCB4630058088AA0845FAF7B0761B405AE866C426711EB152889D175E7B20DA03126B7419A766416
        A68AAC0FBC355DA07D6E6339BC0539CEB55711F633B8C7392627497821CB9D7174C4E655B5928BF722C84B8233A0993B6DE0
        2D7364443EA4C73A754B8190243DF936184819E1B8AB6F0B0BFBAC6C47E66DDF11757BE55E0787ADC112C63E644D1B904877
        764D856ABE78B583600CBB2119CB916C689D4543F4D553CAC33AD19B245B4948EF0BA3E7D1151179B9FB2941F3674E5F8771
        677737C435B2383119A3E75434114439506E1B9145FF16B1458879A1039962434151619B77915D033A3FAB7385FE861E4A25
        B125A205C3F1B16972470B2791534B5FB8731B20C03684CCBEB97A1FA4417655BB485C347519710522C357D50C43FC264409
        8533FE549C825F5DC8CA82A0DD908891BB4F92EAAB51CBE036CD6FB59A749269A0A3");
    let LB = hex!("202030405060708090A0B0C0D0E0F100202030405060708E020304050607080C");
    let PB1 = hex!("DE9EDB7D7B7DC1B4D35B61C2ECE435373F8343C85B78674DADFC7E146F882B4F");
    let PB2 = hex!("
    DB3D4F38A49CC5C1C7766573873F3926184923F570FCDBA6D7086BEA39601FADFEBABB2F9ED0EBD86A6468BE03D3B05713DE
    50B5E5D58FFDB5500F2AF7419682BC7857870D1E624C2B48A7E0D30A91F141F0764014FBED12A9F72C958EB53A7ED4A16825
    78B4348A05C183C790FF56D66B23BD601FB372C771F52045E13CA2D6DAB80A165A2159B8F990B5BBF125883DEC0A2AF4A54C
    3F386DE4DF6EE96923E9BB2551753DDC6D1F00D7EE910835082C6260974D11FBA49951DB2E27B47362EC4EBF804327AD9682
    01EDB71BDC8C32887214FB2AAA842AABBE0A4E03FDC695B19610377B9BEA9D371016674E977E9E45382D236365EFEDF56665
    9F9936D9D14CA8595DDF121AE7ACC6056DD6FE1B58DC0F0B23CF5366D2488C4D6361B09875242B3A39374159CF3654ABD25F
    8B080BAE117A5F77D15031AD8B350C6922FFD426EC9F9F80A1918FE722CB7A4B537210EF8A5538A52048BADCE3CAF5C46454
    EEAF413819D57EFBA834D7017F9343B302679A0A28F532E93FE8C5B6AEC3C42C160A3FAD20FA2ABADD29C2564DB59FA25A11
    CA502D11421F7F080A616F9656942932E11BFDCC47B1D8EFFA81D724FFABF4613830631737EB7E52DA78A6B026DB1C4FB80B
    BF2D8F9393875330B2F9C1A124436028BF2624C1E64797ABE2E526967DD99BC21B555A5833A31ACE7969E3ECC64C1697DEC0
    B074108F6B17EFA2A517923B435D8446043FB1A96B2EF3B3D3952F08657997D1D9169FFD14316185EC30457E0FAF7EBA2B5A
    02A01993EC530BB9C44C091D2E9D9BC82951E577D76DC2757F2E04E822B6A29F840887A297202E7389A0999F9E69255DE0A3
    3AEB8CD0B21B7F3B5AA7BFD864CF8FF4FFE78FFF166CAF1B805464D5E4B60EB0277E3BA4F3F3390640F5F16E0B784CC8A679
    40977B2F0202D37A74472161589A7B9E7721CC532904A17AFF8FA86ECDC46A410BD6F9309B2CC310D7941A02A5720CD64241
    B5C13C78A86010805AC74C3B81D83348C63C410451BD2052CE764DA83CF80B2654CB1D033F259DA36039E4DF1A5C4CE3F861
    3E28CFC2B25EAE2A21B425B44D0C998977B3ADF5156BFCA1E357EC3F6B5805B2CDC4D46A4C83154AEF0F50D493BAB0BBCA13
    0E92CA21AF8BDF817F7616B55C4C24C066EBF896F39A7BF50A241561E578BDD931CB07EADD193986C455F8798AB97B8D732D
    37C796E09C1C7ABB978BF666CED961373198607AC355FCF6903B4F3047A1D97C344A2D8B73DB310769CCFB4AE3DA6C4E82DE
    B83BF4060722D9E5A9AFBD3E03B4517E3B7D563F31821D5D8EF7F06F0D92A9F401EA9BEFD52CA8DB331360E603C14A340B80
    6155DE690CD2D92EE6A8EE53BCEED7EEB308D375518C851C109A03EE61960D6CD7CD1FDEE5CC2A401039A15EE4F97A734008
    01A090FBF09BE42119662D06C3FF8217FCFC2C70CDE6E1C2F9A396A2E08A3C22AE3CE90A5C97C9F69EBC1546898A047C9DCA
    D128003A90B29B62F7B093CC90C9CD38104C1A3CE62BEA6A3646EF7E3B9FB7C4C44E78FF650C");
    let k1 = hex!("4A5D9D5BA4CE2DE1728E3BF480350F25E07E21C947D19E3376F09B3C1E161742");
    let k2 = hex!("E3E4F4E9D4F5C9AE03836BB9266C50B033285ACE9BC56F73817CE19679D1429A");
    let context = b"ETSI_QSHKE_TEST_VECTORS_V_1_2";
    let label = /*LA ^ LB*/ hex!("212233445566778899AABBCCDDEEFE1121223344556677861223344556677889");
    //MA = cid || len(LA)|| LA || len(PA1) || PA1 || len(PA2) || PA2
    //MB = cid || len(LB)|| LB || len(PB1) || PB1 || len(PB1) || PB2
    let key_material = hex!("1B697069B3382C389E30ED03D59D2BAA");

    let MA = message_format(&CID, &[&LA, &PA1, &PA2]);
    let MB = message_format(&CID, &[&LB, &PB1, &PB2]);

    let context_calc = concatenate(&[context, &MA, &MB] );

    println! ( "MA = {}", hex::encode(&MA));
    println! ( "MB = {}", hex::encode(&MB));
    println! ( "context={:02X?}", context_calc );

    let km_calc: Array<u8, U16> = Kmac128Kdf::derive_secrets_salt_others ( [label.as_slice()], b"KDF", [1u32.to_be_bytes().as_slice(), &k1, &k2, &context_calc]);

    println! ( "km_calc={:02X?}", km_calc);
    assert_eq!(km_calc, key_material);

    type EtsiHybrid = HybridKem<X25519Kem, MlKem768, EtsiCatKdfCombiner</*Kmac128KdfStatic,*/ EtsiTestVectorsLabel, 0x7721, false>, U16>;

    let mut decapsulator = EtsiHybrid::try_from_slice_decap2(&[dA1.as_slice(), &dA2, &zA2].concat()).unwrap();
    decapsulator.set_kdf(EtsiCatKdfCombiner::new_with_labels(&LA, &LB));
    
    let km_calc2 = decapsulator.try_decapsulate(&[PB1.as_slice(), PB2.as_slice()].concat().try_into().unwrap()).unwrap();
    assert_eq!(km_calc2.as_slice(), key_material.as_slice());
}






// CasKDF with HKDF with SHA256, ECDH with NIST P-256 and ML-KEM 768
#[allow(non_snake_case)]
#[test]
fn test_d_3_1()
{
    let CID = hex!("1122");
    let LA1 = hex!("10102030405060708090A0B0C0D0E0F10102030405060708090A0B0C0D0E0F14");
    let PA1 = hex!("EAD218590119E8876B29146FF89CA61770C4EDBBF97D38CE385ED281D8A6B23028AF61281FD35E2FA7002523ACC85A429CB0
        6EE6648325389F59EDFCE1405141");
    let dA1 = hex!("7d7dc5f71eb29ddaf80d6214632eeae03d9058af1fb6d22ed80badb62bc1a534");
    let LB1 = hex!("0202030405060708090A0B0C0D0E0F14202030405060708090A0B0C0D0E0F14B");
    let PB1 = hex!("700C48F77F56584C5CC632CA65640DB91B6BACCE3A4DF6B42CE7CC838833D287DB71E509E3FD9B060DDB20BA5C51DCC5948D
        46FBF640DFE0441782CAB85FA4AC");
    //previous_chain_secret = psk = <NULL>
    let k1 = hex!("46FC62106420FF012E54A434FBDD2D25CCC5852060561E68040DD7778997BD7B");
    let context = b"ETSI_QSHKE_TEST_VECTORS_V_1_2";
    let label1 = /*LA1 ^ LB1*/ hex!("1212233445566778899AABBCCDDEEFE5212233445566778899AABBCCDDEEFE5F");
    //let MA1 = cid || len(LA1) || LA1 || len(PA1) || PA1
    //let MB1 = cid || len(LB1) || LB1 || len(PB1) || PB1
    let chain_secret1 = hex!("DA1B0A9081A422C6510559DA924B25AFFDAC9DC19C100FDDA1C2D825695C125D");
    let key_material1 = hex!("49A376AEA4059C01DB384944659F82E2");
    let LA2 = hex!("3102030405060708090A0B0C0D0E0F110102030405060708090A0B0C0D0E0F30");
    let zA2 = hex!("b585d4eb01085111a172a87688d0032e3381a9e9a35fdd6ef2f8aeb3b40eb5ce");
    let dA2 = hex!("89b0c4b23019af3498a27da290892d981dd59fa08993bc05da21e1d72503664c");
    let PA2 = hex!("533145987CB33CD2C8F5AC8A73C03A97FB31D2B89D02B1576CFC77BC97656FC040FCC7569750459EE753EBD69839692B375A
        0F53165B191CA8C6185B85626282C0A4AD63B36B6A289F661D505850832248D6F39084695C028B979835848931874E037EDF
        33CD9F1521E2B478BF0C37D859572AB08C20F7687749032949AB7457B66C1206C08A78C58633BA008E8770224700B84758B2
        2B290E9ED01F750439B00B97729960940817D3BA0CE7F10EB6A0C8EBD975C85A6299A6CE486132292189F9DCC13F27591870
        4192A417E7B305834323C354213195BAD0A5AA30A3980B028A1E116E97E74ED8D053A2FA51E00068BCD69D325246E93A30AD
        493D28099AF143016BE454413256A5DA144C9985C70664EE12013DF167E228B921EA3BAC494B5D5140581A4D7E7080B4C284
        A6DAA955366EAE3217541A0B1109313F7A1AE9305D55B45CB6A5B2F3321A10DB137E92306A3B2A25FC1999495F7A732D7CD8
        3BE0923050A5562A036699F92427CB71C0CA201D958F7A3171740AB477188DB276A52E576703493E289C14BF896D5A827586
        492D23B605CDC6932A4ABF902A219F88B12D0479C91B4EE6C586A4A2061FC22D66264772359B569456111574D84606CBA282
        92C37A40B81F5A113BB9E72871E14184270FE2A87C33BA7D01E95A578950D098C48A584428BAC781BA938F13BB80F4790EC3
        6F1A394FEC97AB80054F60A90DA86ABE7D84799A604233A5A495294D13805B6CF3505DB833E9F223D102AAA9E666580B088E
        1CBABC4CB52725CB768B5E990B89411AA652E06A2BDB937B185EB924C59AF6BA9BE2BA09409DB5C262D751731461A89AAC05
        ADACC320B6AFC5C4A5FDBB2F56B2483D11779C7117707B121D0B36362B2BF8D4B28F6948F5EB1D5E41B1C8A5053D581019C3
        6AC87988803CB934027909DC4C5BD1AE2EF451D9F7945209C0E9E60AF43C50DC98646F3BB13BE6491E91930D9AA1AA315FB3
        B1A067579565D170C4E888E9042751106B72A60470A69992508E8CE3101A602A22DA7FB1A744F09488E704481F649DAB6158
        E5306F573009EC63ACF11B549D280033343FC9750BB927B931B94F9C5475A2B803AF36CC3CC30521EA2A86040E03E7CF90B3
        6D2E370856285AE4523367482E68473CA500200F75C8C423C8AB93C7BFE74DF253AF97114A3FEAC1DDD34E06747C6B386990
        428100A99351BA14A3C19B1A7A6DA5A715F6A698E9FC330C13B98D61A2A85AC0E0896CC8032490B93FEB284703F21E6D1630
        7D7886F948752FE55CEE7291C06AA7BBB79146C644AEA7C2765C5EFA535B729158EB51BC2D4C389B970B30086966D858D51B
        78EF3829F9290DAF241C6D370425D83DDD61153DD2AC0FD206120434AD6792D60B2F084A2950AAC250B4001F309EA45B09D9
        DB440D6A2C9BB3B140569C51C985A2B0BE03ABA918C2311B11069FC9A0C762CCA59C1BDAE47C0406AF0CC7BBB1821C0F8733
        563ABBE896525E1156F7D593F55C39922B6B79E462CE587189247FA045CB19FA7256B960D0B25B7B364ECE250D43E19313C7
        98CE424634DC358A0914FAF33EA2B06EAA748947C6C150E54D7BD3A4C4873B117266145833FF04CAA96424AB678B49BA94D6
        619F01BBC62961850CF25765C7627910EF8E79F9B3749086AABF75407D7AC42748BC");
    let LB2 = hex!("4202030405060708090A0B0C0D0E0F1F202030405060708090A0B0C0D0E0F1F7");
    let PB2 = hex!("CC1160B24F3AB56D7E3EEF460A2AD73D0E5B50BC5FD6E06D74C80DF6295A5E7FED8664C9B819ABB90BF1B2481CA3958EDE01
        9E5A8D215E3C3B2FC662E6A6E5F4D6CD36C30C747745FCD8F85560645EC010987B87A7B42E619F388FDBB9DF0B916A01AD06
        40A9B761A9353DE373033EC5E2D16B59DB508BA33259B9791691FE35B2F08AFF381BFC9A74E380DFAC915B6165ED8C276DC7
        112FD36B7C21710AC6A2201179642BACA216C3D4C39EA74E75A370B9ADE85A2AD8B00EADCC4AE2B3819374FDCE01F4AF0253
        5194B88933ECE5A9B90C1886EFBCF40B1505D4D2603F7FED815F3B101664A90B239FE598E90C09069E102C500912C71F5339
        6EA1C9035682C9ECB1627193FDEE803078E4CAB436B6CACE8A861AD95B5F53E6C9757EEDD7FC9EA369089E82D2D32C952094
        60BD880C7D856DD8BD589E131C991E1148B5E4139E7F4EE32B25DA676FCB279ED94D9B28B6C4843F07A93FADC1314869D2E2
        71D90D993E4F5B654157BDBF45215D691AFAECC498E9ADB3A798029C2D68665878634E02B34006BA953DB444203C88C4523B
        EDCA14358E0B129BC712EAB69D1C253C490DD4E5F751FBA1B38BA200A3E73E78299306855237C6F72B15598B2EAB30224A22
        C2C7883C6BEDE636C4D1C06ED0B6793E4609969CF8A442614C8C547598C26CC848BC4593E24591FC85F624548A1D01EA5BE0
        4892C5C12EC07F70C8CA51C4CCD1C9F061EE1BFE07112C2577552966EB25759E77882F1B5B327964E6269E36C1D5AC9C94B0
        1D891E1B3AC2660C5D99E32364AB31015986352ABB20A228C358A548D1B413FF534550F2EE0C80E0741B7F90DC22E8D701A4
        4514810820A5A1D5EE62173283F91DAB585615E36A520FD7540FF7E7B9D6F2FB616251F1D2B6A034AF6427E66D559D7E04F1
        C7C22FEFA5F3F7B256D7225D5F683FE29238754D66E10687290675202CD15A32A7F71B5750A95BFCC183D2C26BF31D41225C
        04FBC123683FA911B994C5B9AE5172EE9847356C67302E7C405625543B7FA82D9BE737467F7C000F97FFBB647500DE9EE36A
        266F97AE83AB58D239533C8A2FB440E649ACDF6EFC8D98BAF10A1BFA0F7681EC9708BAB9D00A78FFF74AA4C7099D6DA69FBE
        E2B7C5EA7CEB04527D01CA2CCA8416181BA450C2519A8F383881FF439DEDCE45BF0117CAC0A612E52AD1A3B2F2D1C9917264
        DD131813F3D9F6D2D574D6CE9AA0943AA7E84C9BDEC515B6827921366794FE6B9058769ADCB3A14593CA49A866DC7AF5BCAF
        2A48BB06271B3948CC64572AE3A9D46A1209D3E70A02D50AC3CB0AA1B820F8EA25DA127931406AAFC9B00C0FD90C75973215
        86694E35EA291A88665A2FFBAE5C9BE45938E60027C6C6DEB384F873457B5B5C7107651AE0273DF8A23FDFF74A2A6BD67703
        854FA5E115712E84D6726F27370FDE6390B362142FCD93647BD2D7A3927DE5F5040F60E17C39D1248F6662CF441EE4B2470C
        D412050CE09EC31075001286F401A58FE6217000D6A9C8BA753C4CE9D1D8CF8B908614DF0A81");
    let previous_chain_secret = hex!("DA1B0A9081A422C6510559DA924B25AFFDAC9DC19C100FDDA1C2D825695C125D");
    let k2 = hex!("D71BD5A07C158C130283EF854516D290A46ADE09A63831C7B83B8FD0724C8FB0");
    let context2 = b"ETSI_QSHKE_TEST_VECTORS_V_1_2";
    // let label2 = LA2 ^ LB2
    let label2 = hex!("7300000000000000000000000000000E212233445566778899AABBCCDDEEFEC7");
    // let MA2 = cid || len(LA2) || LA2 || len(PA2) || PA2
    // let MB2 = cid || len(LB2) || LB2 || len(PB2) || PB2
    let chain_secret2 = hex!("5E0A1BCC706338B2C8176D0476D28F551FCBB3EF68A917190BDE3E4E6B0447B5");
    let key_material2 = hex!("B4D24420223C495C2E12A50FD93C05B9");

    let MA1 = message_format(&CID, &[&LA1, &PA1]);
    let MB1 = message_format(&CID, &[&LB1, &PB1]);
    
    let hhhh = concatenate_and_hash(&[&k1, &MA1, &MB1]);
    
    
    let round_secret1 = Ktf1::<HmacReset<Sha256>>::derive_secret_salt_other(&[], &[], &hhhh);
    
    println! ( "round_secret1={:02X?}", round_secret1);
    
    let chain_secret_key_mat: Array<u8, U48> = Hkdf::<Sha256>::derive_secret_salt_other ( &round_secret1, &label1, context);

    println! ( "chain_secret_key_mat={:02X?}", chain_secret_key_mat);
    assert_eq! ( &chain_secret_key_mat[..32], previous_chain_secret);
    assert_eq! ( &chain_secret_key_mat[32..], key_material1);   

    let MA2 = message_format(&CID, &[&LA2, &PA2]);
    println! ( "MA2={:02X?}", MA2);
    let MB2 = message_format(&CID, &[&LB2, &PB2]);
    println! ( "MB2={:02X?}", MB2);
        
    let hhhh2 = concatenate_and_hash(&[&k2, &MA2, &MB2]);
    println! ( "hhhh2={:02X?}", hhhh2);

    let round_secret2 = Ktf1::<HmacReset<Sha256>>::derive_secret_salt_other(&[], &chain_secret1, &hhhh2);

    println! ( "round_secret2={:02X?}", round_secret2);
    println! ( "label2={:02X?}", label2);
    println! ( "context2={:02X?}", context2);

    let chain_secret_key_mat: Array<u8, U48> = Hkdf::<Sha256>::derive_secret_salt_other ( &round_secret2, &label2, context2);

    println! ( "chain_secret_key_mat2={:02X?}", chain_secret_key_mat);
    assert_eq! ( &chain_secret_key_mat[..32], chain_secret2);
    assert_eq! ( &chain_secret_key_mat[32..], key_material2);

    type EtsiHybrid = HybridKem<EcdhKem<NistP256, EcRaw2Encoder<NistP256>>, MlKem768, EtsiCasKdfCombiner<Hkdf<Sha256>, EtsiTestVectorsLabel, 0x1122>, U16>;

    let mut decapsulator = EtsiHybrid::try_from_slice_decap2(&[dA1.as_slice(), &dA2, &zA2].concat()).unwrap();
    decapsulator.set_kdf(EtsiCasKdfCombiner::new_with_labels(&LA1, &LA2, &LB1, &LB2));
    let km_calc2 = decapsulator.try_decapsulate(&[PB1.as_slice(), PB2.as_slice()].concat().try_into().unwrap()).unwrap();
    assert_eq!(km_calc2.as_slice(), key_material2.as_slice());
}



// CasKDF with HMAC with SHA256, ECDH with NIST P-256 and ML-KEM 768
#[allow(non_snake_case)]
#[test]
fn test_d_3_2()
{
    let CID = hex!("4122");
    let LA1 = hex!("10102030405060708090A0B0C0D0E0F10102030405060708090A0B0C0D0E0F14");
    let PA1 = hex!("EAD218590119E8876B29146FF89CA61770C4EDBBF97D38CE385ED281D8A6B23028AF61281FD35E2FA7002523ACC85A429CB0
        6EE6648325389F59EDFCE1405141");
    let dA1 = hex!("7d7dc5f71eb29ddaf80d6214632eeae03d9058af1fb6d22ed80badb62bc1a534");
    
    let LB1 = hex!("0202030405060708090A0B0C0D0E0F14202030405060708090A0B0C0D0E0F14B");
    let PB1 = hex!("700C48F77F56584C5CC632CA65640DB91B6BACCE3A4DF6B42CE7CC838833D287DB71E509E3FD9B060DDB20BA5C51DCC5948D
        46FBF640DFE0441782CAB85FA4AC");
    let previous_chain_secret /* = psk = <NULL>*/ = hex!("");
    let k1 = hex!("46FC62106420FF012E54A434FBDD2D25CCC5852060561E68040DD7778997BD7B");
    let context = "ETSI_QSHKE_TEST_VECTORS_V_1_2";
    let label1 = /*LA1 ^ LB1*/ hex!("1212233445566778899AABBCCDDEEFE5212233445566778899AABBCCDDEEFE5F");
    // let MA1 = cid || len(LA1) || LA1 || len(PA1) || PA1
    // let MB1 = cid || len(LB1) || LB1 || len(PB1) || PB1
    let chain_secret1 = hex!("C8247E6FC6371394EB8FE74955D4A0C9BFE49B9AAD9F3EAD7F007D6F0E4AC8B9");
    let key_material1 = hex!("C4BF20A5F972813B117F9507227D6FD9");

    let MA1 = message_format(&CID, &[&LA1, &PA1]);
    let MB1 = message_format(&CID, &[&LB1, &PB1]);

    let hhhh = concatenate_and_hash(&[&k1, &MA1, &MB1]);
    println! ( "MA1={}", hex::encode(&MA1));
    println! ( "MB1={}", hex::encode(&MB1));
    println!( "hhhh={:02X?}", &hhhh );
    // let mut hasher = Hmac::<Sha256>::new_from_slice(&previous_chain_secret).unwrap();
    // hasher.update(&hhhh);
    // let round_secret1 = hasher.finalize().into_bytes();
    let round_secret1 = Ktf1::<HmacReset<Sha256>>::derive_secret_salt_other(&[], &previous_chain_secret, &hhhh);
    println! ( "round_secret1={:02X?}", round_secret1);

    //let chain_secret_key_mat1: Array<u8, U48> = Hkdf::<Sha256>::derive_secret_salt_other ( &round_secret1, &label1, context.as_bytes());
    let chain_secret_key_mat1: Array<u8, U48> = SskdfMac::<HmacReset<Sha256>>::derive_secret_salt_other(&round_secret1, &label1, context.as_bytes());

    println! ( "chain_secret_key_mat={:02X?}", chain_secret_key_mat1);
    assert_eq! ( &chain_secret_key_mat1[..32], chain_secret1);
    assert_eq! ( &chain_secret_key_mat1[32..], key_material1);
    
    let LA2 = hex!("3102030405060708090A0B0C0D0E0F110102030405060708090A0B0C0D0E0F30");
    let zA2 = hex!("b585d4eb01085111a172a87688d0032e3381a9e9a35fdd6ef2f8aeb3b40eb5ce");
    let dA2 = hex!("89b0c4b23019af3498a27da290892d981dd59fa08993bc05da21e1d72503664c");
    let PA2 = hex!("533145987CB33CD2C8F5AC8A73C03A97FB31D2B89D02B1576CFC77BC97656FC040FCC7569750459EE753EBD69839692B375A
        0F53165B191CA8C6185B85626282C0A4AD63B36B6A289F661D505850832248D6F39084695C028B979835848931874E037EDF
        33CD9F1521E2B478BF0C37D859572AB08C20F7687749032949AB7457B66C1206C08A78C58633BA008E8770224700B84758B2
        2B290E9ED01F750439B00B97729960940817D3BA0CE7F10EB6A0C8EBD975C85A6299A6CE486132292189F9DCC13F27591870
        4192A417E7B305834323C354213195BAD0A5AA30A3980B028A1E116E97E74ED8D053A2FA51E00068BCD69D325246E93A30AD
        493D28099AF143016BE454413256A5DA144C9985C70664EE12013DF167E228B921EA3BAC494B5D5140581A4D7E7080B4C284
        A6DAA955366EAE3217541A0B1109313F7A1AE9305D55B45CB6A5B2F3321A10DB137E92306A3B2A25FC1999495F7A732D7CD8
        3BE0923050A5562A036699F92427CB71C0CA201D958F7A3171740AB477188DB276A52E576703493E289C14BF896D5A827586
        492D23B605CDC6932A4ABF902A219F88B12D0479C91B4EE6C586A4A2061FC22D66264772359B569456111574D84606CBA282
        92C37A40B81F5A113BB9E72871E14184270FE2A87C33BA7D01E95A578950D098C48A584428BAC781BA938F13BB80F4790EC3
        6F1A394FEC97AB80054F60A90DA86ABE7D84799A604233A5A495294D13805B6CF3505DB833E9F223D102AAA9E666580B088E
        1CBABC4CB52725CB768B5E990B89411AA652E06A2BDB937B185EB924C59AF6BA9BE2BA09409DB5C262D751731461A89AAC05
        ADACC320B6AFC5C4A5FDBB2F56B2483D11779C7117707B121D0B36362B2BF8D4B28F6948F5EB1D5E41B1C8A5053D581019C3
        6AC87988803CB934027909DC4C5BD1AE2EF451D9F7945209C0E9E60AF43C50DC98646F3BB13BE6491E91930D9AA1AA315FB3
        B1A067579565D170C4E888E9042751106B72A60470A69992508E8CE3101A602A22DA7FB1A744F09488E704481F649DAB6158
        E5306F573009EC63ACF11B549D280033343FC9750BB927B931B94F9C5475A2B803AF36CC3CC30521EA2A86040E03E7CF90B3
        6D2E370856285AE4523367482E68473CA500200F75C8C423C8AB93C7BFE74DF253AF97114A3FEAC1DDD34E06747C6B386990
        428100A99351BA14A3C19B1A7A6DA5A715F6A698E9FC330C13B98D61A2A85AC0E0896CC8032490B93FEB284703F21E6D1630
        7D7886F948752FE55CEE7291C06AA7BBB79146C644AEA7C2765C5EFA535B729158EB51BC2D4C389B970B30086966D858D51B
        78EF3829F9290DAF241C6D370425D83DDD61153DD2AC0FD206120434AD6792D60B2F084A2950AAC250B4001F309EA45B09D9
        DB440D6A2C9BB3B140569C51C985A2B0BE03ABA918C2311B11069FC9A0C762CCA59C1BDAE47C0406AF0CC7BBB1821C0F8733
        563ABBE896525E1156F7D593F55C39922B6B79E462CE587189247FA045CB19FA7256B960D0B25B7B364ECE250D43E19313C7
        98CE424634DC358A0914FAF33EA2B06EAA748947C6C150E54D7BD3A4C4873B117266145833FF04CAA96424AB678B49BA94D6
        619F01BBC62961850CF25765C7627910EF8E79F9B3749086AABF75407D7AC42748BC");
    let LB2 = hex!("4202030405060708090A0B0C0D0E0F1F202030405060708090A0B0C0D0E0F1F7");
    let PB2 = hex!("CC1160B24F3AB56D7E3EEF460A2AD73D0E5B50BC5FD6E06D74C80DF6295A5E7FED8664C9B819ABB90BF1B2481CA3958EDE01
        9E5A8D215E3C3B2FC662E6A6E5F4D6CD36C30C747745FCD8F85560645EC010987B87A7B42E619F388FDBB9DF0B916A01AD06
        40A9B761A9353DE373033EC5E2D16B59DB508BA33259B9791691FE35B2F08AFF381BFC9A74E380DFAC915B6165ED8C276DC7
        112FD36B7C21710AC6A2201179642BACA216C3D4C39EA74E75A370B9ADE85A2AD8B00EADCC4AE2B3819374FDCE01F4AF0253
        5194B88933ECE5A9B90C1886EFBCF40B1505D4D2603F7FED815F3B101664A90B239FE598E90C09069E102C500912C71F5339
        6EA1C9035682C9ECB1627193FDEE803078E4CAB436B6CACE8A861AD95B5F53E6C9757EEDD7FC9EA369089E82D2D32C952094
        60BD880C7D856DD8BD589E131C991E1148B5E4139E7F4EE32B25DA676FCB279ED94D9B28B6C4843F07A93FADC1314869D2E2
        71D90D993E4F5B654157BDBF45215D691AFAECC498E9ADB3A798029C2D68665878634E02B34006BA953DB444203C88C4523B
        EDCA14358E0B129BC712EAB69D1C253C490DD4E5F751FBA1B38BA200A3E73E78299306855237C6F72B15598B2EAB30224A22
        C2C7883C6BEDE636C4D1C06ED0B6793E4609969CF8A442614C8C547598C26CC848BC4593E24591FC85F624548A1D01EA5BE0
        4892C5C12EC07F70C8CA51C4CCD1C9F061EE1BFE07112C2577552966EB25759E77882F1B5B327964E6269E36C1D5AC9C94B0
        1D891E1B3AC2660C5D99E32364AB31015986352ABB20A228C358A548D1B413FF534550F2EE0C80E0741B7F90DC22E8D701A4
        4514810820A5A1D5EE62173283F91DAB585615E36A520FD7540FF7E7B9D6F2FB616251F1D2B6A034AF6427E66D559D7E04F1
        C7C22FEFA5F3F7B256D7225D5F683FE29238754D66E10687290675202CD15A32A7F71B5750A95BFCC183D2C26BF31D41225C
        04FBC123683FA911B994C5B9AE5172EE9847356C67302E7C405625543B7FA82D9BE737467F7C000F97FFBB647500DE9EE36A
        266F97AE83AB58D239533C8A2FB440E649ACDF6EFC8D98BAF10A1BFA0F7681EC9708BAB9D00A78FFF74AA4C7099D6DA69FBE
        E2B7C5EA7CEB04527D01CA2CCA8416181BA450C2519A8F383881FF439DEDCE45BF0117CAC0A612E52AD1A3B2F2D1C9917264
        DD131813F3D9F6D2D574D6CE9AA0943AA7E84C9BDEC515B6827921366794FE6B9058769ADCB3A14593CA49A866DC7AF5BCAF
        2A48BB06271B3948CC64572AE3A9D46A1209D3E70A02D50AC3CB0AA1B820F8EA25DA127931406AAFC9B00C0FD90C75973215
        86694E35EA291A88665A2FFBAE5C9BE45938E60027C6C6DEB384F873457B5B5C7107651AE0273DF8A23FDFF74A2A6BD67703
        854FA5E115712E84D6726F27370FDE6390B362142FCD93647BD2D7A3927DE5F5040F60E17C39D1248F6662CF441EE4B2470C
        D412050CE09EC31075001286F401A58FE6217000D6A9C8BA753C4CE9D1D8CF8B908614DF0A81");
    let _previous_chain_secret = hex!("C8247E6FC6371394EB8FE74955D4A0C9BFE49B9AAD9F3EAD7F007D6F0E4AC8B9");
    let k2 = hex!("D71BD5A07C158C130283EF854516D290A46ADE09A63831C7B83B8FD0724C8FB0");
    let context2 = "ETSI_QSHKE_TEST_VECTORS_V_1_2";
    //let label2 = LA2 ^ LB2 
    let label2 = hex!("7300000000000000000000000000000E212233445566778899AABBCCDDEEFEC7");
    // let MA2 = cid || len(LA2) || LA2 || len(PA2) || PA2
    // let MB2 = cid || len(LB2) || LB2 || len(PB2) || PB2
    let chain_secret2 = hex!("F99F9E8EF11D595ED63C93F7C5DF216688658B4F558E8B91526DCEDD01A74D39");
    let key_material2 = hex!("7E12FBC4071218FA9D7B3DC21A651EA3");


    let MA2 = message_format(&CID, &[&LA2, &PA2]);
    let MB2 = message_format(&CID, &[&LB2, &PB2]);

    let hhhh2 = concatenate_and_hash(&[&k2, &MA2, &MB2]);

    let round_secret2 = Ktf1::<HmacReset<Sha256>>::derive_secret_salt_other(&[], &chain_secret1, &hhhh2);

    println! ( "round_secret2={:02X?}", round_secret2);
    println! ( "label2={:02X?}", label2);
    println! ( "context2={:02X?}", context2.as_bytes());

    let chain_secret_key_mat: Array<u8, U48> = SskdfMac::<HmacReset<Sha256>>::derive_secret_salt_other ( &round_secret2, &label2, context2.as_bytes());

    println! ( "chain_secret_key_mat2={:02X?}", chain_secret_key_mat);
    assert_eq! ( &chain_secret_key_mat[..32], chain_secret2);
    assert_eq! ( &chain_secret_key_mat[32..], key_material2);


    type EtsiHybrid = HybridKem<EcdhKem<NistP256, EcRaw2Encoder<NistP256>>, MlKem768, EtsiCasKdfCombiner<SskdfMac::<HmacReset<Sha256>>, EtsiTestVectorsLabel, 0x4122>, U16>;

    let mut decapsulator = EtsiHybrid::try_from_slice_decap2(&[dA1.as_slice(), &dA2, &zA2].concat()).unwrap();
    decapsulator.set_kdf(EtsiCasKdfCombiner::new_with_labels(&LA1, &LA2, &LB1, &LB2));
    let km_calc2 = decapsulator.try_decapsulate(&[PB1.as_slice(), PB2.as_slice()].concat().try_into().unwrap()).unwrap();
    assert_eq!(km_calc2.as_slice(), key_material2.as_slice());
}


// D.3.3 KDF as KMAC128, ECDH with NIST P-256, and ML-KEM768
#[allow(non_snake_case)]
#[test]
fn test_d_3_3()
{
    let CID = hex!("7122");
    let LA1 = hex!("10102030405060708090A0B0C0D0E0F10102030405060708090A0B0C0D0E0F14");
    let dA1 = hex!("7d7dc5f71eb29ddaf80d6214632eeae03d9058af1fb6d22ed80badb62bc1a534");
    let PA1 = hex!("EAD218590119E8876B29146FF89CA61770C4EDBBF97D38CE385ED281D8A6B23028AF61281FD35E2FA7002523ACC85A429CB0
        6EE6648325389F59EDFCE1405141");
    let LB1 = hex!("0202030405060708090A0B0C0D0E0F14202030405060708090A0B0C0D0E0F14B");
    let PB1 = hex!("700C48F77F56584C5CC632CA65640DB91B6BACCE3A4DF6B42CE7CC838833D287DB71E509E3FD9B060DDB20BA5C51DCC5948D
        46FBF640DFE0441782CAB85FA4AC");
    let _previous_chain_secret1 = /*psk =*/ hex!("");
    let k1 = hex!("46FC62106420FF012E54A434FBDD2D25CCC5852060561E68040DD7778997BD7B");
    let context1 = "ETSI_QSHKE_TEST_VECTORS_V_1_2";
    let label1 = /*LA1 ^ LB1 */ hex!("1212233445566778899AABBCCDDEEFE5212233445566778899AABBCCDDEEFE5F");
    // MA1 = cid || len(LA1) || LA1 || len(PA1) || PA1
    // MB1 = cid || len(LB1) || LB1 || len(PB1) || PB1
    let chain_secret1 = hex!("DDDDEB4EB4EDB9EC8E7DBA3BB90F581F87518F4C2DB2B7AF3BA49C2D505391D0");
    let key_material1 = hex!("1375E52A33EFCB595531CACEAE3A915D");
    let LA2 = hex!("3102030405060708090A0B0C0D0E0F110102030405060708090A0B0C0D0E0F30");
    let zA2 = hex!("b585d4eb01085111a172a87688d0032e3381a9e9a35fdd6ef2f8aeb3b40eb5ce");
    let dA2 = hex!("89b0c4b23019af3498a27da290892d981dd59fa08993bc05da21e1d72503664c");
    let PA2 = hex!("533145987CB33CD2C8F5AC8A73C03A97FB31D2B89D02B1576CFC77BC97656FC040FCC7569750459EE753EBD69839692B375A
        0F53165B191CA8C6185B85626282C0A4AD63B36B6A289F661D505850832248D6F39084695C028B979835848931874E037EDF
        33CD9F1521E2B478BF0C37D859572AB08C20F7687749032949AB7457B66C1206C08A78C58633BA008E8770224700B84758B2
        2B290E9ED01F750439B00B97729960940817D3BA0CE7F10EB6A0C8EBD975C85A6299A6CE486132292189F9DCC13F27591870
        4192A417E7B305834323C354213195BAD0A5AA30A3980B028A1E116E97E74ED8D053A2FA51E00068BCD69D325246E93A30AD
        493D28099AF143016BE454413256A5DA144C9985C70664EE12013DF167E228B921EA3BAC494B5D5140581A4D7E7080B4C284
        A6DAA955366EAE3217541A0B1109313F7A1AE9305D55B45CB6A5B2F3321A10DB137E92306A3B2A25FC1999495F7A732D7CD8
        3BE0923050A5562A036699F92427CB71C0CA201D958F7A3171740AB477188DB276A52E576703493E289C14BF896D5A827586
        492D23B605CDC6932A4ABF902A219F88B12D0479C91B4EE6C586A4A2061FC22D66264772359B569456111574D84606CBA282
        92C37A40B81F5A113BB9E72871E14184270FE2A87C33BA7D01E95A578950D098C48A584428BAC781BA938F13BB80F4790EC3
        6F1A394FEC97AB80054F60A90DA86ABE7D84799A604233A5A495294D13805B6CF3505DB833E9F223D102AAA9E666580B088E
        1CBABC4CB52725CB768B5E990B89411AA652E06A2BDB937B185EB924C59AF6BA9BE2BA09409DB5C262D751731461A89AAC05
        ADACC320B6AFC5C4A5FDBB2F56B2483D11779C7117707B121D0B36362B2BF8D4B28F6948F5EB1D5E41B1C8A5053D581019C3
        6AC87988803CB934027909DC4C5BD1AE2EF451D9F7945209C0E9E60AF43C50DC98646F3BB13BE6491E91930D9AA1AA315FB3
        B1A067579565D170C4E888E9042751106B72A60470A69992508E8CE3101A602A22DA7FB1A744F09488E704481F649DAB6158
        E5306F573009EC63ACF11B549D280033343FC9750BB927B931B94F9C5475A2B803AF36CC3CC30521EA2A86040E03E7CF90B3
        6D2E370856285AE4523367482E68473CA500200F75C8C423C8AB93C7BFE74DF253AF97114A3FEAC1DDD34E06747C6B386990
        428100A99351BA14A3C19B1A7A6DA5A715F6A698E9FC330C13B98D61A2A85AC0E0896CC8032490B93FEB284703F21E6D1630
        7D7886F948752FE55CEE7291C06AA7BBB79146C644AEA7C2765C5EFA535B729158EB51BC2D4C389B970B30086966D858D51B
        78EF3829F9290DAF241C6D370425D83DDD61153DD2AC0FD206120434AD6792D60B2F084A2950AAC250B4001F309EA45B09D9
        DB440D6A2C9BB3B140569C51C985A2B0BE03ABA918C2311B11069FC9A0C762CCA59C1BDAE47C0406AF0CC7BBB1821C0F8733
        563ABBE896525E1156F7D593F55C39922B6B79E462CE587189247FA045CB19FA7256B960D0B25B7B364ECE250D43E19313C7
        98CE424634DC358A0914FAF33EA2B06EAA748947C6C150E54D7BD3A4C4873B117266145833FF04CAA96424AB678B49BA94D6
        619F01BBC62961850CF25765C7627910EF8E79F9B3749086AABF75407D7AC42748BC");
    let LB2 = hex!("4202030405060708090A0B0C0D0E0F1F202030405060708090A0B0C0D0E0F1F7");
    let PB2 = hex!("CC1160B24F3AB56D7E3EEF460A2AD73D0E5B50BC5FD6E06D74C80DF6295A5E7FED8664C9B819ABB90BF1B2481CA3958EDE01
        9E5A8D215E3C3B2FC662E6A6E5F4D6CD36C30C747745FCD8F85560645EC010987B87A7B42E619F388FDBB9DF0B916A01AD06
        40A9B761A9353DE373033EC5E2D16B59DB508BA33259B9791691FE35B2F08AFF381BFC9A74E380DFAC915B6165ED8C276DC7
        112FD36B7C21710AC6A2201179642BACA216C3D4C39EA74E75A370B9ADE85A2AD8B00EADCC4AE2B3819374FDCE01F4AF0253
        5194B88933ECE5A9B90C1886EFBCF40B1505D4D2603F7FED815F3B101664A90B239FE598E90C09069E102C500912C71F5339
        6EA1C9035682C9ECB1627193FDEE803078E4CAB436B6CACE8A861AD95B5F53E6C9757EEDD7FC9EA369089E82D2D32C952094
        60BD880C7D856DD8BD589E131C991E1148B5E4139E7F4EE32B25DA676FCB279ED94D9B28B6C4843F07A93FADC1314869D2E2
        71D90D993E4F5B654157BDBF45215D691AFAECC498E9ADB3A798029C2D68665878634E02B34006BA953DB444203C88C4523B
        EDCA14358E0B129BC712EAB69D1C253C490DD4E5F751FBA1B38BA200A3E73E78299306855237C6F72B15598B2EAB30224A22
        C2C7883C6BEDE636C4D1C06ED0B6793E4609969CF8A442614C8C547598C26CC848BC4593E24591FC85F624548A1D01EA5BE0
        4892C5C12EC07F70C8CA51C4CCD1C9F061EE1BFE07112C2577552966EB25759E77882F1B5B327964E6269E36C1D5AC9C94B0
        1D891E1B3AC2660C5D99E32364AB31015986352ABB20A228C358A548D1B413FF534550F2EE0C80E0741B7F90DC22E8D701A4
        4514810820A5A1D5EE62173283F91DAB585615E36A520FD7540FF7E7B9D6F2FB616251F1D2B6A034AF6427E66D559D7E04F1
        C7C22FEFA5F3F7B256D7225D5F683FE29238754D66E10687290675202CD15A32A7F71B5750A95BFCC183D2C26BF31D41225C
        04FBC123683FA911B994C5B9AE5172EE9847356C67302E7C405625543B7FA82D9BE737467F7C000F97FFBB647500DE9EE36A
        266F97AE83AB58D239533C8A2FB440E649ACDF6EFC8D98BAF10A1BFA0F7681EC9708BAB9D00A78FFF74AA4C7099D6DA69FBE
        E2B7C5EA7CEB04527D01CA2CCA8416181BA450C2519A8F383881FF439DEDCE45BF0117CAC0A612E52AD1A3B2F2D1C9917264
        DD131813F3D9F6D2D574D6CE9AA0943AA7E84C9BDEC515B6827921366794FE6B9058769ADCB3A14593CA49A866DC7AF5BCAF
        2A48BB06271B3948CC64572AE3A9D46A1209D3E70A02D50AC3CB0AA1B820F8EA25DA127931406AAFC9B00C0FD90C75973215
        86694E35EA291A88665A2FFBAE5C9BE45938E60027C6C6DEB384F873457B5B5C7107651AE0273DF8A23FDFF74A2A6BD67703
        854FA5E115712E84D6726F27370FDE6390B362142FCD93647BD2D7A3927DE5F5040F60E17C39D1248F6662CF441EE4B2470C
        D412050CE09EC31075001286F401A58FE6217000D6A9C8BA753C4CE9D1D8CF8B908614DF0A81");
    let _previous_chain_secret2 = hex!("DDDDEB4EB4EDB9EC8E7DBA3BB90F581F87518F4C2DB2B7AF3BA49C2D505391D0");
    let k2 = hex!("D71BD5A07C158C130283EF854516D290A46ADE09A63831C7B83B8FD0724C8FB0");
    let context2 = "ETSI_QSHKE_TEST_VECTORS_V_1_2";
    // label2 = LA2 ^ LB2
    let label2 = hex!("7300000000000000000000000000000E212233445566778899AABBCCDDEEFEC7");
    // MA2 = cid || len(LA2) || LA2 || len(PA2) || PA2
    // MB2 = cid || len(LB2) || LB2 || len(PB2) || PB2
    let chain_secret2 = hex!("65A510FF49080D4E9EF8AA392C14C1D9C4CCFADD781BD84D2491B7CA81D13852");
    let key_material2 = hex!("A21B0F3D7546FFD4C2A7058AC9AE4D5B");


    let MA1 = message_format(&CID, &[&LA1, &PA1]);
    let MB1 = message_format(&CID, &[&LB1, &PB1]);

    let hhhh = concatenate(&[&k1, &MA1, &MB1]);
    println! ( "MA1={}", hex::encode(&MA1));
    println! ( "MB1={}", hex::encode(&MB1));
    println!( "hhhh={:02X?}", &hhhh );
    
    let round_secret1: Array<u8, U32> = Kmac128Kdf::derive_secret_other(&[0u8; 32], /*b"",*/ &hhhh);
    println! ( "round_secret1={:02X?}", round_secret1);

    //let chain_secret_key_mat1: Array<u8, U48> = Hkdf::<Sha256>::derive_secret_salt_other ( &round_secret1, &label1, context.as_bytes());
    //let km_calc: Array<u8, U16> = Kmac128KdfStatic::derive_secrets_salt_others ( [label.as_slice()], b"KDF", [1u32.to_be_bytes().as_slice(), &k1, &k2, &context_calc]);
    let chain_secret_key_mat1: Array<u8, U48> = Kmac128Kdf::derive_secrets_salt_others([label1.as_slice()], b"KDF", [1u32.to_be_bytes().as_slice(), &round_secret1, context1.as_bytes()]);

    println! ( "chain_secret_key_mat={:02X?}", chain_secret_key_mat1);
    assert_eq! ( &chain_secret_key_mat1[..32], chain_secret1);
    assert_eq! ( &chain_secret_key_mat1[32..], key_material1);

    let MA2 = message_format(&CID, &[&LA2, &PA2]);
    let MB2 = message_format(&CID, &[&LB2, &PB2]);

    let hhhh2 = concatenate(&[&k2, &MA2, &MB2]);

    //let round_secret2 = Ktf1::<HmacReset<Sha256>>::derive_secret_salt_other(&[], &chain_secret1, &hhhh2);
    let round_secret2: Array<u8, U32> = Kmac128Kdf::derive_secret_other(&chain_secret1, /*&[],*/ &hhhh2);

    println! ( "round_secret2={:02X?}", round_secret2);
    println! ( "label2={:02X?}", label2);
    println! ( "context2={:02X?}", context2.as_bytes());

    //let chain_secret_key_mat: Array<u8, U48> = SskdfMac::<HmacReset<Sha256>>::derive_secret_salt_other ( &round_secret2, &label2, context2.as_bytes());
    let chain_secret_key_mat: Array<u8, U48> = Kmac128Kdf::derive_secrets_salt_others ( [label2.as_slice()], b"KDF", [1u32.to_be_bytes().as_slice(), &round_secret2, &context2.as_bytes()]);

    println! ( "chain_secret_key_mat2={:02X?}", chain_secret_key_mat);
    assert_eq! ( &chain_secret_key_mat[..32], chain_secret2);
    assert_eq! ( &chain_secret_key_mat[32..], key_material2);

    type EtsiHybrid<'a> = HybridKem<EcdhKem<NistP256, EcRaw2Encoder<NistP256>>, MlKem768, EtsiCasKdfCombiner<Kmac128Kdf, EtsiTestVectorsLabel, 0x7122>, U16>;

    let mut decapsulator = EtsiHybrid::try_from_slice_decap2(&[dA1.as_slice(), &dA2, &zA2].concat()).unwrap();
    decapsulator.set_kdf(EtsiCasKdfCombiner::new_with_labels(&LA1, &LA2, &LB1, &LB2));
    
    let km_calc2 = decapsulator.try_decapsulate(&[PB1.as_slice(), PB2.as_slice()].concat().try_into().unwrap()).unwrap();
    assert_eq!(km_calc2.as_slice(), key_material2.as_slice());
}



// D.3.4 KDF as HKDF with SHA256, ECDH with Curve25519, and ML-KEM768
#[allow(non_snake_case)]
#[test]
fn test_d_3_4()
{
    let CID = hex!("1722");
    let LA1 = hex!("0102030405060708090A0B0C0D0E0F1101020304050607081020304050607085");
    let dA1 = hex!("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
    let PA1 = hex!("8520F0098930A754748B7DDCB43EF75A0DBF3A0D26381AF4EBA4A98EAA9B4E6A");
    let LB1 = hex!("202030405060708090A0B0C0D0E0F100202030405060708E020304050607080C");
    let PB1 = hex!("DE9EDB7D7B7DC1B4D35B61C2ECE435373F8343C85B78674DADFC7E146F882B4F");
    let _previous_chain_secret = /*psk =*/ hex!("");
    let k1 = hex!("4A5D9D5BA4CE2DE1728E3BF480350F25E07E21C947D19E3376F09B3C1E161742");
    let context1 = "ETSI_QSHKE_TEST_VECTORS_V_1_2";
    let label1 = /*LA1 ^ LB1 */ hex!("212233445566778899AABBCCDDEEFE1121223344556677861223344556677889");
    // MA1 = cid || len(LA1) || LA1 || len(PA1) || PA1
    // MB1 = cid || len(LB1) || LB1 || len(PB1) || PB1
    let chain_secret1 = hex!("F1A0E202AC8F33A77AAF0BD39852A997DCE9EA5F4FF6882BF1D0F1536C84FA4C");
    let key_material1 = hex!("083D51054638A7BE42551230786E0F60");
    let LA2 = hex!("14102030405060708090A0B0C0D0E0F14102030405060708090A0B0C0D0E0F11");
    let zA2 = hex!("a9f93c7b791356b66afcceb745a548c7f6b185e4f45ec1ff1a22acdd96e7a6d8");
    let dA2 = hex!("8d45a2ab49d8c20d4ab5680e5c9d9d0cc9ca8228484946f9afce5b8df6f39d19");
    let PA2 = hex!("06F51174F03C2FE07CC31B0659B87EBF124237811B88B980BC277F8C050B265CBEE1A4AE7145CB9253281BBC291F2808E065
        855FD91C7D14122C589FB21B45FD3B7FBB6562FD53006B565189EC983C7A0D4C21596EF3795AE22ECAD71F75395558B55220
        662BB66C389ED9AB6B784476E1788F34B28B59A4C6F71F9F6A49DA80C4D3107DB2C306968B5600E18285F8BFA293677F699F
        D2D2820DE490F530818D6667686A765FCC0009484D71629C1F148104B462325AC55EF34DD5C7098441A06757CA35C8ADFDAB
        6D36333310241F9970B1B123478DCBB75AE6CA39BB84FFCB23A593C24BC54E74B4086165BB4B10AE39F45447AA4EA5F55762
        386B11051B84B0A688C12C73336FC87164B7FBC7F0B07D2A51BB05560606D5558666CC322963AD3CA2BC1293260A94707770
        C030B2BC9C00477A8D5FF6737961480D48109F66075DA9C8AB516F70A78DA9E444AB65798A2565965A68AD9146FD9267D2A8
        0C4352A0A988157522046620A63D9BA7BBCCAFD50A61384453F8545845B25E7A05745C4B26EF7211200A916241047FDABB66
        936BB7351C04F5CD06A10AE3C459B74BB0CD85044BF8B6BF2B33294014B9D68517CB1A9813230BA08813807A2DFCC6A739B6
        AC79575F19BAB96A7CDED404D0E52508214AD43763A0A048FC36785B2C718F75B3432769C1D2A6240336A82B39D865739AF7
        8E94A92BD7B4703210297FB82E0BE57B97384DB5B24FFA5486C982AF48642D967222A28C6F83E5AD6A59CA486733808BA3BD
        86A780E59888011965A351CA949B0D6C72FB3BA0F867834D166819C252D9600207C88997318B2D204AC3619247A01829484F
        12BCA2E8F16AAC677C9E8AC209F9BCCF019BBDA66E8F073DFBD934E08CA15BE77576029654E049C1C20B1B123E5F0B501356
        28CD2C96A5D0B1EEF48FBE08AC4685247721B128F71DC748452B94A458F39B337BC2305CCC505BB18BF6ABE3EC2C825799B9
        5C13A1F6411CD3B031F3CEC3D99AFC1A28F2019C1BD129A2EA35F06415C8B717337957CAA964E794881257073FF5C12C3C62
        034861C343B7F70B9D475CCC10EA5889910E04CA7EAF0B762DB56962EC40CA47CEB4D228600595CF22421148CF02B4CFCE76
        AD27701F925C01C71C5405534ED54B0100C280DD861D89E967BED4829C568BB76CA500342803835F7983179CDA15899033F7
        97951031138A83669AB4CCB4630058088AA0845FAF7B0761B405AE866C426711EB152889D175E7B20DA03126B7419A766416
        A68AAC0FBC355DA07D6E6339BC0539CEB55711F633B8C7392627497821CB9D7174C4E655B5928BF722C84B8233A0993B6DE0
        2D7364443EA4C73A754B8190243DF936184819E1B8AB6F0B0BFBAC6C47E66DDF11757BE55E0787ADC112C63E644D1B904877
        764D856ABE78B583600CBB2119CB916C689D4543F4D553CAC33AD19B245B4948EF0BA3E7D1151179B9FB2941F3674E5F8771
        677737C435B2383119A3E75434114439506E1B9145FF16B1458879A1039962434151619B77915D033A3FAB7385FE861E4A25
        B125A205C3F1B16972470B2791534B5FB8731B20C03684CCBEB97A1FA4417655BB485C347519710522C357D50C43FC264409
        8533FE549C825F5DC8CA82A0DD908891BB4F92EAAB51CBE036CD6FB59A749269A0A3");
    let LB2 = hex!("202030405060708090A0B0C0D0E0F110202030405060708A0203040506070808");
    let PB2 = hex!("DB3D4F38A49CC5C1C7766573873F3926184923F570FCDBA6D7086BEA39601FADFEBABB2F9ED0EBD86A6468BE03D3B05713DE
        50B5E5D58FFDB5500F2AF7419682BC7857870D1E624C2B48A7E0D30A91F141F0764014FBED12A9F72C958EB53A7ED4A16825
        78B4348A05C183C790FF56D66B23BD601FB372C771F52045E13CA2D6DAB80A165A2159B8F990B5BBF125883DEC0A2AF4A54C
        3F386DE4DF6EE96923E9BB2551753DDC6D1F00D7EE910835082C6260974D11FBA49951DB2E27B47362EC4EBF804327AD9682
        01EDB71BDC8C32887214FB2AAA842AABBE0A4E03FDC695B19610377B9BEA9D371016674E977E9E45382D236365EFEDF56665
        9F9936D9D14CA8595DDF121AE7ACC6056DD6FE1B58DC0F0B23CF5366D2488C4D6361B09875242B3A39374159CF3654ABD25F
        8B080BAE117A5F77D15031AD8B350C6922FFD426EC9F9F80A1918FE722CB7A4B537210EF8A5538A52048BADCE3CAF5C46454
        EEAF413819D57EFBA834D7017F9343B302679A0A28F532E93FE8C5B6AEC3C42C160A3FAD20FA2ABADD29C2564DB59FA25A11
        CA502D11421F7F080A616F9656942932E11BFDCC47B1D8EFFA81D724FFABF4613830631737EB7E52DA78A6B026DB1C4FB80B
        BF2D8F9393875330B2F9C1A124436028BF2624C1E64797ABE2E526967DD99BC21B555A5833A31ACE7969E3ECC64C1697DEC0
        B074108F6B17EFA2A517923B435D8446043FB1A96B2EF3B3D3952F08657997D1D9169FFD14316185EC30457E0FAF7EBA2B5A
        02A01993EC530BB9C44C091D2E9D9BC82951E577D76DC2757F2E04E822B6A29F840887A297202E7389A0999F9E69255DE0A3
        3AEB8CD0B21B7F3B5AA7BFD864CF8FF4FFE78FFF166CAF1B805464D5E4B60EB0277E3BA4F3F3390640F5F16E0B784CC8A679
        40977B2F0202D37A74472161589A7B9E7721CC532904A17AFF8FA86ECDC46A410BD6F9309B2CC310D7941A02A5720CD64241
        B5C13C78A86010805AC74C3B81D83348C63C410451BD2052CE764DA83CF80B2654CB1D033F259DA36039E4DF1A5C4CE3F861
        3E28CFC2B25EAE2A21B425B44D0C998977B3ADF5156BFCA1E357EC3F6B5805B2CDC4D46A4C83154AEF0F50D493BAB0BBCA13
        0E92CA21AF8BDF817F7616B55C4C24C066EBF896F39A7BF50A241561E578BDD931CB07EADD193986C455F8798AB97B8D732D
        37C796E09C1C7ABB978BF666CED961373198607AC355FCF6903B4F3047A1D97C344A2D8B73DB310769CCFB4AE3DA6C4E82DE
        B83BF4060722D9E5A9AFBD3E03B4517E3B7D563F31821D5D8EF7F06F0D92A9F401EA9BEFD52CA8DB331360E603C14A340B80
        6155DE690CD2D92EE6A8EE53BCEED7EEB308D375518C851C109A03EE61960D6CD7CD1FDEE5CC2A401039A15EE4F97A734008
        01A090FBF09BE42119662D06C3FF8217FCFC2C70CDE6E1C2F9A396A2E08A3C22AE3CE90A5C97C9F69EBC1546898A047C9DCA
        D128003A90B29B62F7B093CC90C9CD38104C1A3CE62BEA6A3646EF7E3B9FB7C4C44E78FF650C");
    let _previous_chain_secret = hex!("F1A0E202AC8F33A77AAF0BD39852A997DCE9EA5F4FF6882BF1D0F1536C84FA4C");
    let k2 = hex!("E3E4F4E9D4F5C9AE03836BB9266C50B033285ACE9BC56F73817CE19679D1429A");
    let context2 = "ETSI_QSHKE_TEST_VECTORS_V_1_2";
    // label2 = LA2 ^ LB2
    let label2 = hex!("34301070103010F010301070103011E161223344556677820B090F090B090719");
    // MA2 = cid || len(LA2) || LA2 || len(PA2) || PA2
    // MB2 = cid || len(LB2) || LB2 || len(PB2) || PB2
    let chain_secret2 = hex!("9774DFF0962EEEDE5504442C32CE865101FB4C5EC91B6931BFDB5CECD88A9F0A");
    let key_material2 = hex!("2D490429EE1F9F17CB05AE44691CCD09");


    let MA1 = message_format(&CID, &[&LA1, &PA1]);
    let MB1 = message_format(&CID, &[&LB1, &PB1]);

    let hhhh = concatenate_and_hash(&[&k1, &MA1, &MB1]);
        
    let round_secret1 = Ktf1::<HmacReset<Sha256>>::derive_secret_salt_other(&[], &[], &hhhh);
    println! ( "round_secret1={:02X?}", round_secret1);
    
    let chain_secret_key_mat: Array<u8, U48> = Hkdf::<Sha256>::derive_secret_salt_other ( &round_secret1, &label1, context1.as_bytes());

    println! ( "chain_secret_key_mat={:02X?}", chain_secret_key_mat);
    assert_eq! ( &chain_secret_key_mat[..32], chain_secret1);
    assert_eq! ( &chain_secret_key_mat[32..], key_material1);   


    let MA2 = message_format(&CID, &[&LA2, &PA2]);
    let MB2 = message_format(&CID, &[&LB2, &PB2]);
    let hhhh2 = concatenate_and_hash(&[&k2, &MA2, &MB2]);

    //let round_secret2 = Ktf1::<HmacReset<Sha256>>::derive_secret_salt_other(&[], &chain_secret1, &hhhh2);
    let round_secret2: Array<u8, U32> = Ktf1::<HmacReset<Sha256>>::derive_secret_salt_other(&[], &chain_secret1, &hhhh2);

    println! ( "round_secret2={:02X?}", round_secret2);
    println! ( "label2={:02X?}", label2);
    println! ( "label2={:02X?}", LA2.iter().zip(LB2.iter()).map(|(a, b)| a ^ b).collect::<Vec<u8>>());
    println! ( "context2={:02X?}", context2.as_bytes());

    //let chain_secret_key_mat: Array<u8, U48> = SskdfMac::<HmacReset<Sha256>>::derive_secret_salt_other ( &round_secret2, &label2, context2.as_bytes());
    //let chain_secret_key_mat: Array<u8, U48> = Hkdf::<Sha256>::derive_secrets_salt_others ( [label2.as_slice()], b"KDF", [1u32.to_be_bytes().as_slice(), &round_secret2, &context2.as_bytes()]);
    let chain_secret_key_mat: Array<u8, U48> = Hkdf::<Sha256>::derive_secret_salt_other ( &round_secret2, &label2, context2.as_bytes());

    println! ( "chain_secret_key_mat2={:02X?}", chain_secret_key_mat);
    assert_eq! ( &chain_secret_key_mat[..32], chain_secret2);
    assert_eq! ( &chain_secret_key_mat[32..], key_material2);

    type EtsiHybrid = HybridKem<X25519Kem, MlKem768, EtsiCasKdfCombiner<Hkdf::<Sha256>, EtsiTestVectorsLabel, 0x1722>, U16>;
    //type EtsiHybrid = HybridKem<EcdhKem<NistP256, EcRaw2Encoder<NistP256>>, MlKem768, EtsiCasKdfCombiner<Hkdf<Sha256>, EtsiTestVectorsLabel, 0x1122>, U16>;

    let mut decapsulator = EtsiHybrid::try_from_slice_decap2(&[dA1.as_slice(), &dA2, &zA2].concat()).unwrap();
    decapsulator.set_kdf(EtsiCasKdfCombiner::new_with_labels(&LA1, &LA2, &LB1, &LB2));
    let km_calc2 = decapsulator.try_decapsulate(&[PB1.as_slice(), PB2.as_slice()].concat().try_into().unwrap()).unwrap();
    assert_eq!(km_calc2.as_slice(), key_material2.as_slice());
}



// D.3.5 KDF as HMAC with SHA256, ECDH with Curve25519, and ML-KEM768
#[allow(non_snake_case)]
#[test]
fn test_d_3_5()
{
    let CID = hex!("4722");
    let LA1 = hex!("0102030405060708090A0B0C0D0E0F1101020304050607081020304050607085");
    let dA1 = hex!("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
    let PA1 = hex!("8520F0098930A754748B7DDCB43EF75A0DBF3A0D26381AF4EBA4A98EAA9B4E6A");
    let LB1 = hex!("202030405060708090A0B0C0D0E0F100202030405060708E020304050607080C");
    let PB1 = hex!("DE9EDB7D7B7DC1B4D35B61C2ECE435373F8343C85B78674DADFC7E146F882B4F");
    let _previous_chain_secret = /*psk =*/ hex!("");
    let k1 = hex!("4A5D9D5BA4CE2DE1728E3BF480350F25E07E21C947D19E3376F09B3C1E161742");
    let context1 = "ETSI_QSHKE_TEST_VECTORS_V_1_2";
    let label1 = /*LA1 ^ LB1 */ hex!("212233445566778899AABBCCDDEEFE1121223344556677861223344556677889");
    // MA1 = cid || len(LA1) || LA1 || len(PA1) || PA1
    // MB1 = cid || len(LB1) || LB1 || len(PB1) || PB1
    let chain_secret1 = hex!("66E1C15322867E26BCE237B5BE59BD39EE85F33A351F0E8194CB81A79457DC63");
    let key_material1 = hex!("320DD61D4E5345CB48764C6F39DF0E39");
    let LA2 = hex!("14102030405060708090A0B0C0D0E0F14102030405060708090A0B0C0D0E0F11");
    let zA2 = hex!("a9f93c7b791356b66afcceb745a548c7f6b185e4f45ec1ff1a22acdd96e7a6d8");
    let dA2 = hex!("8d45a2ab49d8c20d4ab5680e5c9d9d0cc9ca8228484946f9afce5b8df6f39d19");
    let PA2 = hex!("06F51174F03C2FE07CC31B0659B87EBF124237811B88B980BC277F8C050B265CBEE1A4AE7145CB9253281BBC291F2808E065
        855FD91C7D14122C589FB21B45FD3B7FBB6562FD53006B565189EC983C7A0D4C21596EF3795AE22ECAD71F75395558B55220
        662BB66C389ED9AB6B784476E1788F34B28B59A4C6F71F9F6A49DA80C4D3107DB2C306968B5600E18285F8BFA293677F699F
        D2D2820DE490F530818D6667686A765FCC0009484D71629C1F148104B462325AC55EF34DD5C7098441A06757CA35C8ADFDAB
        6D36333310241F9970B1B123478DCBB75AE6CA39BB84FFCB23A593C24BC54E74B4086165BB4B10AE39F45447AA4EA5F55762
        386B11051B84B0A688C12C73336FC87164B7FBC7F0B07D2A51BB05560606D5558666CC322963AD3CA2BC1293260A94707770
        C030B2BC9C00477A8D5FF6737961480D48109F66075DA9C8AB516F70A78DA9E444AB65798A2565965A68AD9146FD9267D2A8
        0C4352A0A988157522046620A63D9BA7BBCCAFD50A61384453F8545845B25E7A05745C4B26EF7211200A916241047FDABB66
        936BB7351C04F5CD06A10AE3C459B74BB0CD85044BF8B6BF2B33294014B9D68517CB1A9813230BA08813807A2DFCC6A739B6
        AC79575F19BAB96A7CDED404D0E52508214AD43763A0A048FC36785B2C718F75B3432769C1D2A6240336A82B39D865739AF7
        8E94A92BD7B4703210297FB82E0BE57B97384DB5B24FFA5486C982AF48642D967222A28C6F83E5AD6A59CA486733808BA3BD
        86A780E59888011965A351CA949B0D6C72FB3BA0F867834D166819C252D9600207C88997318B2D204AC3619247A01829484F
        12BCA2E8F16AAC677C9E8AC209F9BCCF019BBDA66E8F073DFBD934E08CA15BE77576029654E049C1C20B1B123E5F0B501356
        28CD2C96A5D0B1EEF48FBE08AC4685247721B128F71DC748452B94A458F39B337BC2305CCC505BB18BF6ABE3EC2C825799B9
        5C13A1F6411CD3B031F3CEC3D99AFC1A28F2019C1BD129A2EA35F06415C8B717337957CAA964E794881257073FF5C12C3C62
        034861C343B7F70B9D475CCC10EA5889910E04CA7EAF0B762DB56962EC40CA47CEB4D228600595CF22421148CF02B4CFCE76
        AD27701F925C01C71C5405534ED54B0100C280DD861D89E967BED4829C568BB76CA500342803835F7983179CDA15899033F7
        97951031138A83669AB4CCB4630058088AA0845FAF7B0761B405AE866C426711EB152889D175E7B20DA03126B7419A766416
        A68AAC0FBC355DA07D6E6339BC0539CEB55711F633B8C7392627497821CB9D7174C4E655B5928BF722C84B8233A0993B6DE0
        2D7364443EA4C73A754B8190243DF936184819E1B8AB6F0B0BFBAC6C47E66DDF11757BE55E0787ADC112C63E644D1B904877
        764D856ABE78B583600CBB2119CB916C689D4543F4D553CAC33AD19B245B4948EF0BA3E7D1151179B9FB2941F3674E5F8771
        677737C435B2383119A3E75434114439506E1B9145FF16B1458879A1039962434151619B77915D033A3FAB7385FE861E4A25
        B125A205C3F1B16972470B2791534B5FB8731B20C03684CCBEB97A1FA4417655BB485C347519710522C357D50C43FC264409
        8533FE549C825F5DC8CA82A0DD908891BB4F92EAAB51CBE036CD6FB59A749269A0A3");
    let LB2 = hex!("202030405060708090A0B0C0D0E0F110202030405060708A0203040506070808");
    let PB2 = hex!("DB3D4F38A49CC5C1C7766573873F3926184923F570FCDBA6D7086BEA39601FADFEBABB2F9ED0EBD86A6468BE03D3B05713DE
        50B5E5D58FFDB5500F2AF7419682BC7857870D1E624C2B48A7E0D30A91F141F0764014FBED12A9F72C958EB53A7ED4A16825
        78B4348A05C183C790FF56D66B23BD601FB372C771F52045E13CA2D6DAB80A165A2159B8F990B5BBF125883DEC0A2AF4A54C
        3F386DE4DF6EE96923E9BB2551753DDC6D1F00D7EE910835082C6260974D11FBA49951DB2E27B47362EC4EBF804327AD9682
        01EDB71BDC8C32887214FB2AAA842AABBE0A4E03FDC695B19610377B9BEA9D371016674E977E9E45382D236365EFEDF56665
        9F9936D9D14CA8595DDF121AE7ACC6056DD6FE1B58DC0F0B23CF5366D2488C4D6361B09875242B3A39374159CF3654ABD25F
        8B080BAE117A5F77D15031AD8B350C6922FFD426EC9F9F80A1918FE722CB7A4B537210EF8A5538A52048BADCE3CAF5C46454
        EEAF413819D57EFBA834D7017F9343B302679A0A28F532E93FE8C5B6AEC3C42C160A3FAD20FA2ABADD29C2564DB59FA25A11
        CA502D11421F7F080A616F9656942932E11BFDCC47B1D8EFFA81D724FFABF4613830631737EB7E52DA78A6B026DB1C4FB80B
        BF2D8F9393875330B2F9C1A124436028BF2624C1E64797ABE2E526967DD99BC21B555A5833A31ACE7969E3ECC64C1697DEC0
        B074108F6B17EFA2A517923B435D8446043FB1A96B2EF3B3D3952F08657997D1D9169FFD14316185EC30457E0FAF7EBA2B5A
        02A01993EC530BB9C44C091D2E9D9BC82951E577D76DC2757F2E04E822B6A29F840887A297202E7389A0999F9E69255DE0A3
        3AEB8CD0B21B7F3B5AA7BFD864CF8FF4FFE78FFF166CAF1B805464D5E4B60EB0277E3BA4F3F3390640F5F16E0B784CC8A679
        40977B2F0202D37A74472161589A7B9E7721CC532904A17AFF8FA86ECDC46A410BD6F9309B2CC310D7941A02A5720CD64241
        B5C13C78A86010805AC74C3B81D83348C63C410451BD2052CE764DA83CF80B2654CB1D033F259DA36039E4DF1A5C4CE3F861
        3E28CFC2B25EAE2A21B425B44D0C998977B3ADF5156BFCA1E357EC3F6B5805B2CDC4D46A4C83154AEF0F50D493BAB0BBCA13
        0E92CA21AF8BDF817F7616B55C4C24C066EBF896F39A7BF50A241561E578BDD931CB07EADD193986C455F8798AB97B8D732D
        37C796E09C1C7ABB978BF666CED961373198607AC355FCF6903B4F3047A1D97C344A2D8B73DB310769CCFB4AE3DA6C4E82DE
        B83BF4060722D9E5A9AFBD3E03B4517E3B7D563F31821D5D8EF7F06F0D92A9F401EA9BEFD52CA8DB331360E603C14A340B80
        6155DE690CD2D92EE6A8EE53BCEED7EEB308D375518C851C109A03EE61960D6CD7CD1FDEE5CC2A401039A15EE4F97A734008
        01A090FBF09BE42119662D06C3FF8217FCFC2C70CDE6E1C2F9A396A2E08A3C22AE3CE90A5C97C9F69EBC1546898A047C9DCA
        D128003A90B29B62F7B093CC90C9CD38104C1A3CE62BEA6A3646EF7E3B9FB7C4C44E78FF650C");
    let _previous_chain_secret = hex!("66E1C15322867E26BCE237B5BE59BD39EE85F33A351F0E8194CB81A79457DC63");
    let k2 = hex!("E3E4F4E9D4F5C9AE03836BB9266C50B033285ACE9BC56F73817CE19679D1429A");
    let context2 = "ETSI_QSHKE_TEST_VECTORS_V_1_2";
    let label2 = hex!("34301070103010F010301070103011E161223344556677820B090F090B090719");
    // MA2 = cid || len(LA2) || LA2 || len(PA2) || PA2
    // MB2 = cid || len(LB2) || LB2 || len(PB2) || PB2
    let chain_secret2 = hex!("FDC9BA444B6BF90BFC286635EB55268F344EC32AA7DB1BDA6B0F4E61790A0344");
    let key_material2 = hex!("37A9900F776007E7FBE40A5486322855");


    let MA1 = message_format(&CID, &[&LA1, &PA1]);
    let MB1 = message_format(&CID, &[&LB1, &PB1]);

    let hhhh = concatenate_and_hash(&[&k1, &MA1, &MB1]);
        
    let round_secret1 = Ktf1::<HmacReset<Sha256>>::derive_secret_salt_other(&[], &[], &hhhh);
    println! ( "round_secret1={:02X?}", round_secret1);
    
    //let chain_secret_key_mat: Array<u8, U48> = Hkdf::<Sha256>::derive_secret_salt_other ( &round_secret1, &label1, context1.as_bytes());
    let chain_secret_key_mat1: Array<u8, U48> = SskdfMac::<HmacReset<Sha256>>::derive_secret_salt_other(&round_secret1, &label1, context1.as_bytes());


    println! ( "chain_secret_key_mat={:02X?}", chain_secret_key_mat1);
    assert_eq! ( &chain_secret_key_mat1[..32], chain_secret1);
    assert_eq! ( &chain_secret_key_mat1[32..], key_material1);   


    let MA2 = message_format(&CID, &[&LA2, &PA2]);
    let MB2 = message_format(&CID, &[&LB2, &PB2]);
    let hhhh2 = concatenate_and_hash(&[&k2, &MA2, &MB2]);

    //let round_secret2 = Ktf1::<HmacReset<Sha256>>::derive_secret_salt_other(&[], &chain_secret1, &hhhh2);
    let round_secret2: Array<u8, U32> = Ktf1::<HmacReset<Sha256>>::derive_secret_salt_other(&[], &chain_secret1, &hhhh2);

    println! ( "round_secret2={:02X?}", round_secret2);
    println! ( "label2={:02X?}", label2);
    println! ( "label2={:02X?}", LA2.iter().zip(LB2.iter()).map(|(a, b)| a ^ b).collect::<Vec<u8>>());
    println! ( "context2={:02X?}", context2.as_bytes());

    //let chain_secret_key_mat: Array<u8, U48> = SskdfMac::<HmacReset<Sha256>>::derive_secret_salt_other ( &round_secret2, &label2, context2.as_bytes());
    //let chain_secret_key_mat: Array<u8, U48> = Hkdf::<Sha256>::derive_secrets_salt_others ( [label2.as_slice()], b"KDF", [1u32.to_be_bytes().as_slice(), &round_secret2, &context2.as_bytes()]);
    //let chain_secret_key_mat: Array<u8, U48> = Hkdf::<Sha256>::derive_secret_salt_other ( &round_secret2, &label2, context2.as_bytes());
    let chain_secret_key_mat2: Array<u8, U48> = SskdfMac::<HmacReset<Sha256>>::derive_secret_salt_other(&round_secret2, &label2, context2.as_bytes());

    println! ( "chain_secret_key_mat2={:02X?}", chain_secret_key_mat2);
    assert_eq! ( &chain_secret_key_mat2[..32], chain_secret2);
    assert_eq! ( &chain_secret_key_mat2[32..], key_material2);

    type EtsiHybrid = HybridKem<X25519Kem, MlKem768, EtsiCasKdfCombiner<SskdfMac::<HmacReset<Sha256>>, EtsiTestVectorsLabel, 0x4722>, U16>;
    //type EtsiHybrid = HybridKem<EcdhKem<NistP256, EcRaw2Encoder<NistP256>>, MlKem768, EtsiCasKdfCombiner<Hkdf<Sha256>, EtsiTestVectorsLabel, 0x1122>, U16>;

    let mut decapsulator = EtsiHybrid::try_from_slice_decap2(&[dA1.as_slice(), &dA2, &zA2].concat()).unwrap();
    decapsulator.set_kdf(EtsiCasKdfCombiner::new_with_labels(&LA1, &LA2, &LB1, &LB2));
    let km_calc2 = decapsulator.try_decapsulate(&[PB1.as_slice(), PB2.as_slice()].concat().try_into().unwrap()).unwrap();
    assert_eq!(km_calc2.as_slice(), key_material2.as_slice());
}


// D.3.6 KDF as KMAC128, ECDH with Curve25519, and ML-KEM768
#[allow(non_snake_case)]
#[test]
fn test_d_3_6()
{
    let CID = hex!("7722");
    let LA1 = hex!("0102030405060708090A0B0C0D0E0F1101020304050607081020304050607085");
    let dA1 = hex!("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
    let PA1 = hex!("8520F0098930A754748B7DDCB43EF75A0DBF3A0D26381AF4EBA4A98EAA9B4E6A");
    let LB1 = hex!("202030405060708090A0B0C0D0E0F100202030405060708E020304050607080C");
    let PB1 = hex!("DE9EDB7D7B7DC1B4D35B61C2ECE435373F8343C85B78674DADFC7E146F882B4F");
    let _previous_chain_secret = /*psk =*/ hex!("");
    let k1 = hex!("4A5D9D5BA4CE2DE1728E3BF480350F25E07E21C947D19E3376F09B3C1E161742");
    let context1 = "ETSI_QSHKE_TEST_VECTORS_V_1_2";
    let label1 = /*LA1 ^ LB1 */ hex!("212233445566778899AABBCCDDEEFE1121223344556677861223344556677889");
    // MA1 = cid || len(LA1) || LA1 || len(PA1) || PA1
    // MB1 = cid || len(LB1) || LB1 || len(PB1) || PB1
    let chain_secret1 = hex!("C92543C00DEB478BDB6416DDEC53020ADA54F4BE288DDD7EA66D5DE96B49A880");
    let key_material1 = hex!("2491C2FBEE1FAAAB2092BBAD5EC91EC7");
    let LA2 = hex!("14102030405060708090A0B0C0D0E0F14102030405060708090A0B0C0D0E0F11");
    let zA2 = hex!("a9f93c7b791356b66afcceb745a548c7f6b185e4f45ec1ff1a22acdd96e7a6d8");
    let dA2 = hex!("8d45a2ab49d8c20d4ab5680e5c9d9d0cc9ca8228484946f9afce5b8df6f39d19");
    let PA2 = hex!("06F51174F03C2FE07CC31B0659B87EBF124237811B88B980BC277F8C050B265CBEE1A4AE7145CB9253281BBC291F2808E065
        855FD91C7D14122C589FB21B45FD3B7FBB6562FD53006B565189EC983C7A0D4C21596EF3795AE22ECAD71F75395558B55220
        662BB66C389ED9AB6B784476E1788F34B28B59A4C6F71F9F6A49DA80C4D3107DB2C306968B5600E18285F8BFA293677F699F
        D2D2820DE490F530818D6667686A765FCC0009484D71629C1F148104B462325AC55EF34DD5C7098441A06757CA35C8ADFDAB
        6D36333310241F9970B1B123478DCBB75AE6CA39BB84FFCB23A593C24BC54E74B4086165BB4B10AE39F45447AA4EA5F55762
        386B11051B84B0A688C12C73336FC87164B7FBC7F0B07D2A51BB05560606D5558666CC322963AD3CA2BC1293260A94707770
        C030B2BC9C00477A8D5FF6737961480D48109F66075DA9C8AB516F70A78DA9E444AB65798A2565965A68AD9146FD9267D2A8
        0C4352A0A988157522046620A63D9BA7BBCCAFD50A61384453F8545845B25E7A05745C4B26EF7211200A916241047FDABB66
        936BB7351C04F5CD06A10AE3C459B74BB0CD85044BF8B6BF2B33294014B9D68517CB1A9813230BA08813807A2DFCC6A739B6
        AC79575F19BAB96A7CDED404D0E52508214AD43763A0A048FC36785B2C718F75B3432769C1D2A6240336A82B39D865739AF7
        8E94A92BD7B4703210297FB82E0BE57B97384DB5B24FFA5486C982AF48642D967222A28C6F83E5AD6A59CA486733808BA3BD
        86A780E59888011965A351CA949B0D6C72FB3BA0F867834D166819C252D9600207C88997318B2D204AC3619247A01829484F
        12BCA2E8F16AAC677C9E8AC209F9BCCF019BBDA66E8F073DFBD934E08CA15BE77576029654E049C1C20B1B123E5F0B501356
        28CD2C96A5D0B1EEF48FBE08AC4685247721B128F71DC748452B94A458F39B337BC2305CCC505BB18BF6ABE3EC2C825799B9
        5C13A1F6411CD3B031F3CEC3D99AFC1A28F2019C1BD129A2EA35F06415C8B717337957CAA964E794881257073FF5C12C3C62
        034861C343B7F70B9D475CCC10EA5889910E04CA7EAF0B762DB56962EC40CA47CEB4D228600595CF22421148CF02B4CFCE76
        AD27701F925C01C71C5405534ED54B0100C280DD861D89E967BED4829C568BB76CA500342803835F7983179CDA15899033F7
        97951031138A83669AB4CCB4630058088AA0845FAF7B0761B405AE866C426711EB152889D175E7B20DA03126B7419A766416
        A68AAC0FBC355DA07D6E6339BC0539CEB55711F633B8C7392627497821CB9D7174C4E655B5928BF722C84B8233A0993B6DE0
        2D7364443EA4C73A754B8190243DF936184819E1B8AB6F0B0BFBAC6C47E66DDF11757BE55E0787ADC112C63E644D1B904877
        764D856ABE78B583600CBB2119CB916C689D4543F4D553CAC33AD19B245B4948EF0BA3E7D1151179B9FB2941F3674E5F8771
        677737C435B2383119A3E75434114439506E1B9145FF16B1458879A1039962434151619B77915D033A3FAB7385FE861E4A25
        B125A205C3F1B16972470B2791534B5FB8731B20C03684CCBEB97A1FA4417655BB485C347519710522C357D50C43FC264409
        8533FE549C825F5DC8CA82A0DD908891BB4F92EAAB51CBE036CD6FB59A749269A0A3");
    let LB2 = hex!("202030405060708090A0B0C0D0E0F110202030405060708A0203040506070808");
    let PB2 = hex!("DB3D4F38A49CC5C1C7766573873F3926184923F570FCDBA6D7086BEA39601FADFEBABB2F9ED0EBD86A6468BE03D3B05713DE
        50B5E5D58FFDB5500F2AF7419682BC7857870D1E624C2B48A7E0D30A91F141F0764014FBED12A9F72C958EB53A7ED4A16825
        78B4348A05C183C790FF56D66B23BD601FB372C771F52045E13CA2D6DAB80A165A2159B8F990B5BBF125883DEC0A2AF4A54C
        3F386DE4DF6EE96923E9BB2551753DDC6D1F00D7EE910835082C6260974D11FBA49951DB2E27B47362EC4EBF804327AD9682
        01EDB71BDC8C32887214FB2AAA842AABBE0A4E03FDC695B19610377B9BEA9D371016674E977E9E45382D236365EFEDF56665
        9F9936D9D14CA8595DDF121AE7ACC6056DD6FE1B58DC0F0B23CF5366D2488C4D6361B09875242B3A39374159CF3654ABD25F
        8B080BAE117A5F77D15031AD8B350C6922FFD426EC9F9F80A1918FE722CB7A4B537210EF8A5538A52048BADCE3CAF5C46454
        EEAF413819D57EFBA834D7017F9343B302679A0A28F532E93FE8C5B6AEC3C42C160A3FAD20FA2ABADD29C2564DB59FA25A11
        CA502D11421F7F080A616F9656942932E11BFDCC47B1D8EFFA81D724FFABF4613830631737EB7E52DA78A6B026DB1C4FB80B
        BF2D8F9393875330B2F9C1A124436028BF2624C1E64797ABE2E526967DD99BC21B555A5833A31ACE7969E3ECC64C1697DEC0
        B074108F6B17EFA2A517923B435D8446043FB1A96B2EF3B3D3952F08657997D1D9169FFD14316185EC30457E0FAF7EBA2B5A
        02A01993EC530BB9C44C091D2E9D9BC82951E577D76DC2757F2E04E822B6A29F840887A297202E7389A0999F9E69255DE0A3
        3AEB8CD0B21B7F3B5AA7BFD864CF8FF4FFE78FFF166CAF1B805464D5E4B60EB0277E3BA4F3F3390640F5F16E0B784CC8A679
        40977B2F0202D37A74472161589A7B9E7721CC532904A17AFF8FA86ECDC46A410BD6F9309B2CC310D7941A02A5720CD64241
        B5C13C78A86010805AC74C3B81D83348C63C410451BD2052CE764DA83CF80B2654CB1D033F259DA36039E4DF1A5C4CE3F861
        3E28CFC2B25EAE2A21B425B44D0C998977B3ADF5156BFCA1E357EC3F6B5805B2CDC4D46A4C83154AEF0F50D493BAB0BBCA13
        0E92CA21AF8BDF817F7616B55C4C24C066EBF896F39A7BF50A241561E578BDD931CB07EADD193986C455F8798AB97B8D732D
        37C796E09C1C7ABB978BF666CED961373198607AC355FCF6903B4F3047A1D97C344A2D8B73DB310769CCFB4AE3DA6C4E82DE
        B83BF4060722D9E5A9AFBD3E03B4517E3B7D563F31821D5D8EF7F06F0D92A9F401EA9BEFD52CA8DB331360E603C14A340B80
        6155DE690CD2D92EE6A8EE53BCEED7EEB308D375518C851C109A03EE61960D6CD7CD1FDEE5CC2A401039A15EE4F97A734008
        01A090FBF09BE42119662D06C3FF8217FCFC2C70CDE6E1C2F9A396A2E08A3C22AE3CE90A5C97C9F69EBC1546898A047C9DCA
        D128003A90B29B62F7B093CC90C9CD38104C1A3CE62BEA6A3646EF7E3B9FB7C4C44E78FF650C");
    let _previous_chain_secret = hex!("C92543C00DEB478BDB6416DDEC53020ADA54F4BE288DDD7EA66D5DE96B49A880");
    let k2 = hex!("E3E4F4E9D4F5C9AE03836BB9266C50B033285ACE9BC56F73817CE19679D1429A");
    let context2 = "ETSI_QSHKE_TEST_VECTORS_V_1_2";
    let label2 = hex!("34301070103010F010301070103011E161223344556677820B090F090B090719");
    //MA2 = cid || len(LA2) || LA2 || len(PA2) || PA2
    //MB2 = cid || len(LB2) || LB2 || len(PB2) || PB2
    let chain_secret2 = hex!("C4A9F090FA80C91A082150B0B5F445F5549F7C9EBC0E0642B794F68851EFD06B");
    let key_material2 = hex!("BF7487D94D53B67C9F73A40293481833");

    let MA1 = message_format(&CID, &[&LA1, &PA1]);
    let MB1 = message_format(&CID, &[&LB1, &PB1]);

    let hhhh = concatenate(&[&k1, &MA1, &MB1]);
    println! ( "MA1={}", hex::encode(&MA1));
    println! ( "MB1={}", hex::encode(&MB1));
    println!( "hhhh={:02X?}", &hhhh );
    
    let round_secret1: Array<u8, U32> = Kmac128Kdf::derive_secret_other(&[0u8; 32], /*b"",*/ &hhhh);
    println! ( "round_secret1={:02X?}", round_secret1);

    //let chain_secret_key_mat1: Array<u8, U48> = Hkdf::<Sha256>::derive_secret_salt_other ( &round_secret1, &label1, context.as_bytes());
    //let km_calc: Array<u8, U16> = Kmac128KdfStatic::derive_secrets_salt_others ( [label.as_slice()], b"KDF", [1u32.to_be_bytes().as_slice(), &k1, &k2, &context_calc]);
    let chain_secret_key_mat1: Array<u8, U48> = Kmac128Kdf::derive_secrets_salt_others([label1.as_slice()], b"KDF", [1u32.to_be_bytes().as_slice(), &round_secret1, context1.as_bytes()]);

    println! ( "chain_secret_key_mat={:02X?}", chain_secret_key_mat1);
    assert_eq! ( &chain_secret_key_mat1[..32], chain_secret1);
    assert_eq! ( &chain_secret_key_mat1[32..], key_material1);

    let MA2 = message_format(&CID, &[&LA2, &PA2]);
    let MB2 = message_format(&CID, &[&LB2, &PB2]);

    let hhhh2 = concatenate(&[&k2, &MA2, &MB2]);

    //let round_secret2 = Ktf1::<HmacReset<Sha256>>::derive_secret_salt_other(&[], &chain_secret1, &hhhh2);
    let round_secret2: Array<u8, U32> = Kmac128Kdf::derive_secret_other(&chain_secret1, /*&[],*/ &hhhh2);

    println! ( "round_secret2={:02X?}", round_secret2);
    println! ( "label2={:02X?}", label2);
    println! ( "context2={:02X?}", context2.as_bytes());

    //let chain_secret_key_mat: Array<u8, U48> = SskdfMac::<HmacReset<Sha256>>::derive_secret_salt_other ( &round_secret2, &label2, context2.as_bytes());
    let chain_secret_key_mat: Array<u8, U48> = Kmac128Kdf::derive_secrets_salt_others ( [label2.as_slice()], b"KDF", [1u32.to_be_bytes().as_slice(), &round_secret2, &context2.as_bytes()]);

    println! ( "chain_secret_key_mat2={:02X?}", chain_secret_key_mat);
    assert_eq! ( &chain_secret_key_mat[..32], chain_secret2);
    assert_eq! ( &chain_secret_key_mat[32..], key_material2);

    type EtsiHybrid = HybridKem<X25519Kem, MlKem768, EtsiCasKdfCombiner<Kmac128Kdf, EtsiTestVectorsLabel, 0x7722>, U16>;

    let mut decapsulator = EtsiHybrid::try_from_slice_decap2(&[dA1.as_slice(), &dA2, &zA2].concat()).unwrap();
    decapsulator.set_kdf(EtsiCasKdfCombiner::new_with_labels(&LA1, &LA2, &LB1, &LB2));
    
    let km_calc2 = decapsulator.try_decapsulate(&[PB1.as_slice(), PB2.as_slice()].concat().try_into().unwrap()).unwrap();
    assert_eq!(km_calc2.as_slice(), key_material2.as_slice());
}