
use cipher::KeyInit;
use elliptic_curve::consts::*;
use elliptic_curve::point::AffineCoordinates;
use elliptic_curve::sec1::ToSec1Point;

use hex_literal::hex;
use hmac::Mac;
use kdfs::InitSalt;
use kdfs::nistsp800_56::ConcatKdf;
use kdfs::hybrid_array::Array;

use kems::nistsp800_56a::EccOnePassUnifiedCapsulator;
use kems::{Decapsulate, EncapsulateDeterministic2, Capsulator, FromKeys, SetKdf};
use kems::eckem::{EcMqvAuthCapsulator, EcRawEncoder, EcUncompressedEncoder, EcdhAuthCapsulatorCompressed, EcdhKem, SeedAsScalar};
use kems::kem_with_kdf::{CombinerNoKeys, KemWithKdf, KemAuthWithKdf};
    
use p521::NistP521;
use p224::NistP224;
use p256::NistP256;
use p384::NistP384;
use sha2::{Sha224, Sha256, Sha512};


///
/// Test vector from NIST
/// 2016/No Key Confirmation/ECC OnePassDH Unified Scheme/KASValidityTest_ECCOnePassDH_KDFConcat_NOKC_init.fax
/// 
#[test]
#[allow(non_snake_case)]
fn test_cavp_kasvs_ecdh_p256() {
    let dsCAVS = hex!("7f73262f313adb4cca2da50a401e7d1888b07e67ec5efe0fa32be786501f4e6e");
    let QsCAVSx = hex!("8b27d83dcb54328c8282aa46055c49814b9dc68f49a4d29e723e1ecfa1d6f0cb");
    let QsCAVSy = hex!("995e1ec4f5dc04e407dabc434c5b0da15bf033466ae1a32fb7108db414bfd1db");
    let QsCAVS = hex!("8b27d83dcb54328c8282aa46055c49814b9dc68f49a4d29e723e1ecfa1d6f0cb995e1ec4f5dc04e407dabc434c5b0da15bf033466ae1a32fb7108db414bfd1db");
    let _Nonce = hex!("41dc5444dc8c0821a073f4af3728aa50");
    let deIUT = hex!("377eec0e61dd4793221f5bc2707a7a925dc99238ddd7789680499c417481cc65");
    let QeIUTx = hex!("5e593cabc3df8644bd51190fc0e44f49dc550441626a6448f4879005a37bb647");
    let QeIUTy = hex!("92843ce9bc510348e73a7665d4c8829a7811c4bcdf357f237e7391b7e1028206");
    let OI = hex!("a1b2c3d4e54341565369645ff2a7ecdff74a2edbf3c0c951ff92b5a401d73e40c9f8b87c59b76ec48370dbf7ba9e1d");
    let _CAVSTag = hex!("146fbc2b8f18d95e");
    let _Z = hex!("1f951cb28f32c293650e7c29744630cba92b62be1d094df41d6b529e854b843e");
    let _MacData = hex!("5374616e646172642054657374204d65737361676541dc5444dc8c0821a073f4af3728aa50");
    let DKM = hex!("0b4aa3215a8bbee3946949aede77eb18");

    let dsCAVS2 = elliptic_curve::SecretKey::<NistP256>::from_bytes ( &dsCAVS.into() ).unwrap();
    let QsCAVS2 = dsCAVS2.public_key();
    assert! ( QsCAVS2.as_affine().x() == QsCAVSx);
    assert! ( QsCAVS2.as_affine().y() == QsCAVSy);
    
    let deIUT2 = elliptic_curve::SecretKey::<NistP256>::from_bytes ( &deIUT.into() ).unwrap();
    let QeIUT = deIUT2.public_key();
    assert! ( QeIUT.as_affine().x() == QeIUTx);
    assert! ( QeIUT.as_affine().y() == QeIUTy);

    type Kem = KemWithKdf::<EcdhKem::<NistP256, EcRawEncoder<NistP256>, SeedAsScalar>, CombinerNoKeys, ConcatKdf<Sha256>, U16>;
    let mut encapsulator = Kem::from_bytes_encap(&QsCAVS.into());
    encapsulator.set_kdf(ConcatKdf::<Sha256>::new_with_salt(&OI));

    let (c0_calc, k_calc) = encapsulator.encapsulate_deterministic (&deIUT).unwrap();
    assert_eq!( c0_calc[..32], QeIUTx );
    assert_eq!( c0_calc[32..], QeIUTy );
    assert_eq!( k_calc.as_slice(), DKM);

    let mut decapsulator = Kem::from_bytes_decap(&dsCAVS.into());
    decapsulator.set_kdf(ConcatKdf::<Sha256>::new_with_salt(&OI));
    let k_calc2 = decapsulator.decapsulate(&c0_calc).unwrap();
    assert_eq!( k_calc2.as_slice(), DKM);

    // let mut hmac = <hmac::Hmac::<sha2::Sha512> as KeyInit>::new_from_slice(k_calc2.as_slice()).unwrap();
    // hmac.update(&MacData);
    // assert_eq! ( hmac.verify_truncated_left(&CAVSTag), Ok(()));
}



///
/// Test Vector From KASTestVectorsECC2016, 
/// No Key Confirmation -> ECC OnePass MQV Scheme 
/// 
#[test]
#[allow(non_snake_case)]
fn test_cavp_kasvs_mqv1_p384() 
{
    let dsCAVS = hex!("52201eb722b25b2008438dabd8f06a44648e75897ee3e2daaf02443cb5ba88a2f2a6a5a7305dcafefc815b219097ff3f");
    let QsCAVSx = hex!("5f41110f5fd1d2417313a60b34a861eaf293d625523a7e01b0141505efafe4ce6f08753a4e73f11475743612c0b99525");
    let QsCAVSy = hex!("c6a3ac15fc082aa5e8078f0df0e048573a0de7b7ea14c2ba67d09ae4295484eac5f7184826d3729df50e0346ef56a5ba");
    let QsCAVS = hex!("5f41110f5fd1d2417313a60b34a861eaf293d625523a7e01b0141505efafe4ce6f08753a4e73f11475743612c0b99525"
                                "c6a3ac15fc082aa5e8078f0df0e048573a0de7b7ea14c2ba67d09ae4295484eac5f7184826d3729df50e0346ef56a5ba");
    let deCAVS = hex!("cdbc9e095091dc320c5e2bda924874aa82578b2d3818ff46ca9e93d2d744987a0c02c9f5adca817e3a973db04ec32be8");
    let QeCAVSx = hex!("696342c35228a5ee3d04499eb7a0185453279931f360526980eeb22e6703f6ec2c2fa35631b8edb44b5dbd287734dee3");
    let QeCAVSy = hex!("a141e782af5f9593812f20ad18da1896bb859b59df0c5a2894635a66f8879542ae092b3631a17eeb9018bfa8b2c596ec");
    let _Nonce = hex!("21fd95f73f50d7c36672e385af2e2b78");
    let dsIUT = hex!("3f6b4dbbaa0ef12d45d91971690658ed98302a621e05e7fd8baf9a1bdc249fe51540bde7f2a0df999cae82f94627a6e4");
    let QsIUT = hex!("d2052f16b57444d4dd326e76824f35ad195b7c7575001f6f6d8fd91232759f197da21da4506721dd1a8887cfd098a553"
                                "cb00ab2f26630103711786cdef397c77f33a16228bba68386f08f7fc91a44220904592a49e386f5a7ada26c779da6c8c");
    let OI = hex!("434156536964a1b2c3d4e5a6efe967d837b84d76b576a4fac9985fa091572977ac5d49b844c5c9574b42d7d9049e6b");
    let _CAVSTag = hex!("c2b9d3d280cbdb46a2490b50e91f2d21514d6a6766307c87");
    let Z = hex!("5b7c00844ee0b833e30c724ca74d88bed70255e88f7d9233af0a88a4806dd88e202518d5c0c5b4892fb5f6fe077e9a89");
    let _MacData = hex!("5374616e646172642054657374204d65737361676521fd95f73f50d7c36672e385af2e2b78");
    let DKM = hex!("b741877d2d3a42ee098748656400a6dd6b871c526b011622");

    let dsCAVS2 = elliptic_curve::SecretKey::<NistP384>::from_bytes ( &dsCAVS.into() ).unwrap();
    let QsCAVS2 = dsCAVS2.public_key();
    assert_eq!(QsCAVS2.as_affine().x(),QsCAVSx);
    assert_eq!(QsCAVS2.as_affine().y(),QsCAVSy);
    assert_eq!(QsCAVS2.to_uncompressed_point()[1..],QsCAVS);
    // Source, ds,B  Qs,B
    let dsIUT2 = elliptic_curve::SecretKey::<NistP384>::from_bytes ( &dsIUT.into() ).unwrap();
    let QsIUT2 = dsIUT2.public_key();
    assert_eq!(QsIUT2.to_sec1_bytes()[1..],QsIUT);
    // Source ephmeral de,B, Qe,B
    let deCAVS2 = elliptic_curve::SecretKey::<NistP384>::from_bytes ( &deCAVS.into() ).unwrap();
    let QeCAVS2 = deCAVS2.public_key();
    assert_eq!(QeCAVS2.as_affine().x(), QeCAVSx);
    assert_eq!(QeCAVS2.as_affine().y(), QeCAVSy);

    let temp_6 = kems::eckem::mqv2 ( &dsCAVS2, &deCAVS2, &QsIUT2, &QsIUT2);
    assert! ( temp_6.to_affine().x() == Z);

    let temp_e = kems::eckem::mqv2 ( &dsIUT2, &dsIUT2, &QsCAVS2, &QeCAVS2);
    assert!( temp_e.to_affine().x() == Z);

    // With new traits
    type MqvAuthP384ConcatSha512 = KemAuthWithKdf<EcMqvAuthCapsulator<NistP384, EcUncompressedEncoder<NistP384>>, CombinerNoKeys, ConcatKdf<Sha512>, U24>;

    let mut encapsulator = <MqvAuthP384ConcatSha512 as Capsulator>::Encapsulator::from_keys(QsIUT2, dsCAVS2 );
    let kdf = ConcatKdf::<Sha512>::new_with_salt(&OI);
    encapsulator.set_kdf(kdf);
    let (c0_calc, k_calc) = encapsulator.encapsulate_deterministic(&deCAVS).unwrap();

    assert_eq!( k_calc.as_slice(), DKM);

    let kdf = ConcatKdf::<Sha512>::new_with_salt(&OI);

    let mut decapsulator = <MqvAuthP384ConcatSha512 as Capsulator>::Decapsulator::from_keys(QsCAVS2, dsIUT2 );
    decapsulator.set_kdf(kdf);
    let k_calc2 = decapsulator.decapsulate(&c0_calc).unwrap();
    assert_eq!( k_calc2.as_slice(), DKM);

    // let mut hmac = <hmac::Hmac::<sha2::Sha384> as KeyInit>::new_from_slice(k_calc2.as_slice()).unwrap();
    // hmac.update(&MacData);
    // assert_eq! ( hmac.verify_truncated_left(&CAVSTag), Ok(()));

}



///
/// Test vector for NIST
/// 2016/No Key Confirmation/ECC OnePass MQV Scheme/KASValidityTest_ECCOnePassMQV_KDFConcat_NOKC_init.fax
/// 
#[test]
#[allow(non_snake_case, unused)]
fn test_cavp_kasvs_mqv1_p521()
{
    let dsCAVS = hex!("00000171b889127a383ffad39982e3b0e604cc5613471b1fa5efd396dd76b38562dcaa5686c3cfbc98b32d990a1eeda768d80aacf8de8584e93737d927cdfb19fa26f2be");
    let QsCAVSx = hex!("000001e8c21466ca2920eb18cbbd7224e6031d8f92a539873d90af1f1db94473cf8ed83d2960b53d46c9dddabdaec361a15f712e63fd43ebe4e89adbf29b4e5aeabbeafb");
    let QsCAVSy = hex!("00000148afea19d479fd8b4bc555f3bf14c2acf8826ea5d328901cc4a1c53f1643254c37d83a1e057ec412db5b396a83933b1f33e826cdf37817c947eb628bbc5b036748");
    let Nonce = hex!("2dd8a7f9378c4a0d41d965f714f0b58d");
    let dsIUT = hex!("00000030cffdbe8f187554ace3fb7814a40a141a934dcb581df240da1ab3e20a50f850465dfd6a4e0bf78265e16f3a23b85c4d8abff56e83b060dc1dceb45709f9bab9e4");
    let QsIUTx = hex!("0000011634a2c6de5f08cd23e60157065954ffbc5a3b0a3231a7591ff700f4720e69a22e1e5e6a7cac7cc9d0204022c3426fc384ee8d35915c253088010aa9e9b2b556e4");
    let QsIUTy = hex!("0000000565afc19341b2fee1096d310333c227aea83fdc5f5986362d5cccbe4aa071254d23836a48ac6d9cfb79c550e29e58ea50f037b7d86e87691e30550c522f902782");
    let deIUT = hex!("000000eb41b72bd3e91ae8e0b322fd13c01c0fa1a6e285ee1ab891fe34f00aa799da0e33fb4557a95381f71047458fe2b1b44eafe37a7d7c11b7ab02f899e6dad5c3235a");
    let QeIUTx = hex!("000000ca7cc6658c79a72f7e8e65591f648ff42c517332c15d4ec3047b5c4756ec83683d8f1696061fb76a76ab26c8c90efee7cba70eb65c9c4d6e8d0062930021d9deb7");
    let QeIUTy = hex!("000001096a81159dbd64dbcfdb3dfeb264414065518830e61da370f6c617e49cb9c97e8c113f8fad03ace2cc28c97a51ea16c3d0069238e0e1ca138dfaca0c1255968494");
    let OI = hex!("a1b2c3d4e5434156536964df674774f508fdc2f39404edf254cfa8aca8916c83f85d10c5ee8b992ee25d53ae96e321"); // Other Information used in KDF
    let CAVSTag = hex!("338bcc99f9742e68632d89520952a2c88b6a15175dab089030cebd0aad6bdb92"); // MAC of "Standard Test Message" || Nonce
    let Z = hex!("01e33c0f6942d6de68eeb7ad5bfed07bbb16d760441be50f5dd241275c35ae12d2b3d517386456e71b81cb24c9cf58e526b118408cf89961c133b9ce0c60f5cc1c17"); // Shared Secret, x component
    let MacData = hex!("5374616e646172642054657374204d6573736167652dd8a7f9378c4a0d41d965f714f0b58d");
    let DKM = hex!("a04c4bf2ea92d9760cc1eb4f1fc8c4853b8e79f4e224323bf523f831ac010a18"); // Derived Keying Material
    //let Result = P (13 - Z value should have leading 0 nibble )

    let dsCAVS2 = elliptic_curve::SecretKey::<NistP521>::from_bytes ( &Array::<u8, U66>::try_from(&dsCAVS[2..]).unwrap() ).unwrap();
    let QsCAVS2 = dsCAVS2.public_key();
    assert! ( QsCAVS2.as_affine().x().as_slice() == &QsCAVSx[2..]);
    
    // Source, ds,B  Qs,B
    let dsIUT2 = elliptic_curve::SecretKey::<NistP521>::from_bytes ( &Array::<u8, U66>::try_from(&dsIUT[2..]).unwrap() ).unwrap();
    let QsIUT = dsIUT2.public_key();
    assert! ( QsIUT.as_affine().x().as_slice() == &QsIUTx[2..]);
    
    // Source ephmeral de,B, Qe,B
    let deIUT2 = elliptic_curve::SecretKey::<NistP521>::from_bytes ( &Array::<u8, U66>::try_from(&deIUT[2..]).unwrap() ).unwrap();
    let QeIUT = deIUT2.public_key();
    assert! ( QeIUT.as_affine().x().as_slice() == &QeIUTx[2..]);
    
    let z_calc = kems::eckem::mqv2 ( &dsCAVS2, &dsCAVS2, &QsIUT, &QeIUT);
    assert_eq! ( z_calc.to_affine().x().as_slice(), &Z );

    type MqvAuthP521ConcatSha512 = KemAuthWithKdf<EcMqvAuthCapsulator<NistP521, EcUncompressedEncoder<NistP521>>, CombinerNoKeys, ConcatKdf<Sha512>, U32>;

    let mut encapsulator = <MqvAuthP521ConcatSha512 as Capsulator>::Encapsulator::from_keys(QsCAVS2, dsIUT2);
    encapsulator.set_kdf(ConcatKdf::<Sha512>::new_with_salt(&OI));
    let (c0_calc, k_calc) = encapsulator.encapsulate_deterministic(&deIUT[2..]).unwrap();
    assert_eq!( k_calc.as_slice(), DKM);

    let mut decapsulator = <MqvAuthP521ConcatSha512 as Capsulator>::Decapsulator::from_keys(QsIUT, dsCAVS2);
    decapsulator.set_kdf(ConcatKdf::<Sha512>::new_with_salt(&OI));
    let k_calc2 = decapsulator.decapsulate(&c0_calc).unwrap();
    assert_eq!( k_calc2.as_slice(), DKM);

    let mut hmac = <hmac::Hmac::<sha2::Sha512> as KeyInit>::new_from_slice(k_calc2.as_slice()).unwrap();
    hmac.update(&MacData);
    assert_eq! ( hmac.verify_truncated_left(&CAVSTag), Ok(()));
}



///
/// Test vector from NIST
/// No Key Confirmation/ECC OnePass MQV Scheme/KASValidityTest_ECCOnePassMQV_KDFConcat_NOKC_init.fax
/// 
#[test]
#[allow(non_snake_case)]

fn test_cavp_kasvs_mqv1_p224() {
    let dsCAVS = hex!("ab5d7bf269ee2eefa6a3ec1dba12263530ae3b10310b5bdf9173dac6");
    let QsCAVSx = hex!("b39d3ac3641cfe283ed112dab048729ee74da099bddbad2d4ab150cb");
    let QsCAVSy = hex!("3bbf4310380ad82d8b2feae0fe9d9b255c4651631450761e0b42b6cd");
    let _Nonce = hex!("1e4185a1c17ab6bbaf391bea4b2745ca");
    let dsIUT = hex!("35fea0d4eee8cb0a1a8f08b53b93f76874aba803e3f77c50b725dc82");
    let QsIUTx = hex!("0e63a5b7303549028611852c405281ca298133cec53fc3a4d430762e");
    let QsIUTy = hex!("7a3c6bd690b5d59a9544d09a7d5825e68bf968fe4480120c04d0789b");
    let deIUT = hex!("58075633458955c503e66bc62272b33d041e34f2842595070036f8e5");
    let QeIUTx = hex!("8817af3d6b03a366536f195226805ac3300e7e6016b0b02465dcb24c");
    let QeIUTy = hex!("ede0c10f998d3f787bfa8ed563aad3c45603e3f46a123e61258e38e9");
    let OI = hex!("a1b2c3d4e54341565369642609f5a5ab04a5ee00b5c63576b7d50c235b2f70e29c31599a559d90c4b13fc127e3d1d1");
    let CAVSTag = hex!("bb3f5ab9ba91f905");
    let _Z = hex!("43b4e7b9b3dbaf598218e647274bf3d98f393e7d4ed9c0f8e1889c79");
    let MacData = hex!("5374616e646172642054657374204d6573736167651e4185a1c17ab6bbaf391bea4b2745ca");
    let DKM = hex!("29ca1a4b43ae978ba89089dc4e2c");

    let dsCAVS2 = elliptic_curve::SecretKey::<NistP224>::from_bytes ( &dsCAVS.into() ).unwrap();
    let QsCAVS2 = dsCAVS2.public_key();
    assert! ( QsCAVS2.as_affine().x() == QsCAVSx);
    assert! ( QsCAVS2.to_sec1_point(false).y().unwrap() == &QsCAVSy );

    // Source, ds,B  Qs,B
    let dsIUT2 = elliptic_curve::SecretKey::<NistP224>::from_bytes ( &dsIUT.into() ).unwrap();
    let QsIUT = dsIUT2.public_key();
    assert! ( QsIUT.as_affine().x() == QsIUTx);
    assert! ( QsIUT.to_sec1_point(false).y().unwrap() == &QsIUTy);

    // Source ephmeral de,B, Qe,B
    let deIUT2 = elliptic_curve::SecretKey::<NistP224>::from_bytes ( &deIUT.into() ).unwrap();
    let QeIUT = deIUT2.public_key();
    assert! ( QeIUT.as_affine().x() == QeIUTx);
    assert! ( QeIUT.to_sec1_point(false).y().unwrap() == &QeIUTy );

    type MqvAuthP224ConcatSha224 = KemAuthWithKdf<EcMqvAuthCapsulator<NistP224, EcUncompressedEncoder<NistP224>>, CombinerNoKeys, ConcatKdf<Sha224>, U14>;
    
    let mut encapsulator = <MqvAuthP224ConcatSha224 as Capsulator>::Encapsulator::from_keys(QsCAVS2, dsIUT2 );
    encapsulator.set_kdf(ConcatKdf::<Sha224>::new_with_salt(&OI));
    let (c0_calc, k_calc) = encapsulator.encapsulate_deterministic(&deIUT).unwrap();
    assert_eq!( k_calc.as_slice(), DKM);

    let mut decapsulator = <MqvAuthP224ConcatSha224 as Capsulator>::Decapsulator::from_keys(QsIUT, dsCAVS2);
    decapsulator.set_kdf(ConcatKdf::<Sha224>::new_with_salt(&OI));
    let k_calc2 = decapsulator.decapsulate(&c0_calc).unwrap();
    assert_eq!( k_calc2.as_slice(), DKM);

    let mut hmac = <hmac::Hmac::<sha2::Sha512> as KeyInit>::new_from_slice(k_calc2.as_slice()).unwrap();
    hmac.update(&MacData);
    assert_eq! ( hmac.verify_truncated_left(&CAVSTag), Ok(()));
}




///
/// Test vector from NIST 
/// 2016/No Key Confirmation/ECC OnePass Unified Scheme/KASValidityTest_ECCOnePassUnified_KDFConcat_NOKC_init.fax
/// 
#[test]
#[allow(non_snake_case)]
fn test_cavp_kasvs_econepass_unified_p224() {
    let dsCAVS = hex!("6063bf909899dd91e051b4e207fb897f1ba226eea9e11b2696dfece7");
    let QsCAVSx = hex!("6d1d90c87af8d42f3706c765cc6f48bf847ed1ca1580d321568ba4de");
    let QsCAVSy = hex!("9df134d19dcd69263c82f2f7b0a7459c32e106edd7cb017a9e104cfb");
    let _Nonce = hex!("8717ded8ebdb064245488b8b21ccf6a6");
    let dsIUT = hex!("206c5b9a7c482ca92d8a553fc4776832f9c3c72b421f1111030de800");
    let QsIUTx = hex!("9c41bb89986c833559dbba3edfcac5da68933342375d1cc75f9e7c4b");
    let QsIUTy = hex!("88a6e5eaac2ec1ef5389e7a4f35b8da34e26ea6f87e8b8d045d80e93");
    let deIUT = hex!("a9b8015b579483e407f2d91142a81ee738d29b9c81b3ef5db00e511a");
    let QeIUTx = hex!("2f1f5b753799175bd49facaeb890654de35999140111378a009bb22c");
    let QeIUTy = hex!("903444521545e6dc3a190675f3eeb396cbf95872148b03527eb4891d");
    let OI = hex!("a1b2c3d4e543415653696488ffe310eb6932b8738dcf0b3b30342b2f9c5bbab6ab819195212ab5103e65865194513a");
    let _OI_nonce = hex!("a1b2c3d4e5 434156536964 ee6fdfa830611fe4ccdff1c94728292f3061e40cb0dcbedc63994546660daefcb223c7e3 7f67e5fa8246d3d060c73c0f6d80ac29");
                           //            C A V U i d   
    let CAVSTag = hex!("f27458ced21439d1");
    let _Z = hex!("823c48dc319c46780a1c14b77d18dbf901c40338d8628b50a0c88913f42e25b57aee7211f2ee6fdea24c5da666d9474371fea1d2184b4cd0");
    let MacData = hex!("5374616e646172642054657374204d6573736167658717ded8ebdb064245488b8b21ccf6a6");
    let DKM = hex!("ddb3a08a153c2e20ad9bfd93e862");

    let dsCAVS2 = elliptic_curve::SecretKey::<NistP224>::from_bytes ( &dsCAVS.into() ).unwrap();
    let QsCAVS2 = dsCAVS2.public_key();
    assert! ( QsCAVS2.as_affine().x() == QsCAVSx);
    assert! ( QsCAVS2.as_affine().y() == QsCAVSy);
    
    let deIUT2 = elliptic_curve::SecretKey::<NistP224>::from_bytes ( &deIUT.into() ).unwrap();
    let QeIUT = deIUT2.public_key();
    assert! ( QeIUT.as_affine().x() == QeIUTx);
    assert! ( QeIUT.as_affine().y() == QeIUTy);

    let dsIUT2 = elliptic_curve::SecretKey::<NistP224>::from_bytes ( &dsIUT.into() ).unwrap();
    let QsIUT = dsIUT2.public_key();
    assert! ( QsIUT.as_affine().x() == QsIUTx);
    assert! ( QsIUT.as_affine().y() == QsIUTy);

    // With new traits
    let mut encapsulator = <KemAuthWithKdf::<EcdhAuthCapsulatorCompressed<_,SeedAsScalar>, CombinerNoKeys, ConcatKdf<Sha224>, U14> as Capsulator>::Encapsulator::from_keys(QsCAVS2, dsIUT2);
    encapsulator.set_kdf(ConcatKdf::<Sha224>::new_with_salt(&OI));
    let (c0_calc, k_calc) = encapsulator.encapsulate_deterministic(&deIUT).unwrap();
    assert_eq!( k_calc.as_slice(), DKM);

    let mut decapsulator = <KemAuthWithKdf::<EcdhAuthCapsulatorCompressed<_,SeedAsScalar>, CombinerNoKeys, ConcatKdf<Sha224>, U14> as Capsulator>::Decapsulator::from_keys(QsIUT, dsCAVS2);
    decapsulator.set_kdf(ConcatKdf::<Sha224>::new_with_salt(&OI));
    let k_calc2 = decapsulator.decapsulate(&c0_calc).unwrap();
    assert_eq!( k_calc2.as_slice(), DKM);

    let mut hmac = <hmac::Hmac::<sha2::Sha512> as KeyInit>::new_from_slice(k_calc2.as_slice()).unwrap();
    hmac.update(&MacData);
    assert_eq! ( hmac.verify_truncated_left(&CAVSTag), Ok(()));

}

//Result = F (10 - OI changed ),,,,,,,              


///
/// Test Vectors from NIST
/// 2016, No Key Confirmation/ECC OnePass Unified Scheme/KASValidityTest_ECCOnePassUnified_KDFConcat_NOKC_init.fax
/// 
#[test]
#[allow(non_snake_case)]
fn test_cavp_kasvs_econepass_unified_p521() {
    let dsCAVS = hex!("000001befc3cedcdba844442c648c1740c36c274e2233f78b8a4671cadb4c779b7e63850930a7cc807243872a01951d0d38641e324f71493edb5439d5b90e51c177b898b");
    let QsCAVSx = hex!("0000017d3594caa6d3a5815e2a9cc65a8b0cfacfdfa599d2f96ecab75eaa17c8b7244c8abbb871ded4a119a1d7df49ef4f9bc885fb83de2c0783e5197c6c29cce4578633");
    let QsCAVSy = hex!("00000068db9bf4a306d1a63ee7612044e949e9db20c913d956ddd4769ab18601fc8cf9f4afb79cd068489488bdfffd2df9b7c960863b57587bdfb6ec768e08147cc9b9d0");
    let _Nonce = hex!("7364579c227be1d2450990f19f1469bc");
    let dsIUT = hex!("000001b2658eebab68fb94b95e7f0d2100eccc01d304b7326781ed608010c3e7cfb0e1613b2f68b2503bd2b655986c65035cb1a1d68a5faeca3d6a86907dcf2b2aff0561");
    let QsIUTx = hex!("000001765a15324b1fc3ec6abb4820859169fad950ab2d2b202163e73496487017e3367db23020e75363058065505145dea8779a34fc79ffab676f06d44f6db451456ec4");
    let QsIUTy = hex!("000001159a58fbf2610c5e20f7974cdd5ee6739b0a034a8441c450cf52d31475fd5b3c66f32999b727b8323d6016112fe5cc32991616383e0f6d5220679f0dd496fcb3f2");
    let deIUT = hex!("0000009adc30685cc15394cdb9b90b770526a5bc750be97a66d8f9c849cc83a1631da8f9caa385c115c6e9bbb15f4b00aad80fe5c248133c1cbcce24015d76c07a4977ef");
    let QeIUTx = hex!("000001807a9121c12834c5b55c7ef269736adc2bdc61744e9e7599e455b92cd7696e94de3f95fef581fc224071ac9afda6bcb505c352bc7458fe5167edaab694bb32f0d4");
    let QeIUTy = hex!("000000b302942bcb9132072da7a6fd994b4d478287ed7bbdd52e7cd701cad45dc0395650baed19efe29791ff7765a558fe605baf49591e2bc5d880ac36e0aea152a9545f");
    let OI = hex!("a1b2c3d4e5 434156536964 f7aa9cd958eaf8ae5b970f4f0630b3584e681b2edbd6d14b0ceeccd63b30d877429f3f69");
                
    let CAVSTag = hex!("8d7e6ceadf601e7cd64ef775de16dff9c23c1bae3c634dbad3ae223c64913e67");
    let _Z = hex!("009e5a7406ef4da0fa16fe47714b11117b4bf30bcf7677a067ad2b30fe82d4b0f66870590d5ca75228deae886007399a6e9296c5535fb9bd5b4aa11e3e2c3112fd4a00d3d99623d95888c27747ee3865e845dec85ee3d3a8eb5f0afc6ab2e501c907a7413790bb2701daa97880a808e71c68cdc19cde3032a8f0212652b3750c0e1f9948");
    let MacData = hex!("5374616e646172642054657374204d6573736167657364579c227be1d2450990f19f1469bc");
    let DKM = hex!("6a164a9cb2f95b83381e12073988fc7ca59ba5e49689a69cd0d42ed2785913b9");


    let dsCAVS2 = elliptic_curve::SecretKey::<NistP521>::from_bytes ( dsCAVS[2..].try_into().unwrap() ).unwrap();
    let QsCAVS2 = dsCAVS2.public_key();
    assert! ( QsCAVS2.as_affine().x().as_slice() == &QsCAVSx[2..]);
    assert! ( QsCAVS2.as_affine().y().as_slice() == &QsCAVSy[2..]);
    
    let deIUT2 = elliptic_curve::SecretKey::<NistP521>::from_bytes ( deIUT[2..].try_into().unwrap() ).unwrap();
    let QeIUT = deIUT2.public_key();
    assert! ( QeIUT.as_affine().x().as_slice() == &QeIUTx[2..]);

    let dsIUT2 = elliptic_curve::SecretKey::<NistP521>::from_bytes ( dsIUT[2..].try_into().unwrap()).unwrap();
    let QsIUT = dsIUT2.public_key();
    assert! ( QsIUT.as_affine().x().as_slice() == &QsIUTx[2..]);
    assert! ( QsIUT.as_affine().y().as_slice() == &QsIUTy[2..]);

    // With new traits
    let mut encapsulator = <EccOnePassUnifiedCapsulator<NistP521, _, U32> as Capsulator>::Encapsulator::from_keys(QsCAVS2, dsIUT2);
    encapsulator.set_kdf(ConcatKdf::<Sha512>::new_with_salt(&OI));
    let (c0_calc, k_calc) = encapsulator.encapsulate_deterministic(&deIUT[2..]).unwrap();
    assert_eq!( k_calc, DKM);
    assert_eq!( &c0_calc[1..67], &QeIUTx[2..]);
    assert_eq!( &c0_calc[67..], &QeIUTy[2..]);


    let mut decapsulator = <EccOnePassUnifiedCapsulator<NistP521, ConcatKdf<Sha512>, U32> as Capsulator>::Decapsulator::from_keys(QsIUT, dsCAVS2 );
    decapsulator.set_kdf(ConcatKdf::<Sha512>::new_with_salt(&OI));
    let k_calc2 = decapsulator.decapsulate(&c0_calc).unwrap();
    assert_eq!( k_calc2.as_slice(), DKM);

    let mut hmac = <hmac::Hmac::<sha2::Sha512> as KeyInit>::new_from_slice(k_calc2.as_slice()).unwrap();
    hmac.update(&MacData);
    assert_eq! ( hmac.verify_truncated_left(&CAVSTag), Ok(()));
}