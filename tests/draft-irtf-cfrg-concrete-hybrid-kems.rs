use generic_array::GenericArray;
use hex_literal::hex;
use kems::{Capsulator, EncapsulateDeterministic2, EncodeSeed, EncodedSizeUser2, GenerateCapsulatorFromSeed };


// https://datatracker.ietf.org/doc/draft-irtf-cfrg-concrete-hybrid-kems/

#[test]
fn test_a_1_1_mlkem768_p256 () 
{
    let seed = hex!("0000000000000000000000000000000000000000000000000000000000000000");
    let randomness = hex!("646464646464646464646464646464646464646464646464646
                464646464646464646464646464646464646464646464646464
                646464646464646464646464646464646464646464646464646
                464646464646464646464646464646464646464646464646464
                646464646464646464646464646464646464646464646464646
                464646464646464646464646464646464646464646464646464
                64646464646464");
   let encapsulation_key = hex!("3d209f716752f6408e7f89bceef97ac3885300453779
                       27644ef046c0a7cae978c8841a0133aac4f1e1a70272
                       77f671219cf58b85d29c8fec08edd432e787a3cf9936
                       fe0026a113cb9efb1d7214049527bfe2141ea170b029
                       4a59403ab0ce16760a8baa95b823cbb8aacdcc17ef32
                       775223c791e3740163941f9bb3f63346bef1c050c31f
                       932c62719429aff14c2bd438ab135bed692d56c77c04
                       cbbffd6335b578318b513771e84b14ea821262141ca0
                       06ccb8bf2500aa1008970f216fe7f1ae34125aa29049
                       2c069a189222adc322f97649c762c7d3128ad3bb2667
                       971d0744014bc3b67445cbcd0b3e7ea69fb1cb9f9c33
                       1f97487920187292926d04a25a2650abbd44982bb0c3
                       c6301fe6a61330d24d8a3c7021dc3e3392c79a139b37
                       613bba67a2984298507b84a4d61eef18acfb979af2d3
                       9caa4c0db4513815359d76fc378c63a7f4f3053b1716
                       8d0221cf0c2eec5514ba235f81d04d67c3b5c5180949
                       17671c26a7c046457533cc32844581277a03eb065c45
                       29a779a9a5878f2aac3f81db9ed3d8c9345697058cbb
                       99d379bca16d8fdb61d129960390524791b9d3e501b9
                       00bd1e5002e095be06c23f1fb212f5801f24b6b28c0c
                       5493d246d02aa29fa3acfbe15ac4e212eb0b6f69ebbe
                       a259a2703aa4c308224bdb741c65c7a5d4bff7882795
                       07bbfe513d7aa5694e7b3cdf62ab36432742d4a0ca9b
                       3570ba742fa803b46989c8526ea586cc4fc32866143b
                       79601725fa545fd280b404530318bbc3371194710b6d
                       74beaa629eb18a36a953b75915ae96999ba5c88cdc56
                       a46861c50032c9b630bcc1445a30878979bc55a2c095
                       5bf399b231203b90c651b6afe0e242b5a543250b142f
                       7291ed753d816098f7913302a8ce91641716623d4fc2
                       ac6772aa5f3674042b7c4a18a2186289a4ac4e200774
                       596ca03e6798c7506b984999db6ac142586bae0799f1
                       e776f9f5247dc574d8556ddf9bbbc4ca3643263457f7
                       4248010d62d4311268360aecb4902b450bf2050ecb8b
                       a7a92820d233f5a14ed31225a1d17ca6f19e825894cf
                       b1807d922cbd60761134be419144bcf72006366a4460
                       137ad9136c113f05eb54c409520edc72e4150cc3a24b
                       0f819eec11bbd19ca9645b0810a60b4a8a9e9c395539
                       6a1653955b047bcf4f98433c27236c570d75f809e44a
                       af2dc33665826351872c293350ab324518c8c0c80b52
                       1c80c81a56bdc968a5650315a830c8bb17532c62ccc2
                       3b1d46412c256b224fd4674491803501d0143125c757
                       7239689965b6989ca561793c0f85c62a9e13487da176
                       62a7188c70b1040a67ed4c3f85e74e3691822fb96314
                       d6134fe6a626b3cbe1461d62a7b573b2cc75579ffa22
                       967e36ceb2a1aa0b71875a22751d706b72ca9ecd0c81
                       00ad0aa58009a5c83fffe91759e6baa0a9345af99fe3
                       b69509dbc84032868844ab3f65bb1df8beadf36442e4
                       8e339c967023a525411544c789a2f04dacd06ffef783
                       02210450b931f6b4c32aab34a3f5260b810f4c9a946f
                       c22d3baabaa80ba8d9955d6dc35e8609b4256b482cdc
                       9d8977c1a47a354e7c527fdb1672e166917b95cd6351
                       820261daab361f8a2dcbb240c55abd6a8105e5291b42
                       7b566d731e6b7047189cff20d8b120e0b3e72472d1b0
                       086812200fd3698e23f06e4f4e08bbb54cc2049c039c
                       845be659999c8fa48d7f62327c146cf1bc0b0bb1b91b
                       30174b7bc220d422023bff6b0dee263532c503f3982e
                       4d3e27071b855578a9a9aa63b8a8c339bf");
   let decapsulation_key = hex!("00000000000000000000000000000000000000000000
                       00000000000000000000");
   let decapsulation_key_pq = hex!("f5977c8283546a63723bc31d2619124f11db46586
                          43336741df81757d5ad3062221e124311ec7f7181
                          568de7938df805d894f5fded465001a04e260a494
                          82cf5");
   let decapsulation_key_t = hex!("e00b3f9d338de90488973787b0916a4a9ae8bebf4e
                         2bc07a7bc18f1a62215182");
   let ciphertext = hex!("d81018a94f8078e02105beaa814e003390befa4589bb614f773
                97af42d8e8150796f2c88a4efca81b8cf93c0ae3716c54ec1b0
                45e3875f38c2dd12d7f717bd7fb701a9fecda5ed8b764c9a35d
                4a5c1d8930f6071f653eebb2d1afa77debb8302d16f17e0f5f3
                920a71a4d49beafa0e1c7e443f8abca64a65a9e81a97e7357bf
                902573363c0e1a12e5228036828e3f759121fada92441fe334e
                85d79347e470d2fed945541d832c54baaa3cb7526c3853954db
                4f73547cc7c27fd38398bfa7704952cb841e38b270e4db7435f
                0ee22f57d7ad3270bd0c88e71b4b864cf2277c65daa10a6dad4
                c7abecd95cc4ebec39c08404b522e4ecc1545713f76bebd3b5a
                0f2feb3461936065dbd13f6a1f61e1b142a2af2e5a482ba2c50
                cf0317049c0b3bfd6d5e9240eba9111d2030fdea17e33b65240
                20d30b0c4f8069285f3a6ca267d287d01e827d8422bf5426e11
                688bfc73756af1841b1c87e126cb50c914b5b2b8673488ad3b0
                74cad77a3840eb12dd688f313ee1e9ff8c479a678f276356fc9
                d65e1d5b4c1e9855b4175db144f7767c12061769190fe6b5e51
                563b91f94d131a2b796bd2980ed0dab4ae7a7110e920007a757
                158a5eb8662cbf89ddffe9d8196821313cdc00108853fc4746b
                111d5b56da638d8ed2973918960f5dfe93ead3ae521e957cec3
                c8d843e8fce234c70ad055177f235439d6098bdd771b1cfcfad
                aab4f50a7378185c62409f383c8ff658c2a2af66498cfd81e96
                2766ac6b774e88424fb4f331837d0a28502708477caf8780a15
                6d723f68fca791e1cd2397bfc2b24c77c765d9b2af36f732d52
                107517efd8157b283b440a613f756c364ca108971a8878199a9
                3f260baec3e850033cc032c2e53f823576affb4d3b116e2d160
                49152c35aaa263ab376f0ad5ede6a749607a283e3016e62191c
                0e8fde33e718cd989591c9a205d608d99fcb8a7471603d716cb
                01b56328d7d880aec2851f4e6d8b5016c25647e9026ebb44154
                3e8012dbfcf078d4012b8c39184dd64f3821b4774ae4e36365f
                8baf2bd1f6667c017a1e65ff8a1554458fb3f367c02721752bf
                a56fc7fd566ae95ffb208f919ef12f4cf8a2fdd141a8df559bd
                db7b8d1f04ee6d4cf7805d142989caf216dfae985faaab9974f
                6d9f8aa1129084db8db912b1655f595ffbaa66491ab4655fd73
                4cfd4bb0c0289d4bcc8fc5e9943b351cb147c8db059a24004d1
                c3e3bb4c14a881e5101acb736c65c5d579acb67ee85a560277b
                43338fe79d34b772c5da001da3b5a3383dd81319a0b4542e6d7
                e46eed5314cc70eb231de27b6e760db598ba19995cf69be0e44
                58e35f3f274aca2455d43fe3344e183c6dc47c857dbe9907b41
                e41006d91b25adcafc098fe66f7554be8dad493c4f4b1dbf7a5
                1464139db474afab5572f92a2232b59be56a72c0505149dae5c
                de1e602877037de7802b5f6fa47a4c9a3e52d6ca15339920254
                e9ffb53c7b834cc0288ed9905a1841e9390ea94a8898bd4c6b6
                d6027e4d43c7867242515bbeefe12340fc04428a824ea7cf56a
                d2a64ed368b71315d80cee846007cff1d2eea2c3f0f92153730
                4ae598f98dd10d1f102811a4e2d161c3fd8bbb193d4b25bee95
                0ac839c0f9d");
   let shared_secret = hex!("9bd018e869bb01b63fb8f5da374a73d347ea14cb2bc570b1
                   3d0908e2288ec456");

    let (encapsulator, decapsulator) = kems::draft_irtf_cfrg_concrete_hybrid_kems::ConcreteMlKem768P256::derive_from_seed(&seed.into());

    assert_eq!(encapsulator.as_bytes().as_slice(), &encapsulation_key );
    assert_eq!(&decapsulator.as_bytes().as_slice(), &[decapsulation_key_pq.as_slice(), decapsulation_key_t.as_slice()].concat() );
    assert_eq!(&decapsulator.as_seed_bytes().unwrap(), &decapsulation_key );

    let encapsulator = kems::draft_irtf_cfrg_concrete_hybrid_kems::ConcreteMlKem768P256::from_bytes_encap(&GenericArray::from_slice(&encapsulation_key));

    let (c0_calc, k_calc) = encapsulator.encapsulate_deterministic(&randomness).unwrap();
    assert_eq! ( c0_calc.as_ref(), ciphertext );
    assert_eq! ( k_calc, shared_secret );

    println! ( "shared_secret={:02X?}", shared_secret);
                   
}



// https://datatracker.ietf.org/doc/draft-irtf-cfrg-concrete-hybrid-kems/
#[test]
fn test_a_2_1_mlkem768_x25519 ()
{
    let seed = hex!("000000000000000000000000000000000000000000000000000000000
          0000000");
    let randomness = hex!("646464646464646464646464646464646464646464646464646
                464646464646464646464646464646464646464646464646464
                64646464646464646464646464");
    let encapsulation_key = hex!("3d209f716752f6408e7f89bceef97ac3885300453779
                       27644ef046c0a7cae978c8841a0133aac4f1e1a70272
                       77f671219cf58b85d29c8fec08edd432e787a3cf9936
                       fe0026a113cb9efb1d7214049527bfe2141ea170b029
                       4a59403ab0ce16760a8baa95b823cbb8aacdcc17ef32
                       775223c791e3740163941f9bb3f63346bef1c050c31f
                       932c62719429aff14c2bd438ab135bed692d56c77c04
                       cbbffd6335b578318b513771e84b14ea821262141ca0
                       06ccb8bf2500aa1008970f216fe7f1ae34125aa29049
                       2c069a189222adc322f97649c762c7d3128ad3bb2667
                       971d0744014bc3b67445cbcd0b3e7ea69fb1cb9f9c33
                       1f97487920187292926d04a25a2650abbd44982bb0c3
                       c6301fe6a61330d24d8a3c7021dc3e3392c79a139b37
                       613bba67a2984298507b84a4d61eef18acfb979af2d3
                       9caa4c0db4513815359d76fc378c63a7f4f3053b1716
                       8d0221cf0c2eec5514ba235f81d04d67c3b5c5180949
                       17671c26a7c046457533cc32844581277a03eb065c45
                       29a779a9a5878f2aac3f81db9ed3d8c9345697058cbb
                       99d379bca16d8fdb61d129960390524791b9d3e501b9
                       00bd1e5002e095be06c23f1fb212f5801f24b6b28c0c
                       5493d246d02aa29fa3acfbe15ac4e212eb0b6f69ebbe
                       a259a2703aa4c308224bdb741c65c7a5d4bff7882795
                       07bbfe513d7aa5694e7b3cdf62ab36432742d4a0ca9b
                       3570ba742fa803b46989c8526ea586cc4fc32866143b
                       79601725fa545fd280b404530318bbc3371194710b6d
                       74beaa629eb18a36a953b75915ae96999ba5c88cdc56
                       a46861c50032c9b630bcc1445a30878979bc55a2c095
                       5bf399b231203b90c651b6afe0e242b5a543250b142f
                       7291ed753d816098f7913302a8ce91641716623d4fc2
                       ac6772aa5f3674042b7c4a18a2186289a4ac4e200774
                       596ca03e6798c7506b984999db6ac142586bae0799f1
                       e776f9f5247dc574d8556ddf9bbbc4ca3643263457f7
                       4248010d62d4311268360aecb4902b450bf2050ecb8b
                       a7a92820d233f5a14ed31225a1d17ca6f19e825894cf
                       b1807d922cbd60761134be419144bcf72006366a4460
                       137ad9136c113f05eb54c409520edc72e4150cc3a24b
                       0f819eec11bbd19ca9645b0810a60b4a8a9e9c395539
                       6a1653955b047bcf4f98433c27236c570d75f809e44a
                       af2dc33665826351872c293350ab324518c8c0c80b52
                       1c80c81a56bdc968a5650315a830c8bb17532c62ccc2
                       3b1d46412c256b224fd4674491803501d0143125c757
                       7239689965b6989ca561793c0f85c62a9e13487da176
                       62a7188c70b1040a67ed4c3f85e74e3691822fb96314
                       d6134fe6a626b3cbe1461d62a7b573b2cc75579ffa22
                       967e36ceb2a1aa0b71875a22751d706b72ca9ecd0c81
                       00ad0aa58009a5c83fffe91759e6baa0a9345af99fe3
                       b69509dbc84032868844ab3f65bb1df8beadf36442e4
                       8e339c967023a525411544c789a2f04dacd06ffef783
                       02210450b931f6b4c32aab34a3f5260b810f4c9a946f
                       c22d3baabaa80ba8d9955d6dc35e8609b4256b482cdc
                       9d8977c1a47a354e7c527fdb1672e166917b95cd6351
                       820261daab361f8a2dcbb240c55abd6a8105e5291b42
                       7b566d731e6b7047189cff20d8b120e0b3e72472d1b0
                       086812200fd3698e23f06e4f4e08bbb54cc2f63601b7
                       f85accfeea2d17964c66b5194b0f08e18519faaee194
                       e3c102823062");
    let decapsulation_key = hex!("00000000000000000000000000000000000000000000
                       00000000000000000000");
    let decapsulation_key_pq = hex!("f5977c8283546a63723bc31d2619124f11db46586
                          43336741df81757d5ad3062221e124311ec7f7181
                          568de7938df805d894f5fded465001a04e260a494
                          82cf5");
    let decapsulation_key_t = hex!("e00b3f9d338de90488973787b0916a4a9ae8bebf4e
                         2bc07a7bc18f1a62215182");
    let ciphertext = hex!("d81018a94f8078e02105beaa814e003390befa4589bb614f773
                97af42d8e8150796f2c88a4efca81b8cf93c0ae3716c54ec1b0
                45e3875f38c2dd12d7f717bd7fb701a9fecda5ed8b764c9a35d
                4a5c1d8930f6071f653eebb2d1afa77debb8302d16f17e0f5f3
                920a71a4d49beafa0e1c7e443f8abca64a65a9e81a97e7357bf
                902573363c0e1a12e5228036828e3f759121fada92441fe334e
                85d79347e470d2fed945541d832c54baaa3cb7526c3853954db
                4f73547cc7c27fd38398bfa7704952cb841e38b270e4db7435f
                0ee22f57d7ad3270bd0c88e71b4b864cf2277c65daa10a6dad4
                c7abecd95cc4ebec39c08404b522e4ecc1545713f76bebd3b5a
                0f2feb3461936065dbd13f6a1f61e1b142a2af2e5a482ba2c50
                cf0317049c0b3bfd6d5e9240eba9111d2030fdea17e33b65240
                20d30b0c4f8069285f3a6ca267d287d01e827d8422bf5426e11
                688bfc73756af1841b1c87e126cb50c914b5b2b8673488ad3b0
                74cad77a3840eb12dd688f313ee1e9ff8c479a678f276356fc9
                d65e1d5b4c1e9855b4175db144f7767c12061769190fe6b5e51
                563b91f94d131a2b796bd2980ed0dab4ae7a7110e920007a757
                158a5eb8662cbf89ddffe9d8196821313cdc00108853fc4746b
                111d5b56da638d8ed2973918960f5dfe93ead3ae521e957cec3
                c8d843e8fce234c70ad055177f235439d6098bdd771b1cfcfad
                aab4f50a7378185c62409f383c8ff658c2a2af66498cfd81e96
                2766ac6b774e88424fb4f331837d0a28502708477caf8780a15
                6d723f68fca791e1cd2397bfc2b24c77c765d9b2af36f732d52
                107517efd8157b283b440a613f756c364ca108971a8878199a9
                3f260baec3e850033cc032c2e53f823576affb4d3b116e2d160
                49152c35aaa263ab376f0ad5ede6a749607a283e3016e62191c
                0e8fde33e718cd989591c9a205d608d99fcb8a7471603d716cb
                01b56328d7d880aec2851f4e6d8b5016c25647e9026ebb44154
                3e8012dbfcf078d4012b8c39184dd64f3821b4774ae4e36365f
                8baf2bd1f6667c017a1e65ff8a1554458fb3f367c02721752bf
                a56fc7fd566ae95ffb208f919ef12f4cf8a2fdd141a8df559bd
                db7b8d1f04ee6d4cf7805d142989caf216dfae985faaab9974f
                6d9f8aa1129084db8db912b1655f595ffbaa66491ab4655fd73
                4cfd4bb0c0289d4bcc8fc5e9943b351cb147c8db059a24004d1
                c3e3bb4c14a881e5101acb736c65c5d579acb67ee85a560277b
                43338fe79d34b772c5da001da3b5a3383dd81319a0b4542e6d7
                e46eed5314cc70eb231de27b6e760db598ba19995cf69be0e44
                58e35f3f274aca2455d43fe3344e183c6dc47c857dbe9907b41
                e41006d91b25adcafc098fe66f7554be8dad493c4f4b1dbf7a5
                1464139db474afab5572f92a2232b59be56a72c0505149dae5c
                de1e602877037de7802b5f6fa47a4c9a3e52d6ca15339920254
                e9ffb53c7b834cc0288ed9905a1841e9390ea94a8898bd4c6b6
                d6027e4d43c7867242515bbeefe12340fc6b3d57762f8badb69
                433f9c6d060f85f5e5c6b6803a816d141c075f63541ad10");
    let shared_secret = hex!("e5ba94031ea6efd69c09c254f6d9783136ba6037e2d4c43b
                   cccf19d6f3f4343a");

    let (encapsulator, decapsulator) = kems::xwing::XwingMlKem768X25519::derive_from_seed(&seed.into());

    assert_eq!(encapsulator.as_bytes().as_slice(), &encapsulation_key );
    assert_eq!(&decapsulator.as_bytes().as_slice(), &[decapsulation_key_pq.as_slice(), decapsulation_key_t.as_slice()].concat() );
    assert_eq!(&decapsulator.as_seed_bytes().unwrap(), &decapsulation_key );

    let encapsulator = kems::xwing::XwingMlKem768X25519::from_bytes_encap(&GenericArray::from_slice(&encapsulation_key));

    let (c0_calc, k_calc) = encapsulator.encapsulate_deterministic(&randomness).unwrap();
    assert_eq! ( c0_calc.as_ref(), ciphertext );
    assert_eq! ( k_calc, shared_secret );

    println! ( "shared_secret={:02X?}", shared_secret);
}




// https://datatracker.ietf.org/doc/draft-irtf-cfrg-concrete-hybrid-kems/
#[test]
fn test_a_3_1_mlkem1024_p384 ()
{

    let seed = hex!("000000000000000000000000000000000000000000000000000000000
          0000000");
    let randomness = hex!("646464646464646464646464646464646464646464646464646
                464646464646464646464646464646464646464646464646464
                646464646464646464646464646464646464646464646464646
                4646464");
    let encapsulation_key = hex!("a10bc8b554cd51980cdbbccc3041420fd320fe8b74c7
                       a84278c63c17070dc231b61ab269b9d677d920261186
                       654b4571f51797d5c342b8070bc6c92bca16adecc631
                       e4e94c7508b111730c749c73e2d6a6f97155cb269ccc
                       06a71a21bef3d269463c935048a7f4636c7b32007370
                       9023f7b04d0530571a9a6f718280870bb63875d3f599
                       bc229b95869cd5bb5d26640856d40b828198fdf2c099
                       998ffdf772e462336c521cd326b5e4997bd95c135c57
                       bd02c7afa80a2923d510951778ee5125b2aa18f90445
                       453b85789224725b259279698ac9426c882baabc38d4
                       fb3a3f6831180918b9825e0e418154d78aebab5e7e70
                       66e69b2567476bf1177fe079a38298be6f01b098c338
                       51ab25312b52e32a5750c2b73d293c0b810473b310aa
                       f062f19914c7377b2e90388f575bf5e6853453b95a74
                       aa18d62d4ae37e6996a48ab5217488a92d7b01e315c5
                       0b68204143792afc4f8367c0ce065ab32014bdb5515f
                       e0594608aad1218994724afaaaa2df0355f46666b6e0
                       2a387b6d3da4713edb610bb048c3a2078b800e9ea483
                       f2009c96d24c71b2cbc8e1200c0277383c5c27895e29
                       8c3607701ce58702a91903274a041408234cb0021ef2
                       b1c5131419b444dc84b89d147d1fe43c43f676d90673
                       5d9ca2a59c2232d97fd4aa1ae2bb3d1b170ca553cb25
                       74954fdc6689fac623cbaa31982d82424d5a564fef7a
                       8ba51b44df15053b2b45bec4aa1ed49929123daf7541
                       75c5938258c608b24d062042ab4bbee5e553a5ea6275
                       21738ae5ab2e06bd98b020787b2f5fa51eb4c46c2bf9
                       0e55a49560340667f88ac41432b7f551dfd98c037c79
                       f79b41b985a8b1f51345550cd816714362040778c43e
                       378a288394bd028c8c31b5a904bc4a5648a596035cb3
                       8f0e276e12c9a96f8425056b05a136642dd2cb754630
                       36485ba1a50539e420e1e31dfac529cad6c68ec06746
                       749473e050a4ac92b7199beceb239b6c12c8e716b666
                       07aeca64a5850b01f99d0b176a7759781ed77cb1ba40
                       d17ac5c6cb06c942c002c2cf6efcb121f10ad2a45ff7
                       81426e7104cbdca73b81865ab22b00ba834355ae485a
                       262f354248932c2be178369a3dd7e2428fdc379346ab
                       2b754c43db657460cb09c5c48b5810cb7a5c6156cf87
                       440c9e36a4869a8ac458b382fc178915a9ce1bcdda7c
                       48807c207e656ffb80bf33e32bc8c7b20ef60572612c
                       eac99ad1c56ce5a764b29b74c17a5b510b1afcb18a1a
                       fc35c12ac213725325f9b7a2eb338fe4c0080c31a58a
                       995db7027d900e78544887f90ada467d0e383c119c53
                       99310bc6735874e8804ff6c2bae57f2c3357cb627033
                       c12a5924b20ce5abf113172bd2b77086cac543811793
                       bba71734c9f005ac2656460bc30a442b388725758a62
                       3e37ba6e293abfb84f344229f373c214ca776a7c05ad
                       c465fed93b9cf77f0022ab71f1adde369dd8f420a58c
                       057c14cc18dc47da7c12b086473eab419652967001c4
                       e42a381c8ba539a875d21a9945133bab9bc1e53a600d
                       e77cbfb2aeab6b19ced4c6eaa8998ee6a1577255f713
                       2d80a32d6c0c6ec44c9c4b28699a645bb0bc958e0027
                       5077925309519b0824c7000dfa61912ec049063a067d
                       00b059053e508a5bfee63473869c8a8510af898cd757
                       2854f5c38af96f5f97a7372632ea7bb4b6fb831c612a
                       f71191ff9806b379bcd43c6059b7b1f953741444af71
                       3c155d962722b947aa23a32a89b356a6a7508aad6396
                       8c1dea78ff18aac27a89aa7b42b0d7481dd3cc649421
                       e51397782218ac5441760ba51a0328d66b436fec32d7
                       aa4d68e0cad1bc14f7241c903480f809983fc2c30d93
                       138cf63b59bc737ac08192893d039187a811bef3d320
                       9eb7b8d1e05b5b251cef760a210b2732867ab32049ba
                       3c354e3858aee7b71df792924730d8e842e484122b50
                       677b0a306e61cf21b62091da18b937192936a09e5a41
                       8cf78b666157dd477af1c36a12320129522840e37094
                       1157808782a5335b0ac10d70e1beafd401074b84b982
                       6cc58aad217bae0f419b2da896133272d8f22c6f420f
                       cc738fccc1082fc93c7df0994c6bcf2cc8a29037b6bb
                       2b4bcef4b0ee8caf8506bc5ecba082a56806c1cede0b
                       944338a69a668254c1150ae05030e256b2b67661ba02
                       7d97576da613ac8c7c29051f1240b96b0c127e264d5e
                       1dbbfe9561a567d5c9103673b446b3ccea6c5f7f34f0
                       9348a5d4a58b0498871dc940ee97b50c0336f9a60c32
                       99f99560ac70657a27befa702265ce590583e04a2832
                       6092d3dea2118dd1df5e81d7d3014ec4b5ce67dcb45e
                       f001769dd5d5ada76934d38d740924712bfae672169d
                       8f8744c151346d285fbb653f83aa0f");
    let decapsulation_key = hex!("00000000000000000000000000000000000000000000
                       00000000000000000000");
    let decapsulation_key_pq = hex!("f5977c8283546a63723bc31d2619124f11db46586
                          43336741df81757d5ad3062221e124311ec7f7181
                          568de7938df805d894f5fded465001a04e260a494
                          82cf5");
    let decapsulation_key_t = hex!("e00b3f9d338de90488973787b0916a4a9ae8bebf4e
                         2bc07a7bc18f1a6221518238c5c4b1760c4ea8a9e4
                         7beb174f12d2");
    let ciphertext = hex!("dc63d18bb9715fb6e3ba71cb439fcd3377a75305cc9b144e675
                8bf5794a272e6b4a0da33234c0ac1bb5b4e60e4c82eb1fb780d
                59e4e4616641a0595ba031e3ae69d971dcd5fff14e21731a8e1
                a221f46c7820d214630b707fa1b0de3a484698f3d49e0a75f12
                12b8c42d330dd909f15eac0402f19ee77fba9447e1c44304b0d
                8c371c17c5549fdbdec1e0a2e7be9f577d7a4b5b2618d9ba67a
                b95a0297cd5c5a13c89cc5a57cbd9a8ae38d66455c9a3d2bc55
                b498775fee2f6dc224d376d5f526a8354c8ed724f60337e900b
                85627972383e1fd987d407a8834005814a4fdc94c947e5f3471
                459288cfb127952b3208f10c914200bbaac5fcebd2bc9e28484
                92bab17b9288ca8b81d1c2ac9522dcc0b6d5f51e10f3afbb5d6
                5fbf919edef6323c4e92c6b0690c10db25a9182de9e919ea1b3
                e65ae6150635d5180ebd7d23a2264828bc3ee1fd34dba1924ad
                0db30c747e05baa9148f1a032769c685e04665fd802a79c4624
                f69a9198a426eac1b217d903cdacf8844e73365f3a219a700dd
                a27edf6bea33602617c5fd105b301b884bfaaa1163b791ec09f
                82523fef65c87b75ed063ceb127729b82c8712e1f41b547d095
                f55ee71f3f8b47a306cb5d9bdd817854c74a42eebf934a1136d
                ea3fbc546ad8ce51b3171913722f08b0261d197590342bfe410
                8dcb08c62a98610cbfb8d3b2831f56dcac2220e29a5811f38f0
                824f21a6cbebc64fd89a09b110dffbe03799ffc74fe565c80db
                f6a66acd7bfd14cb90acba03405a7982d4c1c68caa75f8b72e4
                dd6401d7dce4db4f6b820a7886a604b66b4e5b9eea5e5eddc2b
                ca458a25977bd1f02874c5d9daf2baf56b3040f24ce7fe14cc1
                4d61c7960db4decb37d9779c8e36d69a7763066d8c1149312d2
                6887a693dc222daa892dd00cd8f3a558cf605e4c65c011c2e9f
                0d671ba10af2bb90ee0351ae5078eb7878399ec9eb4ace87a68
                269618bda12a7aed6fda0385496c5d10ac36b35255f4a31edfa
                8a2c516b65c63431013ed4909ec7a787a5efb9d3c3887b80ac1
                8a44934b6559bd8a84b18e86fa1b0b9e1d9f92ba495ba5595d8
                2e5095612b79e805154bf428a7071662c7cefb6450165c6f8f6
                954c37219bff4a49894a8aa37f940a40f4ec942c281e6c47ea4
                08199927a724ff1c7460fc8fd47a98d0c9d4d1f07994d8084f6
                e084935ad7c2985282fabd5ca13b942e10d35278f4ff4cb1cb9
                6f3c862410e79144a46b4db1a3c3d4d63018ec5c01ca48cb670
                81482e7d434b4abe5fa3071f2fbb533f745602b0da6183b28e6
                c5dfa42dab7ae0bbbf7638e106be1bd7312cba399e08c96dbd6
                9a128a2face2d4a02951533a25e82fe63d0aaaa2e8c75150215
                c93ab06c22f9cab8d1cae7424f8baa09b3260ecfa3c7c8d55a2
                76b4b317f72ec86b1b145a63aca83ef8c1204d8ab0c96ea3f74
                2de39db47020616e139285814f188029ace4587f14cf12b5ed8
                1086d8213cf8cb578341e04e16f519b77ff4c2644a5732639d6
                58d0c4eaf992bd7dbd5011b700a5fa63dc1b24a84a3c80656ba
                b5705dc3a74312c80e8bdb24a7ac6e27bcb8c07ece62c6e5777
                dd3dc0657181f440c7524d907dd27950bcb252aef7f8cbf453c
                ee3fe3143a665072c787cea76de323aa41537df2f3a40a518a6
                94b918953bde8d57084e32d3b1fdcf9d153e73f02624beaf6eb
                e23e6828a6a489583494f3cd790fc96bb6f5d8b198402965e2e
                668e6581e7cf1c8a47a92198388f2b4cd38df660f0ddd48ad12
                6819c4435af3a12c89113d778ac544fd8079cb8aaa97d2ff1b6
                08da574c4dcd87f4979390de3be405f0e47788dd0b016628050
                79fd73c64e9278c036544add3694c838bfcfb08c8a5efb09549
                442123eaa59fa30fbb9198105f6be00163bac076193f6721c53
                9714108bbfae167f5db8085c5838618f32a968bbb25c40645a1
                7c17b9bec64aea45832eec5adc25b53e677f67566fbf5ce2d91
                93a06bd9b477e601d589b25f422defc49105252cd9ca6adcbb3
                6be8a01a8472b4d463f655be14ccff9b0571a2048e31c14b9b2
                3e2d43fafa3f85ece6fd41896cc5c68993dbaa926f285ec94c7
                2887de9564881d735c05f83aa474b3d4cd133a630ac63850771
                cb5270f6cb7a391170d66af3e4901b6eb0253f3f34ef57d6bab
                d97aa99ce718c3bcb53ff13d4028a0c943bb9681106ce176242
                cccb75df1d3f8d3706e5b068b042c3154d5e6292581b36499e6
                b069b9a490aa67f0675390539da8555e6a4e8a35a86fdfea83e
                1387bf4acc650ec1edae7c99aa3a48306ee1d1a5e513c0c6901
                f64d0a3ee285de3c11d49f90cd4323dafda14832f0d8b760c0e
                5a48633c967cfaf");
    let shared_secret = hex!("8c028c6ea72a1c59408e2b15dd8fed8008517e861cd2329b
                   159bda1919ea656c");

    let (encapsulator, decapsulator) = kems::draft_irtf_cfrg_concrete_hybrid_kems::ConcreteMlKem1024P384::derive_from_seed(&seed.into());

    assert_eq!(encapsulator.as_bytes().as_slice(), &encapsulation_key );
    assert_eq!(&decapsulator.as_bytes().as_slice(), &[decapsulation_key_pq.as_slice(), decapsulation_key_t.as_slice()].concat() );
    assert_eq!(&decapsulator.as_seed_bytes().unwrap(), &decapsulation_key );

    let encapsulator = kems::draft_irtf_cfrg_concrete_hybrid_kems::ConcreteMlKem1024P384::from_bytes_encap(&GenericArray::from_slice(&encapsulation_key));

    let (c0_calc, k_calc) = encapsulator.encapsulate_deterministic(&randomness).unwrap();
    assert_eq! ( c0_calc.as_ref(), ciphertext );
    assert_eq! ( k_calc, shared_secret );

    println! ( "shared_secret={:02X?}", shared_secret);
}