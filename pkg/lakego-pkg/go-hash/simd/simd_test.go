package simd

import (
    "bytes"
    "testing"
    "encoding/hex"
)

func fromHex(s string) []byte {
    h, _ := hex.DecodeString(s)
    return h
}

type testData struct {
    msg []byte
    md []byte
}

func Test_Hash224_Check(t *testing.T) {
   tests := []testData{
        {
           fromHex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"),
           fromHex("cbb4f8a9304b4b043093a94b7059ee36e43ff94a21dc46611f1a7769"),
        },
        {
           fromHex(""),
           fromHex("43e1d53656d7b85d10d5499e28afdef90bb497730d2853c8609b534b"),
        },
        {
           fromHex("cc"),
           fromHex("1f32c0acdce1581c02c93aafac852bba621544aaf9a9259cce7fa169"),
        },
        {
           fromHex("41fb"),
           fromHex("15674f75783ca50b106aeb9f0bacc8b895d9328b26677d4d84cd7700"),
        },
        {
           fromHex("1F877C"),
           fromHex("962e228a4f942e51c2451198bbce4127b571d3811b6d564efd1f9625"),
        },
        {
           fromHex("c1ecfdfc"),
           fromHex("2b1b45a0eaea7f2924cce3e45337cb6815205d5b072833a8acc0ddfa"),
        },
        {
           fromHex("1f66ab4185ed9b6375"),
           fromHex("b56c6ab9077f94d8b278cdba8932a8bc51af6485f64a4a504b8a5fc4"),
        },
        {
           fromHex("a746273228122f381c3b46e4f1"),
           fromHex("10ad4fd67660b7c95283f9b11de3267e9ba734801fa91f2775058122"),
        },
        {
           fromHex("d8dc8fdefbdce9d44e4cbafe78447bae3b5436102a"),
           fromHex("aa2b804cbba1ad272b54fc4666844c6b2a59850cc67800b687a63551"),
        },
        {
           fromHex("aecbb02759f7433d6fcb06963c74061cd83b5b3ffa6f13c6"),
           fromHex("81f5794f6499526430547117f50b3c25dec6cf035427b18df9e16919"),
        },
        {
           fromHex("512a6d292e67ecb2fe486bfe92660953a75484ff4c4f2eca2b0af0edcdd4339c6b2ee4e542"),
           fromHex("bd5aec2eb0d8210268f252b3bbea5767d2d065b104d8a79039cdd242"),
        },
        {
           fromHex("be9684be70340860373c9c482ba517e899fc81baaa12e5c6d7727975d1d41ba8bef788cdb5cf4606c9c1c7f61aed59f97d"),
           fromHex("9aa35fdaa426476c081366ac518f946d36a3dcb30494107765a9ee68"),
        },
        {
           fromHex("7167e1e02be1a7ca69d788666f823ae4eef39271f3c26a5cf7cee05bca83161066dc2e217b330df821103799df6d74810eed363adc4ab99f36046a"),
           fromHex("c79c8d628b55ad6d4f3875c12c3820cb420c5d615abc1797f98aefd9"),
        },
        {
           fromHex("0efa26ac5673167dcacab860932ed612f65ff49b80fa9ae65465e5542cb62075df1c5ae54fba4db807be25b070033efa223bdd5b1d3c94c6e1909c02b620d4b1b3a6c9fed24d70749604"),
           fromHex("2ff22d1cc95210637dec7a37286cf90698596d73c5b751c1ab2b02ea"),
        },
        {
           fromHex("64ec021c9585e01ffe6d31bb50d44c79b6993d72678163db474947a053674619d158016adb243f5c8d50aa92f50ab36e579ff2dabb780a2b529370daa299207cfbcdd3a9a25006d19c4f1fe33e4b1eaec315d8c6ee1e730623fd1941875b924eb57d6d0c2edc4e78d6"),
           fromHex("d14ebc913d70459f1c9b0f73c935a341675c86035916d8cb1ed12f81"),
        },
    }

    h := New224()

    for i, test := range tests {
        h.Reset()
        h.Write(test.msg)
        sum := h.Sum(nil)

        if !bytes.Equal(sum, test.md) {
            t.Errorf("[%d] New224 fail, got %x, want %x", i, sum, test.md)
        }

        // =====

        sum2 := Sum224(test.msg)

        if !bytes.Equal(sum2[:], test.md) {
            t.Errorf("[%d] Sum224 fail, got %x, want %x", i, sum2, test.md)
        }
    }
}

func Test_Hash256_Check(t *testing.T) {
   tests := []testData{
        {
           fromHex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"),
           fromHex("5bebdb816cd3e6c8c2b5a42867a6f41570c4b917f1d3b15aabc17f24679e6acd"),
        },
        {
           fromHex(""),
           fromHex("8029e81e7320e13ed9001dc3d8021fec695b7a25cd43ad805260181c35fcaea8"),
        },
        {
           fromHex("cc"),
           fromHex("4acb11b332c3cb462b60ebbb0dec32ef7a2a3470af49ec5c10aa52a484a640d4"),
        },
        {
           fromHex("41fb"),
           fromHex("4fd086605090c098ec99640723b3e46ce797ada52edf8a96b50500e0306e4eea"),
        },
        {
           fromHex("1F877C"),
           fromHex("42a770e206a956289532677562fac28d19249b9fae54d4e595494a2e4e15aec4"),
        },
        {
           fromHex("c1ecfdfc"),
           fromHex("a97be3876200aa03e5dcc12f2c78abf9e7f0c456e968b2a3d747b3986d4db871"),
        },
        {
           fromHex("1f66ab4185ed9b6375"),
           fromHex("2f358f89bce6966422c4055210e57f9f625b7b53098947aa1774ffefb6f29e62"),
        },
        {
           fromHex("a746273228122f381c3b46e4f1"),
           fromHex("993088cbd2ea7d3227f4434ee36d00363389ad661d7fe8cc475490d339c37a78"),
        },
        {
           fromHex("d8dc8fdefbdce9d44e4cbafe78447bae3b5436102a"),
           fromHex("4f783a0ddafa59f2f5bed60c3834dcd814d2dbd64f38a0997bf032a55dcc0067"),
        },
        {
           fromHex("973cf2b4dcf0bfa872b41194cb05bb4e16760a1840d8343301802576197ec19e2a1493d8f4fb"),
           fromHex("c6596dfb8c07dc9d59ac4abfba7522edef6addb56f255538d63c43fd7ecf5b71"),
        },
        {
           fromHex("ca061a2eb6ceed8881ce2057172d869d73a1951e63d57261384b80ceb5451e77b06cf0f5a0ea15ca907ee1c27eba"),
           fromHex("50a7bc269aefe0671e0db65d4bfedf569eacf60457a862147113b6b71aa5e039"),
        },
        {
           fromHex("416b5cdc9fe951bd361bd7abfc120a5054758eba88fdd68fd84e39d3b09ac25497d36b43cbe7b85a6a3cebda8db4e5549c3ee51bb6fcb6ac1e"),
           fromHex("b05890245c0ea9fc237ad5406e24b538a2f18fc8133cf02b826e53fe2dfaa53d"),
        },
        {
           fromHex("68c8f8849b120e6e0c9969a5866af591a829b92f33cd9a4a3196957a148c49138e1e2f5c7619a6d5edebe995acd81ec8bb9c7b9cfca678d081ea9e25a75d39db04e18d475920ce828b94e72241f24db72546b352a0e4"),
           fromHex("8c1765d6209751564c1768a50208df9ee59129b21a7d8682dfef5aa2b33aa5c8"),
        },
        {
           fromHex("5954bab512cf327d66b5d9f296180080402624ad7628506b555eea8382562324cf452fba4a2130de3e165d11831a270d9cb97ce8c2d32a96f50d71600bb4ca268cf98e90d6496b0a6619a5a8c63db6d8a0634dfc6c7ec8ea9c006b6c456f1b20cd19e781af20454ac880"),
           fromHex("334b78da1f11fb6642e8c7bb2b7ab6dcfb35fc294ec3aabd99c592a4679618eb"),
        },
        {
           fromHex("a62fc595b4096e6336e53fcdfc8d1cc175d71dac9d750a6133d23199eaac288207944cea6b16d27631915b4619f743da2e30a0c00bbdb1bbb35ab852ef3b9aec6b0a8dcc6e9e1abaa3ad62ac0a6c5de765de2c3711b769e3fde44a74016fff82ac46fa8f1797d3b2a726b696e3dea5530439acee3a45c2a51bc32dd055650b"),
           fromHex("0d226fab554ef5bb7ea547ff391382c9d7f38c326c6cb5a9fe71b06ecdcce9db"),
        },
        {
           fromHex("2b6db7ced8665ebe9deb080295218426bdaa7c6da9add2088932cdffbaa1c14129bccdd70f369efb149285858d2b1d155d14de2fdb680a8b027284055182a0cae275234cc9c92863c1b4ab66f304cf0621cd54565f5bff461d3b461bd40df28198e3732501b4860eadd503d26d6e69338f4e0456e9e9baf3d827ae685fb1d817"),
           fromHex("11469a5cd8ece2ed101a655293a07bcf6212366a2f22073375e4005acca401a4"),
        },
    }

    h := New256()

    for i, test := range tests {
        h.Reset()
        h.Write(test.msg)
        sum := h.Sum(nil)

        if !bytes.Equal(sum, test.md) {
            t.Errorf("[%d] New256 fail, got %x, want %x", i, sum, test.md)
        }

        // =====

        sum2 := Sum256(test.msg)

        if !bytes.Equal(sum2[:], test.md) {
            t.Errorf("[%d] Sum256 fail, got %x, want %x", i, sum2, test.md)
        }
    }
}

func Test_Hash384_Check(t *testing.T) {
   tests := []testData{
        {
           fromHex(""),
           fromHex("5fdd62778fc213221890ad3bac742a4af107ce2692d6112e795b54b25dcd5e0f4bf3ef1b770ab34b38f074a5e0ecfcb5"),
        },
        {
           fromHex("cc"),
           fromHex("33154248a9e2bda03d5e3704ef2871c33365d4ba176bc02ff71e00a28c4630f3b8b74239a480a743867f4e984b7b842f"),
        },
        {
           fromHex("41fb"),
           fromHex("532eb0af028ebface47eeb76ce30988a8ca1b116f18a9f2c334c89d5dbb20d0af9b5631c7bda11aca58807c8c81f8f1a"),
        },
        {
           fromHex("1F877C"),
           fromHex("d0e2373343277839b89df8dbd79a6a7d0a8a8026fb2d7b2f02300a8785ccaec567612a56e4ddd16bea238c6ed4832aeb"),
        },
        {
           fromHex("c1ecfdfc"),
           fromHex("69d25fff1040271946848368dc115111ecc2ebd5c453fbb6b4861ffa2af1b74294bdddd4117932e22d858a3463471fbd"),
        },
        {
           fromHex("1f66ab4185ed9b6375"),
           fromHex("71979fab2e4a4dee02dd2b05052b0a5e26247d9dc3270a2b368594f86069641e3b3aa6a67ed91853cc868c6da15ba8e9"),
        },
        {
           fromHex("a746273228122f381c3b46e4f1"),
           fromHex("b520ef30f4b0be661c7e70ed6625fdfdfe96c82b9ed7e529ccc624ce31e1a9f4a11122bca09cce77a30aa8d9beb3262e"),
        },
        {
           fromHex("aecbb02759f7433d6fcb06963c74061cd83b5b3ffa6f13c6"),
           fromHex("8cad92954523960d36e68454de65df4b5c451c1e8995cd7499adaec8f367afd44c05b387788c88d8ea51397e6d63073b"),
        },
        {
           fromHex("62f154ec394d0bc757d045c798c8b87a00e0655d0481a7d2d9fb58d93aedc676b5a0"),
           fromHex("5af5c1477c917bd2cc8eab2c6e8a3d62a6c1fc5f89831aeb2ef421ddb48a7722703ddff381dabc7549e77f8231397880"),
        },
        {
           fromHex("d8faba1f5194c4db5f176fabfff856924ef627a37cd08cf55608bba8f1e324d7c7f157298eabc4dce7d89ce5162499f9"),
           fromHex("2a329317fb362dc8bc0cd5a9f003e13b029a04c5cc6101790c59cbe8341e425ed279661d559f2ab6d3f010df8d92b72a"),
        },
        {
           fromHex("5c5faf66f32e0f8311c32e8da8284a4ed60891a5a7e50fb2956b3cbaa79fc66ca376460e100415401fc2b8518c64502f187ea14bfc9503759705"),
           fromHex("c9deeaecacbc5ec7cd576e9575d3c66438370af7ab8daa0a65d958f08d8f107810f541d45af476f052ffd7d26e1f8b8c"),
        },
        {
           fromHex("abc87763cae1ca98bd8c5b82caba54ac83286f87e9610128ae4de68ac95df5e329c360717bd349f26b872528492ca7c94c2c1e1ef56b74dbb65c2ac351981fdb31d06c77a4"),
           fromHex("9a5b44da4a9015d7feb01c22589f7000e2444e19f143f638897f98bb152e8203c903db5936e02a63650c80e17a02b063"),
        },
        {
           fromHex("b180de1a611111ee7584ba2c4b020598cd574ac77e404e853d15a101c6f5a2e5c801d7d85dc95286a1804c870bb9f00fd4dcb03aa8328275158819dcad7253f3e3d237aeaa7979268a5db1c6ce08a9ec7c2579783c8afc1f91a7"),
           fromHex("761f8dc6c6a8e9903b6c5ecc43420e36ad145b48740ce9593bdfaea92c7b5172c74c1371d38822110b16dce58aa315be"),
        },
        {
           fromHex("b55c10eae0ec684c16d13463f29291bf26c82e2fa0422a99c71db4af14dd9c7f33eda52fd73d017cc0f2dbe734d831f0d820d06d5f89dacc485739144f8cfd4799223b1aff9031a105cb6a029ba71e6e5867d85a554991c38df3c9ef8c1e1e9a7630be61caabca69280c399c1fb7a12d12aefc"),
           fromHex("5976ffaaa314e25194ed2896c37ba6e69c689667188768120da2e52a56d0d70ab8285c7fc8c2e814867610fea2a41935"),
        },
        {
           fromHex("157d5b7e4507f66d9a267476d33831e7bb768d4d04cc3438da12f9010263ea5fcafbde2579db2f6b58f911d593d5f79fb05fe3596e3fa80ff2f761d1b0e57080055c118c53e53cdb63055261d7c9b2b39bd90acc32520cbbdbda2c4fd8856dbcee173132a2679198daf83007a9b5c51511ae49766c792a29520388444ebefe28256fb33d4260439cba73a9479ee00c63"),
           fromHex("2ef0904ca7b90496d1d7f82c66f071b5c5a22ebb474006fa6377db662880c205c92b5108d37a1f53bcad938abcf8a511"),
        },
        {
           fromHex("94f7ca8e1a54234c6d53cc734bb3d3150c8ba8c5f880eab8d25fed13793a9701ebe320509286fd8e422e931d99c98da4df7e70ae447bab8cffd92382d8a77760a259fc4fbd72"),
           fromHex("7ba7b2967269ff2648012c33a08c58c1deadccb20ebc3a77208913f5fb885fb0b2b80ec14321636ea9734682ed51d2f1"),
        },
        {
           fromHex("0e3ab0e054739b00cdb6a87bd12cae024b54cb5e550e6c425360c2e87e59401f5ec24ef0314855f0f56c47695d56a7fb1417693af2a1ed5291f2fee95f75eed54a1b1c2e81226fbff6f63ade584911c71967a8eb70933bc3f5d15bc91b5c2644d9516d3c3a8c154ee48e118bd1442c043c7a0dba5ac5b1d5360aae5b9065"),
           fromHex("23b606fe6a9a9e926c477214704e2f582722f4a24f3de550e158c4decf1a28671ebf43fab15a4aef3705cf93728718fc"),
        },
        {
           fromHex("cb2a234f45e2ecd5863895a451d389a369aab99cfef0d5c9ffca1e6e63f763b5c14fb9b478313c8e8c0efeb3ac9500cf5fd93791b789e67eac12fd038e2547cc8e0fc9db591f33a1e4907c64a922dda23ec9827310b306098554a4a78f050262db5b545b159e1ff1dca6eb734b872343b842c57eafcfda8405eedbb48ef32e99696d135979235c3a05364e371c2d76f1902f1d83146df9495c0a6c57d7bf9ee77e80f9787aee27be1fe126cdc9ef893a4a7dcbbc367e40fe4e1ee90b42ea25af01"),
           fromHex("361f1f8a9a7a721885a783f18c10fb720a331bf63b4dd3a6b040d4569ac741d88cb6b4940f6ad8717c7798744fd06fd9"),
        },
        {
           fromHex("57af971fccaec97435dc2ec9ef0429bcedc6b647729ea168858a6e49ac1071e706f4a5a645ca14e8c7746d65511620682c906c8b86ec901f3dded4167b3f00b06cbfac6aee3728051b3e5ff10b4f9ed8bd0b8da94303c833755b3ca3aeddf0b54bc8d6632138b5d25bab03d17b3458a9d782108006f5bb7de75b5c0ba854b423d8bb801e701e99dc4feaad59bc1c7112453b04d33ea3635639fb802c73c2b71d58a56bbd671b18fe34ed2e3dca38827d63fdb1d4fb3285405004b2b3e26081a8ff08cd6d2b08f8e7b7e90a2ab1ed7a41b1d0128522c2f8bff56a7fe67969422ce839a9d4608f03"),
           fromHex("bcc6e67afa98e2d19d2d7ba985142fc9f382f85076d42ed33dc8c2d7ff2b5fe0fe79e922f1637023b9ecc9d25c3bff99"),
        },
    }

    h := New384()

    for i, test := range tests {
        h.Reset()
        h.Write(test.msg)
        sum := h.Sum(nil)

        if !bytes.Equal(sum, test.md) {
            t.Errorf("[%d] New384 fail, got %x, want %x", i, sum, test.md)
        }

        // =====

        sum2 := Sum384(test.msg)

        if !bytes.Equal(sum2[:], test.md) {
            t.Errorf("[%d] Sum384 fail, got %x, want %x", i, sum2, test.md)
        }
    }
}

func Test_Hash512_Check(t *testing.T) {
   tests := []testData{
        {
           fromHex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f"),
           fromHex("8851ad0a57426b4af57af3294706c0448fa6accf24683fc239871be58ca913fbee53e35c1dedd88016ebd131f2eb0761e97a3048de6e696787fd5f54981d6f2c"),
        },
        {
           fromHex(""),
           fromHex("51a5af7e243cd9a5989f7792c880c4c3168c3d60c4518725fe5757d1f7a69c6366977eaba7905ce2da5d7cfd07773725f0935b55f3efb954996689a49b6d29e0"),
        },
        {
           fromHex("cc"),
           fromHex("6fd2d5e6104bd3966283321234cd40f4ed380cb53a03911b610746466c10a93e41c9b745c79dfde3275980fe82fc8372efc406a9b0bdc8c63a375954e63436e2"),
        },
        {
           fromHex("41fb"),
           fromHex("6dae77bb11d866244840b90196d8268d7b4564593fcaf1ce925e672eb878f8c0ac4fdbe547c4524275a5c982a483c97d4d92ef975447f454c2049139c71bd13c"),
        },
        {
           fromHex("1F877C"),
           fromHex("a15ef9ab0143bf37807c1d5f654106fe1e877adf94aed7e1746f452374359e904f3f996812e6ab16ffcc7c358357dc4e97fbaaaaefdeb02b8e12d59c88be44bd"),
        },
        {
           fromHex("c1ecfdfc"),
           fromHex("a4e5c8f1b1ed3dd14ccaba9f2d974d529e97acc476fe6fe2f0a2ace9272be66452096b561e57541cf16c85a6565401f55bbf9bac0dfc6f957d63966112ef1aa7"),
        },
        {
           fromHex("1f66ab4185ed9b6375"),
           fromHex("26999df82b465a272d5cf97114876dc7fc356126bb129026d800234c5fd20930e9cd1dc57633c5bbde62a282eca53c861353543b7cdbb2ea7ee041d77f5dd659"),
        },
        {
           fromHex("a746273228122f381c3b46e4f1"),
           fromHex("76aa046b22a8ea25a7e90c32ee755b285c246e9bb7be9f7b95cd0f7cf8d2edf79ae910b28c81640844fa076e24a9bd7e7042d17600eb132058d92f12e453e698"),
        },
        {
           fromHex("d8dc8fdefbdce9d44e4cbafe78447bae3b5436102a"),
           fromHex("45af2457bd500ac6a0a5267641f47d7428930072eda65596f240d85b76edfa3c8c41188681c4606b43f8341d70d0a4af962a0c78d8defa3fdf5095d856e51f2d"),
        },
        {
           fromHex("973cf2b4dcf0bfa872b41194cb05bb4e16760a1840d8343301802576197ec19e2a1493d8f4fb"),
           fromHex("71b55bac9db48f08e21574a4cfa7ad725d86503c0b1c281fe8b6cab7e797f69feb7ec94508ede5e5220af156f4d254ca8c0fed85d49e4e365ec51c82d2409593"),
        },
        {
           fromHex("d8faba1f5194c4db5f176fabfff856924ef627a37cd08cf55608bba8f1e324d7c7f157298eabc4dce7d89ce5162499f9"),
           fromHex("bdd5d51f2bb70e2ea7b0f13672c89425c2f541e0d0c06a84cf78acd4476f030bf6335e453ce30c89f3e4e8a0bed0005ce63f2e83114ca569d37a724381de25c5"),
        },
        {
           fromHex("fc424eeb27c18a11c01f39c555d8b78a805b88dba1dc2a42ed5e2c0ec737ff68b2456d80eb85e11714fa3f8eabfb906d3c17964cb4f5e76b29c1765db03d91be37fc"),
           fromHex("b70db1d13a6ba7c7b2d64a67003059be0180c0ffd4417fd319c4f77d11ac6a46809abe7753f8c219e9c34b7a3cab980e87787429b0a31d687c90a495ada04eb6"),
        },
        {
           fromHex("871a0d7a5f36c3da1dfce57acd8ab8487c274fad336bc137ebd6ff4658b547c1dcfab65f037aa58f35ef16aff4abe77ba61f65826f7be681b5b6d5a1ea8085e2ae9cd5cf0991878a311b549a6d6af230"),
           fromHex("c51e398199bb616416c123694386c896d34bda64d63adfc41fb469865ec2727580671311d780613b8f36290cca8d87ec339f090aebf376af3fc2d6f6cdc88305"),
        },
        {
           fromHex("2eeea693f585f4ed6f6f8865bbae47a6908aecd7c429e4bec4f0de1d0ca0183fa201a0cb14a529b7d7ac0e6ff6607a3243ee9fb11bcf3e2304fe75ffcddd6c5c2e2a4cd45f63c962d010645058d36571404a6d2b4f44755434d76998e83409c3205aa1615db44057db991231d2cb42624574f545"),
           fromHex("eee794e6842d87ea13aa9fac4f3e9fe8dbdb93a37f0e5288aedab0ecb1287e1723800cd289f43de0e967c59e95c90856e5a1371a3171515311515f7e2a845efa"),
        },
        {
           fromHex("1755e2d2e5d1c1b0156456b539753ff416651d44698e87002dcf61dcfa2b4e72f264d9ad591df1fdee7b41b2eb00283c5aebb3411323b672eaa145c5125185104f20f335804b02325b6dea65603f349f4d5d8b782dd3469ccd"),
           fromHex("b18521abd3b88549a0f2cc6ae65ce68056e0500e18ed7bc3f52b260b199def4b2c91509fe18108d1774e10966cd91de332b836f37fa03a60a1fa2606324ca6e8"),
        },
        {
           fromHex("dab11dc0b047db0420a585f56c42d93175562852428499f66a0db811fcdddab2f7cdffed1543e5fb72110b64686bc7b6887a538ad44c050f1e42631bc4ec8a9f2a047163d822a38989ee4aab01b4c1f161b062d873b1cfa388fd301514f62224157b9bef423c7783b7aac8d30d65cd1bba8d689c2d"),
           fromHex("e3a9a65d1d7836400189a0f002371ade43accf69d535b14a7aeef27d4ebe7e17d84f294a64cc713372481ff6d272be8fa737976817c106e138a532c907240c38"),
        },
        {
           fromHex("6c4b0a0719573e57248661e98febe326571f9a1ca813d3638531ae28b4860f23c3a3a8ac1c250034a660e2d71e16d3acc4bf9ce215c6f15b1c0fc7e77d3d27157e66da9ceec9258f8f2bf9e02b4ac93793dd6e29e307ede3695a0df63cbdc0fc66fb770813eb149ca2a916911bee4902c47c7802e69e405fe3c04ceb5522792a5503fa829f707272226621f7c488a7698c0d69aa561be9f378"),
           fromHex("90e06ed6fb339ec78cb3cf279ba7c391b25001bcc20c31a56c660c5d77d155ffd0e4a22e9f227b05d0c9ce2afd7bac87d63a08854a83a9e439ea27bd242d3aa4"),
        },
        {
           fromHex("9d9f3a7ecd51b41f6572fd0d0881e30390dfb780991dae7db3b47619134718e6f987810e542619dfaa7b505c76b7350c6432d8bf1cfebdf1069b90a35f0d04cbdf130b0dfc7875f4a4e62cdb8e525aadd7ce842520a482ac18f09442d78305fe85a74e39e760a4837482ed2f437dd13b2ec1042afcf9decdc3e877e50ff4106ad10a525230d11920324a81094da31deab6476aa42f20c84843cfc1c58545ee80352bdd3740dd6a16792ae2d86f11641bb717c2"),
           fromHex("d8a7d41cbca08005af8e9f4b2484bf853f4774426b92a1cca2368d1ab5acf6c6d9c4a9f64b418b945426406dc61ab826e01aa6fa1c589b9583a3f1708c6df879"),
        },
        {
           fromHex("7a6a4f4fdc59a1d223381ae5af498d74b7252ecf59e389e49130c7eaee626e7bd9897effd92017f4ccde66b0440462cdedfd352d8153e6a4c8d7a0812f701cc737b5178c2556f07111200eb627dbc299caa792dfa58f35935299fa3a3519e9b03166dffa159103ffa35e8577f7c0a86c6b46fe13db8e2cdd9dcfba85bdddcce0a7a8e155f81f712d8e9fe646153d3d22c811bd39f830433b2213dd46301941b59293fd0a33e2b63adbd95239bc01315c46fdb678875b3c81e053a40f581cfbec24a1404b1671a1b88a6d06120229518fb13a74ca0ac5ae"),
           fromHex("cabe9ac40d1d515894082106599daeeb141bdd70affdd517ba3b2ae3ee796fba2ffbbeb2b93dc68d2c0c67f836a44e77e8c4ad2e54332d9ba43596471f74f762"),
        },
    }

    h := New512()

    for i, test := range tests {
        h.Reset()
        h.Write(test.msg)
        sum := h.Sum(nil)

        if !bytes.Equal(sum, test.md) {
            t.Errorf("[%d] New512 fail, got %x, want %x", i, sum, test.md)
        }

        // =====

        sum2 := Sum512(test.msg)

        if !bytes.Equal(sum2[:], test.md) {
            t.Errorf("[%d] Sum512 fail, got %x, want %x", i, sum2, test.md)
        }
    }
}
