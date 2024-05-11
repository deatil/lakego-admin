package skeins

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

func Test_HashHS224_Check(t *testing.T) {
   tests := []testData{
        {
           fromHex(""),
           fromHex("1f18a672ca5d4aa91b1035f85f21468cc9ffd5e23cb14b19ba80c8b9"),
        },
        {
           fromHex("cc"),
           fromHex("5b8196077ce5e8a545cd5f7d92eca8ac079e950b46ddfcf04752f9b5"),
        },
        {
           fromHex("1F877C"),
           fromHex("13a3d46e3b288daf1b39ce7e9d8fbdbfa68a9fcaa4366cbb89f11fed"),
        },

        {
           fromHex("1f66ab4185ed9b6375"),
           fromHex("018b6cd33a42aa93eb7f7d60b465e58130b4b20f359b3ed321d8016b"),
        },
        {
           fromHex("a746273228122f381c3b46e4f1"),
           fromHex("ba8de86c06f244aca0111da3e376764fdfe99513a531bc36935c63aa"),
        },
        {
           fromHex("03d9f92b2c565709a568724a0aff90f8f347f43b02338f94a03ed32e6f33666ff5802da4c81bdce0d0e86c04afd4edc2fc8b4141c2975b6f07639b1994c973d9a9afce3d9d365862003498513bfa166d2629e314d97441667b007414e739d7febf0fe3c32c17aa188a8683"),
           fromHex("841e82ccc3652edd0ce4eed218a8430f3723072ca7430c81af73f346"),
        },
    }

    iv := [4]uint64{
        0xCCD0616248677224, 0xCBA65CF3A92339EF,
        0x8CCD69D652FF4B64, 0x398AED7B3AB890B4,
    }

    h := NewHS224(iv)

    for i, test := range tests {
        h.Reset()
        h.Write(test.msg)
        sum := h.Sum(nil)

        if !bytes.Equal(sum, test.md) {
            t.Errorf("[%d] NewHS224 fail, got %x, want %x", i, sum, test.md)
        }
    }
}

func Test_HashHS256_Check(t *testing.T) {
   tests := []testData{
        {
           fromHex(""),
           fromHex("dc41c46b107e7cbe55b5d9c4a119c5f9d448bee67fc84f6337c355b096d7163f"),
        },
        {
           fromHex("cc"),
           fromHex("93bd18b5de8dff951e187ab6c681c2aa2cd63a2b1acd9529cf2795b843cb762e"),
        },
        {
           fromHex("1F877C"),
           fromHex("0531d9b94efa9347f5196f5bfd09f04fe5f572944f3074c056c5feb2142d1d5d"),
        },

        {
           fromHex("1f66ab4185ed9b6375"),
           fromHex("4ecbbffb4cfa05f2b961bdd6c43c707dad5b6a766fbdf5fe1984fa61f5d05061"),
        },
        {
           fromHex("a746273228122f381c3b46e4f1"),
           fromHex("a4b86177b09ecc15e3d23f35132f0164537590464e88b21b0353a5ee100b750d"),
        },
        {
           fromHex("03d9f92b2c565709a568724a0aff90f8f347f43b02338f94a03ed32e6f33666ff5802da4c81bdce0d0e86c04afd4edc2fc8b4141c2975b6f07639b1994c973d9a9afce3d9d365862003498513bfa166d2629e314d97441667b007414e739d7febf0fe3c32c17aa188a8683"),
           fromHex("e0ed645c3a7776d90cf5fa441f1ece1abd0564018f2db01d4e54c80b9a9e2335"),
        },
    }

    iv := [4]uint64{
        0xCCD044A12FDB3E13, 0xE83590301A79A9EB,
        0x55AEA0614F816E6F, 0x2A2767A4AE9B94DB,
    }

    h := NewHS256(iv)

    for i, test := range tests {
        h.Reset()
        h.Write(test.msg)
        sum := h.Sum(nil)

        if !bytes.Equal(sum, test.md) {
            t.Errorf("[%d] NewHS256 fail, got %x, want %x", i, sum, test.md)
        }
    }
}

// ======

func Test_Hash224_Check(t *testing.T) {
   tests := []testData{
        {
           fromHex(""),
           fromHex("1541ae9fc3ebe24eb758ccb1fd60c2c31a9ebfe65b220086e7819e25"),
        },
        {
           fromHex("cc"),
           fromHex("23f031a6a4378039b66a5a178bad217eaec094b7fcba663a47ddcf33"),
        },
        {
           fromHex("41fb"),
           fromHex("b9caaa9ddaf14985f6a3322c8f0bd182bdfb2dc3cabdff56f14940b1"),
        },
        {
           fromHex("1F877C"),
           fromHex("f320534dd6ab164dbf32194e8df50638be81b3442911e116cd004959"),
        },
        {
           fromHex("c1ecfdfc"),
           fromHex("a2ae4b71475c13cab784e7439b1b46a7c43f65ca7131ae0dbdc881bd"),
        },
        {
           fromHex("1f66ab4185ed9b6375"),
           fromHex("9567a563c89743c3ec317902331f1d6b44d507e1ad3831895cb84ada"),
        },
        {
           fromHex("a746273228122f381c3b46e4f1"),
           fromHex("146e2af3e7964e03b2e49b83afa070de29a92378e5f74445a29cfb37"),
        },
        {
           fromHex("d8dc8fdefbdce9d44e4cbafe78447bae3b5436102a"),
           fromHex("4c5a54aad044bc8819fc2d895fbeaee6aa5aaae3094fb2aba671a5da"),
        },
        {
           fromHex("aecbb02759f7433d6fcb06963c74061cd83b5b3ffa6f13c6"),
           fromHex("59db014cac582e5242c03910e8b2a2c2de3bf6e1051038a1d0e1b18c"),
        },
        {
           fromHex("512a6d292e67ecb2fe486bfe92660953a75484ff4c4f2eca2b0af0edcdd4339c6b2ee4e542"),
           fromHex("4a4ef2addecfff390f4294718ae199ffee59dd8aa8860afe6385a764"),
        },
        {
           fromHex("c8f2b693bd0d75ef99caebdc22adf4088a95a3542f637203e283bbc3268780e787d68d28cc3897452f6a22aa8573ccebf245972a"),
           fromHex("3c81e8da5c4c8c711500bc756aa1d0942275a622691a600033ffe36e"),
        },
        {
           fromHex("90078999fd3c35b8afbf4066cbde335891365f0fc75c1286cdd88fa51fab94f9b8def7c9ac582a5dbcd95817afb7d1b48f63704e19c2baa4df347f48d4a6d603013c23f1e9611d595ebac37c"),
           fromHex("937a74032c1d8a74140d2e8a528d1de16e98734b9d32367ebd95f759"),
        },
        {
           fromHex("68c8f8849b120e6e0c9969a5866af591a829b92f33cd9a4a3196957a148c49138e1e2f5c7619a6d5edebe995acd81ec8bb9c7b9cfca678d081ea9e25a75d39db04e18d475920ce828b94e72241f24db72546b352a0e4"),
           fromHex("a01aa45810d1055282dc385a7e540337444f8168ed598decc9218c81"),
        },
        {
           fromHex("03d9f92b2c565709a568724a0aff90f8f347f43b02338f94a03ed32e6f33666ff5802da4c81bdce0d0e86c04afd4edc2fc8b4141c2975b6f07639b1994c973d9a9afce3d9d365862003498513bfa166d2629e314d97441667b007414e739d7febf0fe3c32c17aa188a8683"),
           fromHex("cb94318727f7d2b504bd6fe08ff976e5c3ee7652e91692eba55c46ac"),
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
           fromHex(""),
           fromHex("39ccc4554a8b31853b9de7a1fe638a24cce6b35a55f2431009e18780335d2621"),
        },
        {
           fromHex("cc"),
           fromHex("a018268ed814e0ad0f2d0304e8fe3f4118fcefc07454d07123cc2c3e40e06a4f"),
        },
        {
           fromHex("41fb"),
           fromHex("f91902ddcc9688462e48f0bcdfca031637f0d8da577c1e2aa316b5c022450bf2"),
        },
        {
           fromHex("1F877C"),
           fromHex("ae5520f519d56cb15f15be222b46548bf967397f353d40b109732f066f6396dc"),
        },
        {
           fromHex("c1ecfdfc"),
           fromHex("2638b1711f1346d08bf02b5d1a575cd924140a608512af5b8e4475632599a896"),
        },
        {
           fromHex("1f66ab4185ed9b6375"),
           fromHex("9a3b62cc26e36c9a8629320242d18900a5ba08ddcc37d06a32a1cf7c6f6ad718"),
        },
        {
           fromHex("a746273228122f381c3b46e4f1"),
           fromHex("b054a5dde925709ddf26c1fa45bdc2a9b6b82c71f2a80c7594082a9031ff666d"),
        },
        {
           fromHex("d8dc8fdefbdce9d44e4cbafe78447bae3b5436102a"),
           fromHex("0f363ecc1b9f971e7af89169a686237e3aac4330300f387f3a589cadaa392ac4"),
        },
        {
           fromHex("b2dcfe9ff19e2b23ce7da2a4207d3e5ec7c6112a8a22aec9675a886378e14e5bfbad4e"),
           fromHex("94309484994a3cf04b882c8d53315c58fa2454d1cc753c8b703a073e6b5bf476"),
        },
        {
           fromHex("01e43fe350fcec450ec9b102053e6b5d56e09896e0ddd9074fe138e6038210270c834ce6eadc2bb86bf6"),
           fromHex("5d03c3c3a6ce9a4af70270e6737ba7194fb0be9333b6ff53ce470f15ae335117"),
        },
        {
           fromHex("5c5faf66f32e0f8311c32e8da8284a4ed60891a5a7e50fb2956b3cbaa79fc66ca376460e100415401fc2b8518c64502f187ea14bfc9503759705"),
           fromHex("b0d012a15ddc5796ea900c2c1b5aeb2307b6cfc80cff88a76bff2fadb81560f6"),
        },
        {
           fromHex("13bd2811f6ed2b6f04ff3895aceed7bef8dcd45eb121791bc194a0f806206bffc3b9281c2b308b1a729ce008119dd3066e9378acdcc50a98a82e20738800b6cddbe5fe9694ad6d"),
           fromHex("5cac4b0d209c0584f7b015e97cab3dc8e4806b892477e16f0c10150b72ea4ba5"),
        },
        {
           fromHex("d4654be288b9f3b711c2d02015978a8cc57471d5680a092aa534f7372c71ceaab725a383c4fcf4d8deaa57fca3ce056f312961eccf9b86f14981ba5bed6ab5b4498e1f6c82c6cae6fc14845b3c8a"),
           fromHex("1ee4600134eb024596bde2cbefa4fc7a28c4c5ed755c8ac56fe610f2abb189c0"),
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
           fromHex("dd5aaf4589dc227bd1eb7bc68771f5baeaa3586ef6c7680167a023ec8ce26980f06c4082c488b4ac9ef313f8cbe70808"),
        },
        {
           fromHex("cc"),
           fromHex("00d5a235be7bc36a9fd68227a593f106ee831f3f7558c96da5b71ae7d0db3084e43d6c57d9f202e8c69cc2c0d4333b20"),
        },
        {
           fromHex("41fb"),
           fromHex("bd9cf424d78ecef97bf6350b8a3108b2564d1c5acd225f1aafab38952e2d055c63cbb2d4e2e3e1e0eecdc509d0376f64"),
        },
        {
           fromHex("1F877C"),
           fromHex("772d0130af7122ec74ccc8d3525c9ded5eb947e7986d404289a188903dae603bcd602463c9e5b5b36dc35bc2efa63269"),
        },
        {
           fromHex("c1ecfdfc"),
           fromHex("4695da47bfb7ca4b4e3a75a9d11f32d4e1d2b157e4cc6c99d2f8958576e689c1cd290fe681f93815de0597c1955b8fb7"),
        },
        {
           fromHex("1f66ab4185ed9b6375"),
           fromHex("6b5b8ff4a1e0e17a5a56de5e22bbca3c2515097fdc9f37fe3be7ac795e4daba9109d1d385089598ed66338432d403e2b"),
        },
        {
           fromHex("a746273228122f381c3b46e4f1"),
           fromHex("fd050947149fcb0acaddd62d54c8b1f1ae7c92402fe5d3628e9c729b389ddd2f64d3773ea7fb3283a0b2779366bb1acd"),
        },
        {
           fromHex("d8dc8fdefbdce9d44e4cbafe78447bae3b5436102a"),
           fromHex("e443b8372b11bfb4ce30edcc67ab71683b4d5ca4f03f8b2dbdb01874ffdaba9bfba53ba02eb1d4a528e78403de969c60"),
        },
        {
           fromHex("a963c3e895ff5a0be4824400518d81412f875fa50521e26e85eac90c04"),
           fromHex("330666c8c85d5ac1e59ef7b72428c383530c0c2597af6e6a6005138990577e52856bbc7e153804234cbb7a2f96cb1a56"),
        },
        {
           fromHex("f5961dfd2b1ffffda4ffbf30560c165bfedab8ce0be525845deb8dc61004b7db38467205f5dcfb34a2acfe96c0"),
           fromHex("5ea522484208e44e03899f34b7ce1407d7248b4449a5d1017a315261c15f8328ff91eb71437e5959816948b8fefb8bcc"),
        },
        {
           fromHex("5c5faf66f32e0f8311c32e8da8284a4ed60891a5a7e50fb2956b3cbaa79fc66ca376460e100415401fc2b8518c64502f187ea14bfc9503759705"),
           fromHex("2f23ece869a3591573daf89f82ca1699489b7205f8d0fc13c8238eb16808bfb3393b42ab5269c23908d35493270582fb"),
        },
        {
           fromHex("90078999fd3c35b8afbf4066cbde335891365f0fc75c1286cdd88fa51fab94f9b8def7c9ac582a5dbcd95817afb7d1b48f63704e19c2baa4df347f48d4a6d603013c23f1e9611d595ebac37c"),
           fromHex("129f42fa6e56c17f89301b300b907f0e28bd1b50742feb4ef1027a571bb7011e216a90468eda7f5c0fc5352bfaac285d"),
        },
        {
           fromHex("6d8c6e449bc13634f115749c248c17cd148b72157a2c37bf8969ea83b4d6ba8c0ee2711c28ee11495f43049596520ce436004b026b6c1f7292b9c436b055cbb72d530d860d1276a1502a5140e3c3f54a93663e4d20edec32d284e25564f624955b52"),
           fromHex("4b60819a230ac7b5e9e79fde70508bf2301636a400a266a623ff3f5ab15273031a95b0d1c66711287c76445172f98224"),
        },
        {
           fromHex("d1e654b77cb155f5c77971a64df9e5d34c26a3cad6c7f6b300d39deb1910094691adaa095be4ba5d86690a976428635d5526f3e946f7dc3bd4dbc78999e653441187a81f9adcd5a3c5f254bc8256b0158f54673dcc1232f6e918ebfc6c51ce67eaeb042d9f57eec4bfe910e169af78b3de48d137df4f2840"),
           fromHex("93790c9ed2b9ceda2f0d084d36823aa0e65c0451266b212b6e1cbe1fd7170e7f48ad9b40378e8ac6fadb5836a94d9358"),
        },
        {
           fromHex("9bb4af1b4f09c071ce3cafa92e4eb73ce8a6f5d82a85733440368dee4eb1cbc7b55ac150773b6fe47dbe036c45582ed67e23f4c74585dab509df1b83610564545642b2b1ec463e18048fc23477c6b2aa035594ecd33791af6af4cbc2a1166aba8d628c57e707f0b0e8707caf91cd44bdb915e0296e0190d56d33d8dde10b5b60377838973c1d943c22ed335e"),
           fromHex("9f32b2c516a497dc2a12ce93545d8c86601eb7fe1231264f3d5b28fcc4c9e6d76a5ab5ed76bbcd28cdff9dfa18864b5b"),
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
           fromHex(""),
           fromHex("bc5b4c50925519c290cc634277ae3d6257212395cba733bbad37a4af0fa06af41fca7903d06564fea7a2d3730dbdb80c1f85562dfcc070334ea4d1d9e72cba7a"),
        },
        {
           fromHex("cc"),
           fromHex("26d8382ebdc39072293ddcdda6568b4add2449a05424a12dfbf11595228e9fbf7c542f25ec0f7348b19ad23ef5e97d45e5cff7bb9969be332923f33be53a6d09"),
        },
        {
           fromHex("41fb"),
           fromHex("258f3ceebd9c01271d75abe73e90085390f54cd318b4d5fa71e8813a541dd96e9de5a119d053a913296929e263267a3710b3675ab99c42a3f67d96fbe6ca8451"),
        },
        {
           fromHex("1F877C"),
           fromHex("72dda5ab6840dbd44cb2cc8220c2e0fb5c435878e00ebbdacf2a5ad2784860becb731c821d19e28133320aca0cc9e41aa9dbf1469f6388c4f74a900ea38a9f5c"),
        },
        {
           fromHex("c1ecfdfc"),
           fromHex("af443e00d6c8ba0a533f9fb284cc69ea9e17787f2b10fa0013bf86d60a4ec0f7e9785fb74dc97a779832fcebc931f362b5dd5bb4b4a980d7609a7e0bee0d6020"),
        },
        {
           fromHex("1f66ab4185ed9b6375"),
           fromHex("893241922416de44d3d59003765633d0e67c9d8ef9781f41cc5aa2660fb31fedeeb64324347aa6d071ebb14668d11837f130c46fb291289525cf50b251d08353"),
        },
        {
           fromHex("a746273228122f381c3b46e4f1"),
           fromHex("c62e943ac8257354d221b1350648b38f0f6f3dce21ebd6f67fe1b578015749e1e4ba26eee57ff80013514a31a6aca6da770884945d1eef0e2d1473e0d5ae3964"),
        },
        {
           fromHex("d8dc8fdefbdce9d44e4cbafe78447bae3b5436102a"),
           fromHex("50d4671d3737f716647ee911c947443ffb6ab86980bf480fed5eada0ac43db11ba812ea7c5135bed9ebd5e3ed64c2370ecfb4c01630c48a0157807e56b76c363"),
        },
        {
           fromHex("b2dcfe9ff19e2b23ce7da2a4207d3e5ec7c6112a8a22aec9675a886378e14e5bfbad4e"),
           fromHex("211121ce41bded281fc05f7426daed575198c307ae107318a282a173b25cf64131874216a71d5c4e5b66c9b78d8d266dac1aa7773633d4cf5c41c521af1a3191"),
        },
        {
           fromHex("1743a77251d69242750c4f1140532cd3c33f9b5ccdf7514e8584d4a5f9fbd730bcf84d0d4726364b9bf95ab251d9bb"),
           fromHex("b175a67928a446645732f22d10ee101eea9aadd83bd2bea38c9e25e1d1f4ff18865578e3115303eee7857b9d9decc59ab66f42f2aa70ea8192fe9abced5eeb68"),
        },
        {
           fromHex("f57c64006d9ea761892e145c99df1b24640883da79d9ed5262859dcda8c3c32e05b03d984f1ab4a230242ab6b78d368dc5aaa1e6d3498d53371e84b0c1d4ba"),
           fromHex("ab7a725bd93ab805d89d81eb6766e46e1a0045e654b82b389e6b481eaa7d26fe39a471ccf99b6e87eb8e2a9c0d7cadad4b2cb401ffe5bd85de8d0235e8b5bdfd"),
        },
        {
           fromHex("e728de62d75856500c4c77a428612cd804f30c3f10d36fb219c5ca0aa30726ab190e5f3f279e0733d77e7267c17be27d21650a9a4d1e32f649627638dbada9702c7ca303269ed14014b2f3cf8b894eac8554"),
           fromHex("ed3d326e1e618d140bc3ac49db60c96b4d04252de2d44de3b414d8f96c05a6e37c82b1dc515df1cf784aade0201259cab249924776c7c4e0612240f30ddefbde"),
        },
        {
           fromHex("cf3583cbdfd4cbc17063b1e7d90b02f0e6e2ee05f99d77e24e560392535e47e05077157f96813544a17046914f9efb64762a23cf7a49fe52a0a4c01c630cfe8727b81fb99a89ff7cc11dca5173057e0417b8fe7a9efba6d95c555f"),
           fromHex("2915d4d41fc7ad3ebbb2720e8d2789984f800e5ebae0c9376d0197b95b81e064120d9a040d2a7a6320b4cf06c6676e5923472b8fa5b9034a01aefa48f41db008"),
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
