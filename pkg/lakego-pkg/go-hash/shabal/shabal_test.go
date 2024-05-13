package shabal

import (
    "bytes"
    "testing"
    "encoding/hex"
)

func fromHex(s string) []byte {
    h, _ := hex.DecodeString(s)
    return h
}

func fromString(s string) []byte {
    return []byte(s)
}

type testData struct {
    msg []byte
    md []byte
}

func Test_Hash192_Check(t *testing.T) {
   tests := []testData{
        {
           fromString("abcdefghijklmnopqrstuvwxyz-0123456789-ABCDEFGHIJKLMNOPQRSTUVWXYZ-0123456789-abcdefghijklmnopqrstuvwxyz"),
           fromHex("690FAE79226D95760AE8FDB4F58C0537111756557D307B15"),
        },
    }

    h := New192()

    for i, test := range tests {
        h.Reset()
        h.Write(test.msg)
        sum := h.Sum(nil)

        if !bytes.Equal(sum, test.md) {
            t.Errorf("[%d] New192 fail, got %x, want %x", i, sum, test.md)
        }

        // =====

        sum2 := Sum192(test.msg)

        if !bytes.Equal(sum2[:], test.md) {
            t.Errorf("[%d] Sum192 fail, got %x, want %x", i, sum2, test.md)
        }
    }
}

func Test_Hash224_Check(t *testing.T) {
   tests := []testData{
        {
           fromHex(""),
           fromHex("562b4fdbe1706247552927f814b66a3d74b465a090af23e277bf8029"),
        },
        {
           fromHex("cc"),
           fromHex("63d1743b183146ac2a75416c9a0d88c66f85a422a43e3171ef9cc923"),
        },
        {
           fromHex("41fb"),
           fromHex("de6707feb8413d0621e40cc8f2843d369647055b35580533db660b8b"),
        },
        {
           fromHex("1F877C"),
           fromHex("95d94b88f06c521e55000bd3019e1a45668e11ac9cd4511eea490f5d"),
        },
        {
           fromHex("c1ecfdfc"),
           fromHex("223fefcc0539d29cbcfb3d5f63b94d26d0035869b228f38955919686"),
        },
        {
           fromHex("1f66ab4185ed9b6375"),
           fromHex("3366d7de5fe29956cf9c6ecdeae4777fb8b4d1f0692a32838b7e10b7"),
        },
        {
           fromHex("a746273228122f381c3b46e4f1"),
           fromHex("0530841925d57a23bbfc87cad5e140c0594bd150dade13fd2d4c5ddf"),
        },
        {
           fromHex("d8dc8fdefbdce9d44e4cbafe78447bae3b5436102a"),
           fromHex("f47f5a632bbc6c30e80ebfa12f559af6a07868b740d36016ee2deca2"),
        },
        {
           fromHex("aecbb02759f7433d6fcb06963c74061cd83b5b3ffa6f13c6"),
           fromHex("95769e2be095f0e691b2990009d147f6de26cac959a874558b2a3530"),
        },
        {
           fromHex("512a6d292e67ecb2fe486bfe92660953a75484ff4c4f2eca2b0af0edcdd4339c6b2ee4e542"),
           fromHex("ce785556a1d047b53ac83add1eebe4c57e8c7e2660aeffe4d5896094"),
        },
        {
           fromHex("eebcc18057252cbf3f9c070f1a73213356d5d4bc19ac2a411ec8cdeee7a571e2e20eaf61fd0c33a0ffeb297ddb77a97f0a415347db66bcaf"),
           fromHex("4a1421f85a93a5dd50980684ac2968b0d34f8462c31b236b12af59d0"),
        },
        {
           fromHex("68c8f8849b120e6e0c9969a5866af591a829b92f33cd9a4a3196957a148c49138e1e2f5c7619a6d5edebe995acd81ec8bb9c7b9cfca678d081ea9e25a75d39db04e18d475920ce828b94e72241f24db72546b352a0e4"),
           fromHex("03527642f2e22180ad4d030ab4b883cf70a5d5574163bdfb96d49089"),
        },
        {
           fromHex("64ec021c9585e01ffe6d31bb50d44c79b6993d72678163db474947a053674619d158016adb243f5c8d50aa92f50ab36e579ff2dabb780a2b529370daa299207cfbcdd3a9a25006d19c4f1fe33e4b1eaec315d8c6ee1e730623fd1941875b924eb57d6d0c2edc4e78d6"),
           fromHex("caebe8fae98e63d9c35b41dafdf28b4c854e46b10b2e5c8651bbd814"),
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
           fromHex("aec750d11feee9f16271922fbaf5a9be142f62019ef8d720f858940070889014"),
        },
        {
           fromHex("cc"),
           fromHex("f52e6a62fa8a0e0fcdea5e12800c3b4301a0bf8b0f897bbe7685cdc659fdd3f8"),
        },
        {
           fromHex("41fb"),
           fromHex("b956d01abe2105dad2c6b29896e14afbebd6f0ac750b64e9dca508a8b94a86e4"),
        },
        {
           fromHex("1F877C"),
           fromHex("744aa44a262e0551984e1f476030826e9f70fe7d1f84fd279b60806f965a0d8b"),
        },
        {
           fromHex("c1ecfdfc"),
           fromHex("ad1cc03ae512d733bb361eff61793d49d63a184c754ebf7f92a9d2b98edb3b2f"),
        },
        {
           fromHex("1f66ab4185ed9b6375"),
           fromHex("32dc2f0a73f89937afc283855140972e27923a1bdf34bd140e5bf55d54e28cdb"),
        },
        {
           fromHex("a746273228122f381c3b46e4f1"),
           fromHex("7c05480ce796a73a73ae36739cf9c81d36cf3944af5b8eb5a6889da42d29a0ec"),
        },
        {
           fromHex("d8dc8fdefbdce9d44e4cbafe78447bae3b5436102a"),
           fromHex("ba02d41e96d595d792ac0a2b4e22631c6ea99c0f524b95fb1c864bc0e4b7c76d"),
        },
        {
           fromHex("aecbb02759f7433d6fcb06963c74061cd83b5b3ffa6f13c6"),
           fromHex("7a08ab23bcc138d4113dff285f38ccb40e84315ed3158fa77341ffdb41c883ab"),
        },
        {
           fromHex("512a6d292e67ecb2fe486bfe92660953a75484ff4c4f2eca2b0af0edcdd4339c6b2ee4e542"),
           fromHex("100d112ae3d45aa6279e99482a3708357598b95e58f92683bb5857875fd1d06c"),
        },
        {
           fromHex("de286ba4206e8b005714f80fb1cdfaebde91d29f84603e4a3ebc04686f99a46c9e880b96c574825582e8812a26e5a857ffc6579f63742f"),
           fromHex("61f15be03c1c67f3766708df0b268a5c8e25e96d017c4806979d55031472b64d"),
        },
        {
           fromHex("e926ae8b0af6e53176dbffcc2a6b88c6bd765f939d3d178a9bde9ef3aa131c61e31c1e42cdfaf4b4dcde579a37e150efbef5555b4c1cb40439d835a724e2fae7"),
           fromHex("1303d2ba5fbaf789c0ed488b07b6a542371780231204ab72398a106a7355e3af"),
        },
        {
           fromHex("0d58ac665fa84342e60cefee31b1a4eacdb092f122dfc68309077aed1f3e528f578859ee9e4cefb4a728e946324927b675cd4f4ac84f64db3dacfe850c1dd18744c74ceccd9fe4dc214085108f404eab6d8f452b5442a47d"),
           fromHex("a06dd2f676855d1e196a1926178d9c21c838cbeec8a256010f01f98ea4dedc9a"),
        },
        {
           fromHex("ae159f3fa33619002ae6bcce8cbbdd7d28e5ed9d61534595c4c9f43c402a9bb31f3b301cbfd4a43ce4c24cd5c9849cc6259eca90e2a79e01ffbac07ba0e147fa42676a1d668570e0396387b5bcd599e8e66aaed1b8a191c5a47547f61373021fa6deadcb55363d233c24440f2c73dbb519f7c9fa5a8962efd5f6252c0407f190dfefad707f3c7007d69ff36b8489a5b6b7c557e79dd4f50c06511f599f56c896b35c917b63ba35c6ff8092baf7d1658e77fc95d8a6a43eeb4c01f33f03877f92774be89c1114dd531c011e53a34dc248a2f0e6"),
           fromHex("deb14de3505e935dd17307876228f29dcc74e3c1f86c51907645c44acc2d0c46"),
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
           fromHex("ff093d67d22b06a674b5f384719150d617e0ff9c8923569a2ab60cda886df63c91a25f33cd71cc22c9eebc5cd6aee52a"),
        },
        {
           fromHex("cc"),
           fromHex("da6e116f4fc2740abb1308089251582e516c1b0da5e56492126e3aa8fe4be1a9ce5d58514cf32a5c1bd9211b535acfb5"),
        },
        {
           fromHex("41fb"),
           fromHex("f3b641253750a156b84750a9ff6beaf19b96426f0189df0a749f792a1a78543cbd419b324bb24d999ebbd188f9cfb62f"),
        },
        {
           fromHex("1F877C"),
           fromHex("796411d75fb36c8025a2f69c1ca0c10f0d88902291c4cec14375ce73194defc91e98a54c09b1e86f10a9641fac57b916"),
        },
        {
           fromHex("c1ecfdfc"),
           fromHex("1f4c7ddce5089de154ceba5def970903195ca1c45cbda93a0860e387e65915f9946bfa625065d5c64ecdd3d2d6282042"),
        },
        {
           fromHex("1f66ab4185ed9b6375"),
           fromHex("084ef351bfbae50d247183dcd88f240a5bfddd511b2fa285b736d78f9e71be2de245654145d239142622d125d2a56b82"),
        },
        {
           fromHex("a746273228122f381c3b46e4f1"),
           fromHex("3587f792d92ed9152a174c17294e0ef38d95debdb2f43a811bea85a7c0de849bdc2333f48055be6fa0abd198877d3cf7"),
        },
        {
           fromHex("d8dc8fdefbdce9d44e4cbafe78447bae3b5436102a"),
           fromHex("bf4badcdb081b6401c28ba778567111bd644f958c295536e2b2306c12c65193ee4d4b85ac27a9d9f1ff49f19ffaa14a7"),
        },
        {
           fromHex("aecbb02759f7433d6fcb06963c74061cd83b5b3ffa6f13c6"),
           fromHex("3b8075927601790f106cbc9a16c8e8283cd95599098a4cf57e9a3571381372d676b144bcf73f327d5d49692db689fe63"),
        },
        {
           fromHex("512a6d292e67ecb2fe486bfe92660953a75484ff4c4f2eca2b0af0edcdd4339c6b2ee4e542"),
           fromHex("a4ed21db40b4f50b1773e75a1c65aeb94c9ea21b4600f80a3008b863a2fde1c480a3a4f549270618c69dc96b3328a2b1"),
        },
        {
           fromHex("c8f2b693bd0d75ef99caebdc22adf4088a95a3542f637203e283bbc3268780e787d68d28cc3897452f6a22aa8573ccebf245972a"),
           fromHex("764ffc1fbdcb97d960520168a1cd5ef25cb2daae24f290fbbf339806cecf0107c2968b6236edb5649fe240058aa034e0"),
        },
        {
           fromHex("16e8b3d8f988e9bb04de9c96f2627811c973ce4a5296b4772ca3eefeb80a652bdf21f50df79f32db23f9f73d393b2d57d9a0297f7a2f2e79cfda39fa393df1ac00"),
           fromHex("33d1a460b27ed08d9fe19a35bb60df4b7a239ce26a66e7f0ddb6b358fde925b25bb5adf0307fc4324b4286221b1bf965"),
        },
        {
           fromHex("68c8f8849b120e6e0c9969a5866af591a829b92f33cd9a4a3196957a148c49138e1e2f5c7619a6d5edebe995acd81ec8bb9c7b9cfca678d081ea9e25a75d39db04e18d475920ce828b94e72241f24db72546b352a0e4"),
           fromHex("ede2e9cac7b002e32e1f4769c2df07c7fe310f1b41f00e58c40964150effd010c177dcb771ffbf2554f7017f974bbe39"),
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
           fromHex("fc2d5dff5d70b7f6b1f8c2fcc8c1f9fe9934e54257eded0cf2b539a2ef0a19ccffa84f8d9fa135e4bd3c09f590f3a927ebd603ac29eb729e6f2a9af031ad8dc6"),
        },
        {
           fromHex("cc"),
           fromHex("da2621ac83fa9ed23e2fd977cdba8906492e7c9405940974a4017c61a9615bb32a3ec0ff89937b58395168b012175973dea0def7b4412c4c1ed80e5b2d9a6ad0"),
        },
        {
           fromHex("41fb"),
           fromHex("4632729e95eef7a43e701f85c9754506d00ac7ea239a7772b920580a93c95daafcd9acc5e29bef2d6fa954355f80095e3521bd1665e5d1fcb079706676319267"),
        },
        {
           fromHex("1F877C"),
           fromHex("6e1d4a235cfdad76f8a51396624a28e0b403cc172b94fa3ac198848f66b4033107b5c15f67da912358b4f3fedc85496b4ca5feafbe1e6fdaa921cd6f63f76772"),
        },
        {
           fromHex("c1ecfdfc"),
           fromHex("9c97939f8ae8f7a2eef79871cd5dead034b2473ea42a1a07851b343f694b2ecf64da457e75526241f5cc419686f85c9f537c88686057fc3d5dc3546306a30750"),
        },
        {
           fromHex("1f66ab4185ed9b6375"),
           fromHex("2daf819e7c98a9f1f53d5448c230a0a4a9345ee019a0881a7849196b8a395b2f0d83ce598e4c640f4e5c9c939a3626660993f58f9541bd4cadc339037e8bd9b0"),
        },
        {
           fromHex("a746273228122f381c3b46e4f1"),
           fromHex("bff2a10129af8c8f9921b9acd8e27f7ed910d6575183d9542070eea87214dd8481ad3c5844e9d183cee3c8bcc5e90c130d9fa8b2be60e838cf74d9a6bf9c0ecf"),
        },
        {
           fromHex("d8dc8fdefbdce9d44e4cbafe78447bae3b5436102a"),
           fromHex("f6c7de9252c46c23dccc4833b611128bef9b66d1fe1b1eedca1ac38646a24da0c9a333d924dbbc6b4c4bca6c461ff2d2e12954092dd2a63f5e2cab2775ee7bbd"),
        },
        {
           fromHex("337023370a48b62ee43546f17c4ef2bf8d7ecd1d49f90bab604b839c2e6e5bd21540d29ba27ab8e309a4b7"),
           fromHex("e8489ee7df2771bda94c90c36f46a4117976e98a8af6adb1c1ea8d84cbd632b6ab23c17e80ac9dd26744f7a7e79ab3454fd7ccac9603c27d58f35c58a86e5da7"),
        },
        {
           fromHex("be9684be70340860373c9c482ba517e899fc81baaa12e5c6d7727975d1d41ba8bef788cdb5cf4606c9c1c7f61aed59f97d"),
           fromHex("a589e7e6a9e2f127e93f527446c43c67bc525f5cfe9f70640ee85d145d4e764d009a5fb5e53838a653c4dae89ca225da69605a60d01a5548ce6139a72adb38f0"),
        },
        {
           fromHex("5c5faf66f32e0f8311c32e8da8284a4ed60891a5a7e50fb2956b3cbaa79fc66ca376460e100415401fc2b8518c64502f187ea14bfc9503759705"),
           fromHex("97489d6513a5176f8115aa4d2c46ab19e21ed461841afa51f24013edbfa9d564f463c9a1cee6d16cf7b96a0b5ce094344deb4e1e8c27bea7364c225853b56f07"),
        },
        {
           fromHex("d4654be288b9f3b711c2d02015978a8cc57471d5680a092aa534f7372c71ceaab725a383c4fcf4d8deaa57fca3ce056f312961eccf9b86f14981ba5bed6ab5b4498e1f6c82c6cae6fc14845b3c8a"),
           fromHex("9179478c79dbdb3984f3a0eed60241daffd925b0044b6425ece029b8aab4f5a5c0108d65430291e3373930bc766e50e30033068e6b8c4e3b87f13ccb2dd4837e"),
        },
        {
           fromHex("f31e8b4f9e0621d531d22a380be5d9abd56faec53cbd39b1fab230ea67184440e5b1d15457bd25f56204fa917fa48e669016cb48c1ffc1e1e45274b3b47379e00a43843cf8601a5551411ec12503e5aac43d8676a1b2297ec7a0800dbfee04292e937f21c005f17411473041"),
           fromHex("cd15b8fbdd1176bdaee28223f0626305248a39df9088335d5c94f1953e287e0cb425a7bc41d420f50a0981546914b280b1148450cbed9cff29ff60ff63f6d99c"),
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

func Test_HashNew_Check(t *testing.T) {
    tests := []testData{
        {
           fromHex(""),
           fromHex("fc2d5dff5d70b7f6b1f8c2fcc8c1f9fe9934e54257eded0cf2b539a2ef0a19ccffa84f8d9fa135e4bd3c09f590f3a927ebd603ac29eb729e6f2a9af031ad8dc6"),
        },
        {
           fromHex("cc"),
           fromHex("da2621ac83fa9ed23e2fd977cdba8906492e7c9405940974a4017c61a9615bb32a3ec0ff89937b58395168b012175973dea0def7b4412c4c1ed80e5b2d9a6ad0"),
        },
        {
           fromHex("41fb"),
           fromHex("4632729e95eef7a43e701f85c9754506d00ac7ea239a7772b920580a93c95daafcd9acc5e29bef2d6fa954355f80095e3521bd1665e5d1fcb079706676319267"),
        },
        {
           fromHex("1F877C"),
           fromHex("6e1d4a235cfdad76f8a51396624a28e0b403cc172b94fa3ac198848f66b4033107b5c15f67da912358b4f3fedc85496b4ca5feafbe1e6fdaa921cd6f63f76772"),
        },
        {
           fromHex("c1ecfdfc"),
           fromHex("9c97939f8ae8f7a2eef79871cd5dead034b2473ea42a1a07851b343f694b2ecf64da457e75526241f5cc419686f85c9f537c88686057fc3d5dc3546306a30750"),
        },
        {
           fromHex("1f66ab4185ed9b6375"),
           fromHex("2daf819e7c98a9f1f53d5448c230a0a4a9345ee019a0881a7849196b8a395b2f0d83ce598e4c640f4e5c9c939a3626660993f58f9541bd4cadc339037e8bd9b0"),
        },
        {
           fromHex("a746273228122f381c3b46e4f1"),
           fromHex("bff2a10129af8c8f9921b9acd8e27f7ed910d6575183d9542070eea87214dd8481ad3c5844e9d183cee3c8bcc5e90c130d9fa8b2be60e838cf74d9a6bf9c0ecf"),
        },
        {
           fromHex("d8dc8fdefbdce9d44e4cbafe78447bae3b5436102a"),
           fromHex("f6c7de9252c46c23dccc4833b611128bef9b66d1fe1b1eedca1ac38646a24da0c9a333d924dbbc6b4c4bca6c461ff2d2e12954092dd2a63f5e2cab2775ee7bbd"),
        },
        {
           fromHex("337023370a48b62ee43546f17c4ef2bf8d7ecd1d49f90bab604b839c2e6e5bd21540d29ba27ab8e309a4b7"),
           fromHex("e8489ee7df2771bda94c90c36f46a4117976e98a8af6adb1c1ea8d84cbd632b6ab23c17e80ac9dd26744f7a7e79ab3454fd7ccac9603c27d58f35c58a86e5da7"),
        },
        {
           fromHex("be9684be70340860373c9c482ba517e899fc81baaa12e5c6d7727975d1d41ba8bef788cdb5cf4606c9c1c7f61aed59f97d"),
           fromHex("a589e7e6a9e2f127e93f527446c43c67bc525f5cfe9f70640ee85d145d4e764d009a5fb5e53838a653c4dae89ca225da69605a60d01a5548ce6139a72adb38f0"),
        },
        {
           fromHex("5c5faf66f32e0f8311c32e8da8284a4ed60891a5a7e50fb2956b3cbaa79fc66ca376460e100415401fc2b8518c64502f187ea14bfc9503759705"),
           fromHex("97489d6513a5176f8115aa4d2c46ab19e21ed461841afa51f24013edbfa9d564f463c9a1cee6d16cf7b96a0b5ce094344deb4e1e8c27bea7364c225853b56f07"),
        },
        {
           fromHex("d4654be288b9f3b711c2d02015978a8cc57471d5680a092aa534f7372c71ceaab725a383c4fcf4d8deaa57fca3ce056f312961eccf9b86f14981ba5bed6ab5b4498e1f6c82c6cae6fc14845b3c8a"),
           fromHex("9179478c79dbdb3984f3a0eed60241daffd925b0044b6425ece029b8aab4f5a5c0108d65430291e3373930bc766e50e30033068e6b8c4e3b87f13ccb2dd4837e"),
        },
        {
           fromHex("f31e8b4f9e0621d531d22a380be5d9abd56faec53cbd39b1fab230ea67184440e5b1d15457bd25f56204fa917fa48e669016cb48c1ffc1e1e45274b3b47379e00a43843cf8601a5551411ec12503e5aac43d8676a1b2297ec7a0800dbfee04292e937f21c005f17411473041"),
           fromHex("cd15b8fbdd1176bdaee28223f0626305248a39df9088335d5c94f1953e287e0cb425a7bc41d420f50a0981546914b280b1148450cbed9cff29ff60ff63f6d99c"),
        },
    }

    h, err := New(512)
    if err != nil {
        t.Fatal(err)
    }

    for i, test := range tests {
        h.Reset()
        h.Write(test.msg)
        sum := h.Sum(nil)

        if !bytes.Equal(sum, test.md) {
            t.Errorf("[%d] New fail, got %x, want %x", i, sum, test.md)
        }
    }

}
