package kcdsa

import (
    "testing"
    "math/big"
    "crypto/rand"
    "crypto/sha256"

    "github.com/deatil/go-cryptobin/hash/has160"
)

func Test_Verify_TestVectors(t *testing.T) {
    verifyTestCases(t, testCaseTTAK)
}

func Test_Sign_Verify_TestVectors(t *testing.T) {
    R, S := new(big.Int), new(big.Int)
    tmp := new(big.Int)
    var tmpBuf []byte

    for idx, tc := range testCaseTTAK {
        K := tc.KKEY

        priv := PrivateKey{
            PublicKey: PublicKey{
                Parameters: Parameters{
                    P: tc.P,
                    Q: tc.Q,
                    G: tc.G,
                },
                Y: tc.Y,
            },
            X: tc.X,
        }

        var ok bool
        tmpBuf, ok = sign(
            R, S,
            &priv,
            tc.Hash,
            K, tc.M,
            tmp,
            tmpBuf,
        )
        if !ok {
            t.Errorf("%d: error signing", idx)
            return
        }

        if R.Cmp(tc.R) != 0 || S.Cmp(tc.S) != 0 {
            t.Errorf("%d: sign failed", idx)
            return
        }

        ok = Verify(&priv.PublicKey, tc.Hash, tc.M, tc.R, tc.S)
        if ok == tc.Fail {
            t.Errorf("%d: Verify failed, got:%v want:%v", idx, ok, !tc.Fail)
            return
        }
    }
}

func Test_TTAK_GenerateJ(t *testing.T) {
    if testing.Short() {
        t.Skip("skipping ttak parameter generation test in short mode")
        return
    }

    var buf []byte
    var ok bool

    J := new(big.Int)
    for _, tc := range testCaseTTAK {
        d, _ := GetSizes(tc.Sizes)
        buf, ok = GenerateJ(J, buf, tc.Seedb, d.NewHash(), d)
        if !ok {
            t.Fail()
            return
        }

        if J.Cmp(tc.J) != 0 {
            t.Errorf("GenerateTTAKJ failed")
            return
        }
    }
}

func Test_TTAK_GeneratePQ(t *testing.T) {
    if testing.Short() {
        t.Skip("skipping ttak parameter generation test in short mode")
        return
    }

    var buf []byte
    var count int

    P := new(big.Int)
    Q := new(big.Int)

    for _, tc := range testCaseTTAK {
        d, ok := GetSizes(tc.Sizes)
        if !ok {
            t.Errorf("domain not found")
            return
        }

        buf, count, ok = GeneratePQ(P, Q, buf, tc.J, tc.Seedb, d.NewHash(), d)
        if !ok {
            t.Fail()
            return
        }
        if P.Cmp(tc.P) != 0 || Q.Cmp(tc.Q) != 0 || count != tc.Count {
            t.Fail()
            return
        }
    }
}

func Test_GenerateHG(t *testing.T) {
    if testing.Short() {
        t.Skip("skipping ttak parameter generation test in short mode")
        return
    }

    var buf []byte
    var err error

    H := new(big.Int)
    G := new(big.Int)

    for _, tc := range testCaseTTAK {
        buf, err = GenerateHG(H, G, buf, rand.Reader, tc.P, tc.J)
        if err != nil {
            t.Error(err)
            return
        }
    }
}

func Test_GenerateG(t *testing.T) {
    if testing.Short() {
        t.Skip("skipping Test_GenerateG in short mode")
        return
    }

    G := new(big.Int)
    for _, tc := range testCaseTTAK {
        ok := GenerateG(G, tc.P, tc.J, new(big.Int).SetBytes(tc.H))
        if !ok {
            t.Fail()
            return
        }
        if G.Cmp(tc.G) != 0 {
            t.Fail()
            return
        }
    }
}

func Test_RegenerateParameters(t *testing.T) {
    if testing.Short() {
        t.Skip("skipping Test_RegenerateParameters in short mode")
        return
    }

    for _, tc := range testCaseTTAK {
        params := Parameters{
            GenParameters: GenerationParameters{
                J:     tc.J,
                Seed:  tc.Seedb,
                Count: tc.Count,
            },
        }
        err := RegenerateParameters(&params, rnd, tc.Sizes)
        if err != nil {
            t.Error(err)
            return
        }

        if params.P.Cmp(tc.P) != 0 || params.Q.Cmp(tc.Q) != 0 {
            t.Fail()
            return
        }
    }
}

func Test_GenerateKey(t *testing.T) {
    if testing.Short() {
        t.Skip("skipping Test_GenerateKey in short mode")
        return
    }

    for _, tc := range testCaseTTAK {
        priv := PrivateKey{
            PublicKey: PublicKey{
                Parameters: Parameters{
                    P: tc.P,
                    Q: tc.Q,
                    G: tc.G,
                },
            },
        }
        _, _, err := GenerateKeyWithSeed(&priv, rnd, tc.XKEY, UserProvidedRandomInput, tc.Sizes)
        if err != nil {
            t.Error(err)
            return
        }

        if priv.X.Cmp(tc.X) != 0 || priv.Y.Cmp(tc.Y) != 0 {
            t.Fail()
            return
        }
    }
}

var (
    UserProvidedRandomInput = fromHex(`
        73 61 6c 64 6a 66 61 77 70 33 39 39 75 33 37 34 72 30 39 38 75 39 38 5e
        25 5e 25 68 6b 72 67 6e 3b 6c 77 6b 72 70 34 37 74 39 33 63 25 24 38 39
        34 33 39 38 35 39 6b 6a 64 6d 6e 76 63 6d 20 63 76 6b 20 6f 34 75 30 39
        72 20 34 6a 20 6f 6a 32 6f 75 74 32 30 39 78 66 71 77 3b 6c 2a 26 21 5e
        23 40 55 23 2a 23 24 29 28 23 20 7a 20 78 6f 39 35 37 74 63 2d 39 35 20
        35 20 76 35 6f 69 75 76 39 38 37 36 20 36 20 76 6a 20 6f 35 69 75 76 2d
        30 35 33 2c 6d 63 76 6c 72 6b 66 77 6f 72 65 74`)

    M = fromHex(`
        54 68 69 73 20 69 73 20 61 20 74 65 73 74 20 6d 65 73 73 61 67 65 20 66
        6f 72 20 4b 43 44 53 41 20 75 73 61 67 65 21`)

    // samples in TTAK.KO-12.0001/R4
    testCaseTTAK = []testCase{
        // p.30
        {
            Sizes: A2048B224SHA224,
            Hash:  sha256.New224,
            M:     M,

            Seedb: fromHex(`c0 52 a2 76 41 00 f0 f4 ec 90 6b 9c 5c 6b 10 6e 34 70 df c1 36 9f
                                12 c0 62 f8 0e e9`),
            J: toBigint(`870145cb 93f25fb2 9509261c 4510929e b5451582 b0fede90 54a45927 2b87bd40
                            0c7005d1 a7eae156 8d3e2600 f7d0e0ad 74e5a2fe 88ae771d e1dd2652 be027d59
                            66c95190 1774e690 45c15353 b5fb92e0 5cdff939 e9d54647 ae18a2db 9df24ff3
                            ba5413b3 307088bd 5e04fe25 d7a29595 703317b9 d821fea2 e5d70753 23660cf7
                            0898322f c0b4fdf7 b7f1fab0 b8f3e9be 012e3164 ca8218d6 fd17a3a2 d0660776
                            eadab6f3 1b76797a a9a8bc54 3b1de074 40a60b43 a7afa1b9 9b3f52e3 4315047e
                            a15222d0 ed54b5ca c864f1bd b0453eaa 90765e78 677b5d1d 8407eefd 2befadb1
                            36516e13`),
            Count: 80383,
            P: toBigint(`8da8c1b5 c95d11be 46661df5 8c9f803e b729b800 dd92751b 3a4f10c6 a5448e9f
                            3bc0e916 f042e399 b34af9be e582ccfc 3ff5000c ff235694 94351cfe a5529ea3
                            47dcf43f 302f5894 380709ea 2e1c416b 51a5cdfc 7593b18b 7e3788d5 1b9cc9ae
                            828b4f8f b06e0e90 57f7fa0f 93bb0397 031fe7d5 0a6828da 0c1160a0 e66d4e5d
                            2a18ad17 a811e70b 14f4f431 1a028260 3233444f 98763c5a 1e829c76 4cf36adb
                            56980bd4 c54bbe29 7e790228 4292d75c a3600ff4 59310b09 291cbefb c721528a
                            13403b8b 93b711c3 03a2182b 6e6397e0 83380bf2 886af3b9 afcc9f50 55d8b713
                            6c0ebd08 c5cf0b38 888cd115 72787f6d f384c97c 91b58c31 dee5655e cbf3fa53`),
            Q: toBigint(`864f1884 1ec103cd fd1be7fe e54650f2 2a3bb997 537f32cc 79a51f53`),

            H: fromHex(`8cd78a90 87aca828 9c0f5422 1e008eaa f46c56c0 581ea864 4a5e31a0 ca2c4805
                            f088edf8 31982079 00b51688 5d600a68 48998c38 12609c96 be143a82 f89cd4fc
                            c0b23380 fb5620bb 847b9b84 9be0a6db 40d3e2d0 7354ace8 5263048e 462ceac2
                            c8fc9984 d85a401d 764675a0 f9c038b1 582d8950 4568dc7d c031eeba c9888ea8
                            f06dbc24 ba7e782e 12246fc6 f858eca7 6c1af700 376a90e7 6c1fb75c 2f30525f
                            80cf3ae4 5ffcb0a8 ceb7b4fa 6e10c0da 9c8c85d0 586dd871 3800b9a0 b5c6285d
                            c01ad8a8 59fc0842 806cc64e 046a12e8 ecd4ec10 629340c6 66e0db04 f8bb047b
                            2024bb80 73320013 545cf834 c314fe16 c05a92f8 8c2eb468 4ae06466 967500f2`),
            G: toBigint(`0e9be1f8 7a414d16 7a9a5a96 8b079e4a d385a357 3edb21aa 67a6f61c 0d00c14a
                            7a225044 b6e9eb03 68c1eb57 b24b45cd 854fd93c 1b2dfb0a 3ea302d2 367e4ec7
                            2f6e7ee8 ea7f8002 f7704e99 0b954f25 bada8da6 2baeb6f0 6953c0c8 5104ad03
                            f36618f7 6c62f4ec f3480183 69850a56 17c999db e68ba17d 5bc72556 74ef4839
                            22c6a3f9 9d3c3c6f 358896c4 e63c605e e7db16fc bd9be354 e281f7fe 7813d054
                            27ed1912 b5c7653a 167b9434 9147eeaf 85cc9ce2 e81661f3 21512d5d 2c0580b0
                            3d1704ee f2317f45 185c8258 387e7ec9 79c04707 ef546241 2784afe4 1a7b45c8
                            3b9cbe48 f9127cb4 400be9e9 6ac5de17 f2c9dea3 5e3734e7 9b64673f 85681c4e`),

            XKEY: fromHex(`f910456a 20d9ba54 d61495ea 046d5de1 4b90ffdf eff64b4c a89150be`),
            X:    toBigint(`2f1991c1 af401872 8a5a431b 9b5459df b16f6d25 6797fe57 0ec6bc65`),
            Y: toBigint(`04ede5c6 7ea29297 a8cacb6b de6f4666 aea27d10 3dd1e9e9 582f76a2 f22b8b1b
                            32230bc5 8f06b768 f8102b49 fa1cae5e 18921494 7f6239b6 c6ce7c9b c2d230e8
                            9a40bee2 c33a8861 fd4f7d35 b788fe95 b2d5885d 8c8faea8 1c90be4c ee2784e3
                            3577a71d 3b7f085d 71e9a1d4 7815c73f a087acaa b9fcb565 5ac9570e 6852be7c
                            9c0aecea 8bd9aa75 a44fc314 7f733e90 6adb0fd7 6d613561 b1db364b bdc9afd3
                            ce8f5f17 e3e71203 4a999350 8059fa52 441fa90d dfe9a0f2 a0b9192f e2220c08
                            1bd0c0f0 e07cb5f1 ee4ff405 23591f17 8a4fc7cb 5065f6a3 8216e9a0 99c205b2
                            9b8746d8 65e1af6d 903e5a13 8004910b 70eb5b84 eed9760e a60578bf 08852898`),
            Z: toBigint(`1b d0 c0 f0 e0 7c b5 f1 ee 4f f4 05 23 59 1f 17 8a 4f c7 cb 50 65 f6 a3
                            82 16 e9 a0 99 c2 05 b2 9b 87 46 d8 65 e1 af 6d 90 3e 5a 13 80 04 91 0b
                            70 eb 5b 84 ee d9 76 0e a6 05 78 bf 08 85 28 98`),

            KKEY: toBigint(`49561994 fd2bad5e 410ca1c1 5c3fd3f1 2e70263f 2820ad5c 566ded80`),
            R: toBigint(`ed b7 6a 2d 39 f3 d7 fa 16 d0 82 59 41 18 b0 cf 8b a5 76 92 cf 3b aa ec
                            6f 6d d9 51`),
            S: toBigint(`5260a2df 2e923de8 77b130ac 8b5e8b17 63973b88 d5d4627a dfbacf52`),
        },
        // p.36
        {
            Sizes: A2048B224SHA256,
            Hash:  sha256.New,
            M:     M,

            Seedb: fromHex(`e1 75 ca d0 ea cb 74 dd b4 5f 15 f1 f2 57 22 bf 15 56 ef 86 0a 0f e0
                                31 71 18 44 9b`),
            J: toBigint(`853cd825 d245b074 cbc4f83d f6a9f182 4591223b ef5aafe9 5b0c14fc 6e63fc86
                            2f6233ac e777dc96 530b6830 0050adb0 7caf66b6 cf68bdc7 2c0053ac 2a9a02b9
                            b06e5c77 7c8cb831 ba645aa1 b5f5df54 38681e1f 36577f86 0212e30f dab29b2f
                            a3a190ff 608b9a00 962043d1 868a7087 bddd2fb6 2fdd12ef c6b20789 420e9487
                            d1398f07 a813e4a6 7d79be8e a28cd3ed 7ffef03e 5f17a36e ce0cc76e 848ca342
                            b6a7d064 1515c050 18a0e634 eec1e67c 55b51b3c e1e15305 47dbdf0f 85bd3da0
                            5d7a797f 3242dcd0 358f8e7a 85b431e7 89f8a6b1 19e915a4 47fc2c6d 431cf567
                            ccf49ced `),
            Count: 38197,
            P: toBigint(`c3159a30 cdbcc00c e2a99043 9634f7d3 fb16feb1 2c579932 2c14f8b8 a0d9b98e
                            35f724bf e14c4afc 475d78f9 3a83f8fb 4636a5de f357bd6f b0c6245c ac4ef29c
                            8f7da5e9 b39f3158 f4fd27c8 4088bcbb 6286d964 29c90e82 b7f31bf3 e76e93c6
                            8a3163cf b82370e2 75159d66 08f82601 013476d5 50b386ca 34736388 6df337d7
                            a54db7e9 8cc2df0d 828c31eb c62f3bc2 3f070c89 9648e276 2b26ffed a9d88ffb
                            f684c570 4937fedc 03f60c10 5b69542e d40f910b 4c66fc09 1f5e1c12 47628abc
                            e989b74a b0ef6f1a 14e2567f c083991e 1c846242 0bb8fbf9 b3f67b66 b02de042
                            0a18d49a 6d4896d0 d1dddbed 24ee1611 8090221f 9fe9a1e1 2194e0d2 b3c61c13`),
            Q: toBigint(`bb6a5c40 316bd80e 78246e92 ac9bf881 a9eb0cb9 6c7212eb 1e46ae0d`),

            H: fromHex(`8cd78a90 87aca828 9c0f5422 1e008eaa f46c56c0 581ea864 4a5e31a0 ca2c4805
                            f088edf8 31982079 00b51688 5d600a68 48998c38 12609c96 be143a82 f89cd4fc
                            c0b23380 fb5620bb 847b9b84 9be0a6db 40d3e2d0 7354ace8 5263048e 462ceac2
                            c8fc9984 d85a401d 764675a0 f9c038b1 582d8950 4568dc7d c031eeba c9888ea8
                            f06dbc24 ba7e782e 12246fc6 f858eca7 6c1af700 376a90e7 6c1fb75c 2f30525f
                            80cf3ae4 5ffcb0a8 ceb7b4fa 6e10c0da 9c8c85d0 586dd871 3800b9a0 b5c6285d
                            c01ad8a8 59fc0842 806cc64e 046a12e8 ecd4ec10 629340c6 66e0db04 f8bb047b
                            2024bb80 73320013 545cf834 c314fe16 c05a92f8 8c2eb468 4ae06466 967500f2`),
            G: toBigint(`487844c0 b67465b7 18f04dbd 453342b7 49076ee1 f4226f18 1db282e1 c51b0f29
                            0dae9601 ac73ed1f 1b25adad d50bfb42 1e8a09fa 07689a93 e5fb52a5 f8012956
                            b90641f8 45c4b7e4 45cafe2e 3284775b dd70bce4 0ef3274e 52cbc3d5 738da7a8
                            61bc46c0 a9693aa8 7e0aae62 bd371fa0 14ffc69f 3625d5a1 fbaaac80 d81c78a5
                            9badeae5 fdfea922 ebc330a1 37e7699a 2790e86b db270c21 35eab4e0 bcd28b77
                            13a8b241 1534c63f 2edf4e00 5902f6cc 1a155c29 f3eae17f 88acb5c6 70f5cf19
                            a5a54e87 6692ab82 08c4a9ef 75a29e74 f08f92ac 1a38592d 46a2557c 3a18c06e
                            d6529b40 bc5ecff9 715329a2 c01b4245 874250ed 515537ee 7458f898 6ff920bc`),

            XKEY: fromHex(`f910456a 20d9ba54 d61495ea 046d5de1 4b90ffdf eff64b4c a89150be`),
            X:    toBigint(`b55d61ec 0114e020 efc4c9bb 5f2f3d2e 38409e17 d3954174 6d94ff7c`),
            Y: toBigint(`0712496f cf76ce98 8be97ac0 9f0dbbe6 2d58707a 767d608a 3301115d 479cc871
                            4ce3a10b eb152552 46c2623e fe50bfd2 5a83c355 551574e6 e3560e7b d1cd5e7e
                            8e1269a4 a6f1976c 84e8fe8e 32e55aed d548fced cc92a6e4 e1bf2d1f 2aa30c0c
                            0a991c29 b2595029 f903b634 189aa70c fc429531 93016c1f 7bb6276d f3ebfae7
                            c060b987 d89088a0 558fc132 27b86f7a 57dde307 1cc022e0 39be4b68 3858d782
                            f52aa730 49d508ef 994a5039 cab5faf2 89bdac07 75efbb51 eb4d5ff9 99b71d59
                            c4d833b5 d069202a 968f3ac3 5fa77baf bdd9c096 0752c5da f783929d e2dad916
                            f1159e75 a345445d 63c5b422 e0bcd2ba d9379d14 43892ed5 d12f8285 3d51a705`),
            Z: toBigint(`c4 d8 33 b5 d0 69 20 2a 96 8f 3a c3 5f a7 7b af bd d9 c0 96 07 52 c5 da
                            f7 83 92 9d e2 da d9 16 f1 15 9e 75 a3 45 44 5d 63 c5 b4 22 e0 bc d2 ba
                            d9 37 9d 14 43 89 2e d5 d1 2f 82 85 3d 51 a7 05`),

            KKEY: toBigint(`a5c22f64 dde15693 3ad15bcb 928d6a3b 5acf0d7a 2302615c e74ccad6`),
            R: toBigint(`53 f7 31 8e 64 b6 1c cc 83 67 ac 08 51 19 a1 cb bb 25 51 0f e1 be c1 24
                            c2 99 89 e0`),
            S: toBigint(`b750f725 1585204c 236e4204 884166a2 6c6cf08b d281167a 5efadd52`),
        },
        // p.42
        {
            Sizes: A2048B256SHA256,
            Hash:  sha256.New,
            M:     M,

            Seedb: fromHex(`f7 5a bd a0 03 2c e2 18 ce 04 ba f0 a6 dc 92 c8 7e b4 6a a0 56 8c 42
                                78 2e 64 4c c2 b8 2e 24 9a`),
            J: toBigint(`804e0d9f 553ee7d2 3d093a41 cfdc7ef9 cc389257 f6a67cfc 392e06b9 b292899c
                            1d7e8163 9d48603d f18ec5fb 5e7833dc af967568 2c1491e9 366dc57e 9e20cd9c
                            04048f43 b8abdf4d 8f5ba69e 87b5d391 4bd91f24 58921154 1bc8ce9b 2e1707c7
                            90cab99f 453e8f88 0db8754d 509b029f ab06bcd9 26ab39f3 669bf3fe a49a3c00
                            0dea9378 01a9e3f9 ab247edb 1458a7a9 2bdc0b15 e859c6e3 bb842832 0951ec98
                            5a24f453 e20cb508 400ad47a 5cec76f4 bd4e6505 b59423a8 67f1fad5 59f19b76
                            03f9095a 8ca9aa18 1fa1632e 573e446b 61deefef c55ed7a4 02e46d4c 5706a0ab`),
            Count: 52733,
            P: toBigint(`d06eb9f2 75b3ac7f 2970b578 ad1c3173 2a012684 4776f95c f07b4194 c6def6f4
                            16a66751 458b0667 cdbc44af 3f6b5877 0e674a86 1c8febf4 eea0e504 50ec5272
                            26b84707 17ee768c f39cfd32 bc2540d2 924e0968 e64d47ee 4cf0ab6c d192284b
                            826c7508 2e18840b 67bc4cb1 f1708173 f08825ba 4f6e5fb8 6a357f02 c06f8283
                            f3cd58a1 ed4d3062 f4a5c0d2 f26e54c0 fa511b5e d5cfd270 19d4a90d da7aca50
                            561397ab eede9cff 45ec6cf3 e22dac5c af454b7b 9b3b5ffe 16128197 768114c9
                            cd4be4e9 ecdc431a 0cc0ed54 4fd4da1c 9e98a2c3 cb4297fe 1d1387d8 1c51d492
                            5ede6a8b baf660ef 675549b4 aea5267f b5f778d5 308dd691 75de580e c316c4ef`),
            Q: toBigint(`cfefed9c 75b5610f db100d91 c4cb8187 a0077917 33128ff1 43ffedf9 7f6ffd65`),

            H: fromHex(`cfbaee38 b256284b cd948b7d cc4bad84 8bc4908c 3c901434 101cac10 bd2b840d
                            ebccdd2b 942d4aa8 36d2b8ce da48e662 fc8fe9d4 efb92ccf 09042f30 2040c840
                            e8e0e010 789cc107 8431e7ec 2147d472 76f8aa1e 286246d8 9a159c53 8594d375
                            0cd3e504 2c183074 e8703c38 308426fc 45be04d5 d68ce56e f846c4c8 9ea41876
                            04e877fa bc97a2d4 37ca6c57 72e0c0d0 c028c020 10300019 2edc49e6 04f91eac
                            29bc289a 3c18123c 880abc78 1bc25c5b 8a941bd2 4c5b78d0 d408d05c 185064a8
                            747db63c cd8e849d e64c5694 d86e34e8 0654781e f4a43f0a 7c9ff2d4 7f5aac40
                            104068c0 6010f000 38463461 be1cd1b6 84c12e6c 8aec08c2 ac387aec e8b24a24`),
            G: toBigint(`023fec34 dfa5e5ce 369dd782 b07034af 037ac187 28d43204 5739b986 1b0df1dc
                            aeeb5c9e d3e025d8 3adcdae0 419c158b 09ee35ff 84ab9caa 9ed4e535 f982fb99
                            e30d3195 37c05780 a2cf31cf 6bb226c6 6b7b3ed7 6b65dc65 8b216b86 7f186d98
                            0d30d1a9 5285a081 c5aba363 939660a5 7596c621 2207e4e3 58b729bc 079778b4
                            f385824c 0862cdce 08aeb2c6 58c18559 d3ed865c d6bed194 da447fd4 1789c74d
                            352ed26b 56c2d128 f1154f73 3fe71f10 bf676c9f 7e4268c0 53d13152 997a2d9b
                            fb73fccb 0dcea4c1 32f68f28 2a6db325 cc467fb7 f1fe2da5 f80fd32c ae781a75
                            74845a3d 45712054 3987b348 d5d75b1b 954cba47 3f83951a 8c1be717 b953206c`),

            XKEY: fromHex(`f0f30814 a667cf10 587274d3 3bf2ab78 8b904cf1 2e97da0b c0a936e2 b948da94`),
            X:    toBigint(`21e2cf86 8d004318 aca87261 476dfc67 c1983364 82fe1dcb 3cbb5ba0 f081158a`),
            Y: toBigint(`44ce4c95 da1ff8bf bc6b7277 ccc6694e 1b1e6dfa cf617533 354da0cf 6966e156
                            2124003d b09e3330 9a24f87c 467917ae dfeb911f d5344422 06345275 7c40f0a0
                            bb45acc8 e462c5ac 4d8dd0f9 2fcc80f3 3e4160f5 98682bf5 71163c43 bd703c2c
                            1827db2e 2336511d 84520afa 97dc4962 40ea4a82 ca2ffc64 6363f822 d037c813
                            8f3458a3 e41bd3a0 23b63cc1 13b33ecb 3fcccc5c bed325e7 ec1f07e2 03e9aa8e
                            451c96fb dec927d6 ee741540 a90673b4 f2feac07 b6f4eda0 8db28fdf aed8634e
                            7ff40582 ae33d8db f377a761 9ad1c006 68633779 2943e6cd 016d5534 e4122bca
                            18d12075 79ea4c90 610a1496 b63c23dc 996b686e feb34c36 1f9afdcf 7e8fbf9a`),
            Z: toBigint(`7f f4 05 82 ae 33 d8 db f3 77 a7 61 9a d1 c0 06 68 63 37 79 29 43 e6 cd
                            01 6d 55 34 e4 12 2b ca 18 d1 20 75 79 ea 4c 90 61 0a 14 96 b6 3c 23 dc
                            99 6b 68 6e fe b3 4c 36 1f 9a fd cf 7e 8f bf 9a`),

            KKEY: toBigint(`0d30f8f9 2313f7a5 abe0b0de ec219e40 c4640c89 39222aa0 dd6a3329 55778025`),
            R: toBigint(`59 49 00 77 f9 8c 21 78 85 09 cb 47 8c cd e7 7a 4f b5 41 4e 13 cf 92 81
                            cb 80 97 5b 33 70 d9 7d`),
            S: toBigint(`185f21b5 dbf4255b 954a4d62 cf363c32 73211147 cba054e8 3a87da2d d7e0741d`),
        },
        // p.48
        {
            Sizes: A3072B256SHA256,
            Hash:  sha256.New,
            M:     M,

            Seedb: fromHex(`b8 56 20 16 38 55 a7 c0 05 76 13 dc d1 f2 ae 61 80 c4 34 d0 98 90 ea
                                70 22 00 83 f2 8d 27 54 ad`),
            J: toBigint(`85eee24d 8bc775c7 adab8963 9c4013f6 ad8f98c8 350bcd4d db7ed3ca 1e56bd46
                            97fdb8aa 9896e1de 0514d829 6c47d0db 8a68bbb0 1b6b4ffd 400c4cf0 c14d2d01
                            7f50c3c5 cd8fcce8 b2bba2a5 18ac63fe 409e8e5a 3c9cc823 20f4fd45 7cdf86d0
                            0802c95a ee823b0f 057f83a9 433fda61 08de1fed b745c808 6308e828 22503ddf
                            8f775a61 1800db09 2ceaa133 6cf03140 79c198b8 71222b50 49738967 32c39201
                            53e1c174 cb77f7c2 1f16e012 5607afee c73e0e1a 9dcabf02 88c27815 0972525d
                            315801d9 b2989b72 eca68929 4f795af4 163c8489 fd37861f 9f6ac78d beb18ff6
                            e80f8747 83b08f05 520b59c6 7b2fb4b3 9dc8f7a6 5dd206c7 6f614d8e 92fad067
                            1286d375 50ba9bad df01a7e6 3d3d344e eadbdb75 a2ec4943 bc07a2d9 8a5e8e63
                            ba941d85 c9740d50 b15a0ec2 9e7e3f70 054b1ec8 4dba0662 cfe5d301 cfe78255
                            41fe867b 7b1ec83c ecc813ae 92f91c37 3891dfd6 790d83d2 67c3b52a 557f8701`),
            Count: 3448,
            P: toBigint(`cbaeace3 677e98ad b2e49c00 2b8b0f43 4143b466 515839bf 813b097d 2d1ee681
                            5008c27a 3415bc22 31609874 5e5844f3 3ecc8887 c16dfb1c fb77dc4c 3f3571cc
                            eefd4291 8f6c48c3 702ab6ef 0919b7e8 402fc89b 35d09a0e 5040e309 1ee4674b
                            e891933c 1007e017 edd40818 7e4114b6 be5548d7 8db58b84 8475a422 62d7eb79
                            5f08d161 1055efea 8a6aeb20 eb0f1c22 f002a2e8 195bcbba 830b8461 3531bdd9
                            ec71e5a9 7a9dccc6 5d6117b8 5d0ca66c 3fdaa347 6e97adcd 05a1f490 2bd04b92
                            f400c42b a0c9940a 32600443 3b6d3001 28bf930f 484eaa63 02cd7a31 9ee5e561
                            a12a3625 594020c2 40dba3be bd8a4751 5841f198 ebe43218 2639616f 6a7f9bd7
                            434f0534 8f7f1db3 115a9fee ba984a2b 73784334 de7737ee 3704535f ca2f4904
                            cb4ad58f 172f2648 e1d62d05 8539ac78 3d032d18 33d2b9aa d96982c9 692e0ddb
                            b6615508 83ed66f7 aa8bce8f f0663a0a dda226c7 bd0e06df c72594a3 87c676a3
                            ca06a300 62be1d85 f23e3e02 c4d65e06 1b619b04 e83a318e c55eca06 9eb85603`),
            Q: toBigint(`c2a8caf4 87180079 66f2ec13 4eaba3cb b07f31a8 f2667acb 5d9b872f a760a401`),

            H: fromHex(`cafddcde a0226466 28aaec4c f61afea2 062a0eb2 d5cb81fc 02c84e94 9a60d8f0
                            c860b894 3ca4cc07 81bbb56f e923d05a 5834d02c 4824c01c 38140907 c543817f
                            3dbbf940 d0806000 60806000 0afcae20 5263e527 29eb4a5e 32c61a2e 027498ba
                            30665c12 88beb46a ad24bc14 2c049cf4 0ce44f79 ee68a29c 56d00a38 c4101c62
                            bedab652 ae31df4d 7b6917be bc7ac0d0 a0308090 60f04071 e31507b9 2b5d4f01
                            7302ac00 14e87cd0 e4b80a30 16bcc7bd 73e91f34 bc040cd4 5c3810a8 006a147e
                            a8923ca6 d00d3a46 129eeaf6 c24e9abb 9ac8b664 d200ee9c 0a8040c0 00d060b0
                            c090c9eb cd6fd1f3 94063834 b8fc00c4 488c9002 56a74db3 d9bf65cb f1d71cc0
                            88105860 28b0f800 9af46913 7da7913b a502be3a 76724894 a06c8caa 882684a2
                            80275543 b8f8f8b8 38787838 b8e88aec 0ef092f4 16f82458 4c86cace 92165a5e
                            df354b21 2c5238de 448840b8 f0e8a018 844c536d 47e13b55 2fc92360 bcf8f4b0
                            2c686420 9cecba29 4725c321 3f1d3060 50004040 0080c0c0 287a8c5e f042e385`),
            G: toBigint(`17a1c167 af836cc8 5149be43 63f1bb4f 0010848f c9b678b4 e026f1f3 87133749
                            a4b1bba4 c23252a4 c86f31e2 1e8acacb 4e33ad89 b7c3d79a 5409268b fba82b45
                            814e4352 0c09d631 613fa35d b9caf18f 791c2729 a4b014bc 79a85a90 cd541037
                            119eccde 0778863f fcb9c259 31fcd33a 6706e5fe 1f495bb8 bcb3d0ee c9b6d5a9
                            373127a2 121e37d9 8a840330 258dbfce e7e06f81 5b69c16c 5d17289c 4cc37e71
                            9b856298 d4e1574e 4f4f8515 baf9a850 d11dda09 55bc30fa 5b16792d 673a3b1f
                            41512fc3 eb89452d 51509f97 4d878b48 2d2ad2ed 32be1905 6f574504 2bff804f
                            b7482796 612b746f e8d70a83 8cc6f496 dd0ffc3d 95c1e0b1 98184d73 523656a0
                            6431bc52 5c2bc161 9729e8c0 88f6df91 5645e060 922a4af3 edd63047 c7b6077c
                            667c07d8 8eb00f4c fe59d32e 5f545012 c566516b 7874fb3d aed51403 31f29528
                            b30fc8b8 a9371c28 18017b09 53a84ffc 9fbff84b 64bf0238 aa7e2af2 ecadc15a
                            1c06dadc f1f2e7b1 240a5e64 5a6469c9 b002215d 9a91c2a4 ed2fb547 a942d777`),

            XKEY: fromHex(`80f96d39 d9e9230d 47c7ac5b c40e94d7 c3ca4c8e fa2bb0cd f1a369ab 14dfce52`),
            X:    toBigint(`7c28569a 94b46fa7 45c8d306 ad7dc189 96ce046e ebe04383 8391c232 078db05a`),
            Y: toBigint(`2574e10e 806f1c42 58f7cf8f a4a6cf2b eb177dbe 60e4ec17 df21dcdb a72073f6
                            5565506d a3df98d5 a6c8eee6 1b6b5d88 b98c47c2 b2f6fc6f 504fa4fb c7f411e2
                            3eaa3b18 7a353dae d41533a9 558ab932 0a154cae cc544e43 0008889a 2c899373
                            ec75a24c ff26247c f297d293 747ecc05 b3483647 a87bcbb8 d4500092 09f5e449
                            a00a659b 637ce139 cf6487ac a70f9c00 cb670c7f 3b95bfd7 cf236a0a 6f3c93be
                            8d9cf591 c9d30686 9415b1aa 97264b90 4167850a 4794c780 be4527df feb67be6
                            e66786c5 cce0378c cb49920d 855558f4 dac4c42f 92dd229b 483b2257 db0ce35d
                            c737f980 1a261a02 bdf718c2 fd4d69c5 2e0d9712 b42c4897 bae7c684 d3d35bc5
                            726ce899 2696b044 d722afba 78efa858 c4d10f19 72112ce8 ffd39792 49bf14e4
                            9d8e0d9a cb1b0a9c a90d0551 1803845d 7c670bcf 1b066497 a7743b08 a219e764
                            ea0a3a2a 617661c1 6a372fe0 58b547a2 8b626ecf 442222e1 8eef487c c101dbfb
                            715bc33a b85928ec f0bd4dea 30f250a6 a5c86178 83ea0f87 3e7a4651 98c4644b`),
            Z: toBigint(`ea 0a 3a 2a 61 76 61 c1 6a 37 2f e0 58 b5 47 a2 8b 62 6e cf 44 22 22 e1
                            8e ef 48 7c c1 01 db fb 71 5b c3 3a b8 59 28 ec f0 bd 4d ea 30 f2 50 a6
                            a5 c8 61 78 83 ea 0f 87 3e 7a 46 51 98 c4 64 4b`),

            KKEY: toBigint(`83f3008f cebae57e c7a64a3a f7ee6ee1 9cc197a6 d5eba3a5 b3ef79b2 f8f3dd53`),
            R: toBigint(`54 7a 99 02 07 de dd 6d ff 97 89 c4 78 79 ac d9 60 d7 92 51 4b d9 1c 51
                            de c2 a2 4f 90 4c 03 f1`),
            S: toBigint(`1668797b 26641e72 94aa68d3 8562eae3 caa842d0 f446949c 4268ae3d 0392434f`),
        },
        // p.55
        {
            Sizes: A1024B160HAS160,
            Hash:  has160.New,
            M:     M,

            Seedb: fromHex(`68 ad b0 d1 b6 ae f1 44 a9 50 f3 e7 84 c9 89 3d 36 04 09 0e`),
            J: toBigint(`8cfa55c3 2582e0d7 4a09ef55 c5d2acac 5b46e9f3 5470ac48 1d95438c 7f5cc107
                            1d4e0bc5 877e0a0f c6b30dc6 c743f238 9bc69b8f cb7affeb dea013f8 64c68ac2
                            cb8bd7b5 c434809f c6d1b62c d9f20bb1 a7fab58c c3f5d2dc a511e2e4 077e9def
                            912141f8 47f8751d 1dc47f3d`),
            Count: 5189,
            P: toBigint(`d7b9afc1 04f4d53f 737db88d 6bf77e12 cd7ec3d7 1cbe3cb7 4cd224bf f348154a
                            fba6bfed 797044df c655dcc2 0c952c0e c43a97e1 ad67e687 d10729ca f622845d
                            162afca8 f0248cc4 12b3596c 4c5d3384 f7e25ee6 44ba87bb 09b164fb 465477b8
                            7fdba5ea a400ffa0 925714ae 19464ffa cead3a97 50d12194 8ab2d8d6 5c82379f`),
            Q: toBigint(`c3ddd371 7bf05b8f 8dd725c1 62f0b943 2c6f77fb`),

            H: fromHex(`1711797e cf9bc4b8 1c5ad487 b2d9f3d4 f4de8616 c47bb030 355ea4bf 2ab07104
                            0ee59c95 453119d7 68af7a79 95133c2d a1e302c6 9128afba 129e698d c7982f56
                            064c70c1 8fb523ba 826b76f8 1efa58a9 1226e6af c96e2010 97589940 8e785fe4
                            a338b398 065ffd22 2fd1e1b7 a1da01a0 90b84168 e3522241 d2855a4e fe87611a`),
            G: toBigint(`50e414c7 a56892d1 ad633e42 d5cd8346 f2c09808 111c772c c30b0c54 4102c27e
                            7b5f9bec 57b9df2a 15312891 9d795e46 652b2a07 2e1f2517 f2a3afff 5815253a
                            aefe3572 4cfa1af6 afce3a6b 41e3d0e1 3bed0eff 54383c46 65e69b47 ba79bbc3
                            339f86b9 be2b5889 4a18b201 afc41fe3 a0d93d31 25efda79 bc50dbbb 2c3ab639`),

            XKEY: fromHex(`f2072ce3 0a017656 8324564b fdbd7077 173b7e3f`),
            X:    toBigint(`068c4ef3 55d8b6f5 3eff1df6 f243f985 63896c58`),
            Y: toBigint(`96dce0e7 b2f17009 3d9b51d2 ba782027 33b62c40 6d376975 8b3e0cbb a1ff6c78
                            727a3570 3cb6bc24 76c3c293 743dfee9 4aa4b9ef a9a17fa6 bf790ac2 5a82c615
                            23f50aba ac7b6464 7eb15c95 7b07f5ed 7d467243 089f7469 5cd58fbf 57920cc0
                            c05d4582 9c0a8161 b943f184 51845760 ed096540 e78aa975 0b03d024 48cbf8de`),
            Z: toBigint(`23 f5 0a ba ac 7b 64 64 7e b1 5c 95 7b 07 f5 ed 7d 46 72 43 08 9f 74 69
                            5c d5 8f bf 57 92 0c c0 c0 5d 45 82 9c 0a 81 61 b9 43 f1 84 51 84 57 60
                            ed 09 65 40 e7 8a a9 75 0b 03 d0 24 48 cb f8 de`),

            KKEY: toBigint(`4b037e4b 573bb7e3 34cad0a7 0bed6b58 81df9e8e`),
            R:    toBigint(`8f 99 6a 98 ed a5 7c c8 d8 8a a6 ff df ae a2 2f 39 d7 fa 8a`),
            S:    toBigint(`541f7dc4 f92c65eb 7f63b6b4 f22177f1 ee2cf339`),
        },
    }
)
