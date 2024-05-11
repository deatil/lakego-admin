package shavite

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
           fromHex(""),
           fromHex("b33f761f0d3a86bb1051905aec7a691bd0b5a24c3721f67d8e48d839"),
        },
        {
           fromHex("cc"),
           fromHex("47b8fee436662cf2a3d3da3aae797319946cd3cdc31654f09217dc9c"),
        },
        {
           fromHex("41fb"),
           fromHex("3b94eb733ab02a2f7d590f8169fde875c39a54648229f54e59087cc0"),
        },
        {
           fromHex("1F877C"),
           fromHex("623a1f7c9fa33d3a481c996c55e70f44eaa5de42a58174ba5220d6d3"),
        },
        {
           fromHex("c1ecfdfc"),
           fromHex("e087f1b577d82808012c85e30192e37798e33023e4b3f066c034c836"),
        },
        {
           fromHex("1f66ab4185ed9b6375"),
           fromHex("41ddfb0cc77761c29c06c771705bdb511913b8563c7f09fdc14a1066"),
        },
        {
           fromHex("a746273228122f381c3b46e4f1"),
           fromHex("8bdc40f81eae4ff0cf62dd7a638032b7f9e8a0326fbf771147e38d11"),
        },
        {
           fromHex("d8dc8fdefbdce9d44e4cbafe78447bae3b5436102a"),
           fromHex("d3110cb6edafab7922f028e6456ace17065a2c7e2c2d75a261432025"),
        },
        {
           fromHex("aecbb02759f7433d6fcb06963c74061cd83b5b3ffa6f13c6"),
           fromHex("acf8b4c206a3a8f5433c137fab60a3a87a956d9768650402ede3549f"),
        },
        {
           fromHex("512a6d292e67ecb2fe486bfe92660953a75484ff4c4f2eca2b0af0edcdd4339c6b2ee4e542"),
           fromHex("ca6baeeaf54d4df84e4bcd1fccfc8a307c3adb9fc41429bcdf4cd76a"),
        },
        {
           fromHex("c8f2b693bd0d75ef99caebdc22adf4088a95a3542f637203e283bbc3268780e787d68d28cc3897452f6a22aa8573ccebf245972a"),
           fromHex("729f108bdae50b79c021fa5a196e122ca28081415eb7df3fd48a4aa0"),
        },
        {
           fromHex("2fda311dbba27321c5329510fae6948f03210b76d43e7448d1689a063877b6d14c4f6d0eaa96c150051371f7dd8a4119f7da5c483cc3e6723c01fb7d"),
           fromHex("bf725df0437e578869bb34baae109b5861c189798d9287bd20ea0211"),
        },
        {
           fromHex("758ea3fea738973db0b8be7e599bbef4519373d6e6dcd7195ea885fc991d896762992759c2a09002912fb08e0cb5b76f49162aeb8cf87b172cf3ad190253df612f77b1f0c532e3b5fc99c2d31f8f65011695a087a35ee4eee5e334c369d8ee5d29f695815d866da99df3f79403"),
           fromHex("4616de60ca4645fdba484a743575d7c3e7dfb8f4f3bc6b4c91165905"),
        },
        {
           fromHex("84891e52e0d451813210c3fd635b39a03a6b7a7317b221a7abc270dfa946c42669aacbbbdf801e1584f330e28c729847ea14152bd637b3d0f2b38b4bd5bf9c791c58806281103a3eabbaede5e711e539e6a8b2cf297cf351c078b4fa8f7f35cf61bebf8814bf248a01d41e86c5715ea40c63f7375379a7eb1d78f27622fb468ab784aaaba4e534a6dfd1df6fa15511341e725ed2e87f98737ccb7b6a6dfae416477472b046bf1811187d151bfa9f7b2bf9acdb23a3be507cdf14cfdf517d2cb5fb9e4ab6"),
           fromHex("01f4aa0a2d7ba7441104824e3526b0a530a3f7c5df32b9867f445383"),
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
           fromHex("08c5825af2e9e5947286a8fe208bd5f8c6a7c8e4da598947d7ff8eda0fcd2bd7"),
        },
        {
           fromHex("cc"),
           fromHex("a0ee13af2658a165434e3b5afe81cc053cb051cb08a40c0768a77209d10eff86"),
        },
        {
           fromHex("41fb"),
           fromHex("d14cbcf9314108921e1118e9749e6fd1162a79a424ef383adc311cac4c662412"),
        },
        {
           fromHex("1F877C"),
           fromHex("cdce33f661886fe9f63382c6a3e40b0de15f1b164dff83f5eea0288f2bf39214"),
        },
        {
           fromHex("c1ecfdfc"),
           fromHex("a4879ccc8107e9e508b1e6d992a9f8b77405be2efca7e03a719ce8ac1e8f6673"),
        },
        {
           fromHex("1f66ab4185ed9b6375"),
           fromHex("20a8128c86f562a862b9b2046955de614e90ad545ba9b5fcb72c2629d5284a4d"),
        },
        {
           fromHex("a746273228122f381c3b46e4f1"),
           fromHex("35cb8f82c2114b54823060a7a4fd6a77487196945b9a906401a3641ac833ae29"),
        },
        {
           fromHex("d8dc8fdefbdce9d44e4cbafe78447bae3b5436102a"),
           fromHex("926d50be8203c50b0bcc2953d003e3cab60fc2904fcbb30f1af09cc6be5638c5"),
        },
        {
           fromHex("7e15d2b9ea74ca60f66c8dfab377d9198b7b16deb6a1ba0ea3c7ee2042f89d3786e779cf053c77785aa9e692f821f14a7f51"),
           fromHex("1a52145d06069d4d931eb6f5638309aa88e5dc167ec6c45788b038c1b41ec8ae"),
        },
        {
           fromHex("95d1474a5aab5d2422aca6e481187833a6212bd2d0f91451a67dd786dfc91dfed51b35f47e1deb8a8ab4b9cb67b70179cc26f553ae7b569969ce151b8d"),
           fromHex("2a59b288426dd4786ba716ebc55e258a4beddbaedb901afbb9529f003c2a4862"),
        },
        {
           fromHex("90078999fd3c35b8afbf4066cbde335891365f0fc75c1286cdd88fa51fab94f9b8def7c9ac582a5dbcd95817afb7d1b48f63704e19c2baa4df347f48d4a6d603013c23f1e9611d595ebac37c"),
           fromHex("3609217d0035871babc6977649aec3fc3aaa22be2e49a56916f6d851a8a49c31"),
        },
        {
           fromHex("e35780eb9799ad4c77535d4ddb683cf33ef367715327cf4c4a58ed9cbdcdd486f669f80189d549a9364fa82a51a52654ec721bb3aab95dceb4a86a6afa93826db923517e928f33e3fba850d45660ef83b9876accafa2a9987a254b137c6e140a21691e1069413848"),
           fromHex("715e3da4ab6d90a2d7aaa92a7f197d1cf1298c357632a10781b7b752abc413ab"),
        },
        {
           fromHex("e90847ae6797fbc0b6b36d6e588c0a743d725788ca50b6d792352ea8294f5ba654a15366b8e1b288d84f5178240827975a763bc45c7b0430e8a559df4488505e009c63da994f1403f407958203cebb6e37d89c94a5eacf6039a327f6c4dbbc7a2a307d976aa39e41af6537243fc218dfa6ab4dd817b6a397df5ca69107a9198799ed248641b63b42cb4c29bfdd7975ac96edfc274ac562d0474c60347a078ce4c25e88"),
           fromHex("f98d02787f6aeac8e52cd8ab386f107fae7c17709c4cd31d5aa92305214c6f29"),
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
           fromHex("814b55553ce7c0841f8ff0321e6287f9f50a8e0cae811932385ecc1b7c386b4eb14edb79c8381babf09276b69d1bb3ee"),
        },
        {
           fromHex("cc"),
           fromHex("35dc52e484750c578bb53516d7299b0ae0b7b7c74c301a301b70b2c5dc627082a389b4eac9085317d5e123a46dec1acb"),
        },
        {
           fromHex("41fb"),
           fromHex("0a74a38f5106b39c76a332063248df5021f15ff63a0a9b2e9774c902d6ad0ae9e1e746d933f82a88f9e7cc1baba9c677"),
        },
        {
           fromHex("1F877C"),
           fromHex("b22e87c107a7135abf1dad9d2800fc5162631a49d2f727a30c991715a22adb62ebdac57defbfc95bd2c506b13071457f"),
        },
        {
           fromHex("c1ecfdfc"),
           fromHex("6d8870e1492a00440cff7e3bc62f403a049416941d1b29d4d79a000b7e1ca465537d05144c514503295d0f2592711838"),
        },
        {
           fromHex("1f66ab4185ed9b6375"),
           fromHex("a319790d098f342b0fec3571889be60f538ced7937a19109a7f650fa2e01eab4f86aa40c3329edd7deb58d12b687d853"),
        },
        {
           fromHex("a746273228122f381c3b46e4f1"),
           fromHex("f6a19a20c2becbeddc8babd94483edae9407d34d1d503d4bf51daf2fd878af6f57daf987fd9d1eea4fb64faedea21ef7"),
        },
        {
           fromHex("aecbb02759f7433d6fcb06963c74061cd83b5b3ffa6f13c6"),
           fromHex("4a84d216198968601bb07cd3d09889a6229f308cf8aad49009b9867d2ea954435879068b0888a4d65dac82359239fb1c"),
        },
        {
           fromHex("62f154ec394d0bc757d045c798c8b87a00e0655d0481a7d2d9fb58d93aedc676b5a0"),
           fromHex("96577a0a483f0c03967c5ed1e0982cf7abf1f8486a087c70bf4b0b55aba121d6219691694aee401eec1ad3478cdae324"),
        },
        {
           fromHex("eebcc18057252cbf3f9c070f1a73213356d5d4bc19ac2a411ec8cdeee7a571e2e20eaf61fd0c33a0ffeb297ddb77a97f0a415347db66bcaf"),
           fromHex("e3ccd40e8956c2f39093d2309dbe6fef03879763a903dedebf135471d80b31f3a66c94274bc9579fe9a5491a3749ca55"),
        },
        {
           fromHex("bbfd933d1fd7bf594ac7f435277dc17d8d5a5b8e4d13d96d2f64e771abbd51a5a8aea741beccbddb177bcea05243ebd003cfdeae877cca4da94605b67691919d8b033f77d384ca01593c1b"),
           fromHex("466a01a79492eb372c43b071f223413bb543d7af2005d6d65bb1443dbc759b62735ef83044c210fb5c426ec704ab9e1a"),
        },
        {
           fromHex("7adc0b6693e61c269f278e6944a5a2d8300981e40022f839ac644387bfac9086650085c2cdc585fea47b9d2e52d65a2b29a7dc370401ef5d60dd0d21f9e2b90fae919319b14b8c5565b0423cefb827d5f1203302a9d01523498a4db10374"),
           fromHex("a0f0c49f57dbd1846cc612ac90728519ce44a20e67084dd2520ae9fe7043b56b6a6fbea3a02c144197b9e76e5aa53754"),
        },
        {
           fromHex("f76b85dc67421025d64e93096d1d712b7baf7fb001716f02d33b2160c2c882c310ef13a576b1c2d30ef8f78ef8d2f465007109aad93f74cb9e7d7bef7c9590e8af3b267c89c15db238138c45833c98cc4a471a7802723ef4c744a853cf80a0c2568dd4ed58a2c9644806f42104cee53628e5bdf7b63b0b338e931e31b87c24b146c6d040605567ceef5960df9e022cb469d4c787f4cba3c544a1ac91f95f"),
           fromHex("e4620129738b436a89cf2c089a943ce173b6c03fc2f522cc7ba76a3a4426835bfc748a7a0caf377ce97866f3440ca0ec"),
        },
        {
           fromHex("9f2c18ade9b380c784e170fb763e9aa205f64303067eb1bcea93df5dac4bf5a2e00b78195f808df24fc76e26cb7be31dc35f0844cded1567bba29858cffc97fb29010331b01d6a3fb3159cc1b973d255da9843e34a0a4061cabdb9ed37f241bfabb3c20d32743f4026b59a4ccc385a2301f83c0b0a190b0f2d01acb8f0d41111e10f2f4e149379275599a52dc089b35fdd5234b0cfb7b6d8aebd563ca1fa653c5c021dfd6f5920e6f18bfafdbecbf0ab00281333ed50b9a999549c1c8f8c63d7626c48322e9791d5ff72294049bde91e73f8"),
           fromHex("80e117640acaf0ad32686bf76bd4eaafc445df65edc273da09c8ecf58412d92ea8393fdbcbe292ff4d4d64dd69ed5714"),
        },
        {
           fromHex("04e16dedc1227902baaf332d3d08923601bdd64f573faa1bb7201918cfe16b1e10151dae875da0c0d63c59c3dd050c4c6a874011b018421afc4623ab0381831b2da2a8ba42c96e4f70864ac44e106f94311051e74c77c1291bf5db9539e69567bf6a11cf6932bbbad33f8946bf5814c066d851633d1a513510039b349939bfd42b858c21827c8ff05f1d09b1b0765dc78a135b5ca4dfba0801bcaddfa175623c8b647eacfb4444b85a44f73890607d06d507a4f8393658788669f6ef4deb58d08c50ca0756d5e2f49d1a7ad73e0f0b3d3b5f090acf622b1878c59133e4a848e05153592ea81c6fbf"),
           fromHex("e9047cfb4017ea0f226e4a665e39c8b1b4edae3938a29b4f260d734d0d7a8125a537da6b9348e9342fd3f094ef925524"),
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
           fromHex("a485c1b2578459d1efc5dddd840bb0b4a650ac82fe68f58c4442ccda747da006b2d1dc6b4a4eb7d84ff91e1f466fef429d259acd995dddcad16fa545c7a6e5ba"),
        },
        {
           fromHex("cc"),
           fromHex("3fe519289541f0ec62f2247b55844f9dfce6d008c9062e4ae2821a0dd9e47b7e37e9b859e1b2d0e0cf1090c68223034c94314a190b92bf71f3810ee32b2732e6"),
        },
        {
           fromHex("41fb"),
           fromHex("8def5b88bc6d60da48f14e88ef66dde72ad2dfffa51fe5ab2a165598b2b4698c46bedc79f4f147bb033e9ec8fd2697596db4329b9c524885b313559bbe2f8e7f"),
        },
        {
           fromHex("1F877C"),
           fromHex("eea90031f7e5954f8d65a58480dd29e7014e03bbe24fefa9b0f3dd37a3e6f9a1cf4803584c0e19155732c100eecf3f035e00f7debec7f90ce386a9ecd363c3f6"),
        },
        {
           fromHex("c1ecfdfc"),
           fromHex("dcfd5938d89f88ebaff8d724e59ffc9144b565cf42678773feb3756a5a756ac52e53402a676e20d526d4513e8251dc7413b760b31563f4f206b6578ab9e118b9"),
        },
        {
           fromHex("1f66ab4185ed9b6375"),
           fromHex("a2a86a68f5a1d175dd2dc81270b6fce4ee88be260d33d40e6a65cb9c476942af60648c3762997108d408d47e9ac22b90db6999840855534a470d62f7875701a9"),
        },
        {
           fromHex("a746273228122f381c3b46e4f1"),
           fromHex("8187d8b9e67757e4b231aa11f3c3cef702942224e9b7b3000a2cf67743e03b807d5772ebaf2d06f6d6e8bf1e7a7892ba3a2a6688331d31020cbcd05d0e4cd51a"),
        },
        {
           fromHex("d8dc8fdefbdce9d44e4cbafe78447bae3b5436102a"),
           fromHex("078b1b7a072d456d6d76d31b9f557feab8bc4d0bd3da2b7e9cab3a0d6dbc93cea7eb9b42502c1abd9b758abb73f62d195785155fb72815dc120eb3d3a8e4b051"),
        },
        {
           fromHex("973cf2b4dcf0bfa872b41194cb05bb4e16760a1840d8343301802576197ec19e2a1493d8f4fb"),
           fromHex("30a0e0c9f408dad84de6df5a4debe13500b487a9efff7f21e30070c32feacc2ea45bd219d9d20c14edcc06ce708a04f7bdd26f0648ce1949bc7215967f6772ca"),
        },
        {
           fromHex("c8f2b693bd0d75ef99caebdc22adf4088a95a3542f637203e283bbc3268780e787d68d28cc3897452f6a22aa8573ccebf245972a"),
           fromHex("b872d1254cf30496b090305261a9eadcce04b5d55fbf34a0a9b092c64baf297a9e93475fea253895d04192e28851349a653a196949547a356712cf6f019c7649"),
        },
        {
           fromHex("fc424eeb27c18a11c01f39c555d8b78a805b88dba1dc2a42ed5e2c0ec737ff68b2456d80eb85e11714fa3f8eabfb906d3c17964cb4f5e76b29c1765db03d91be37fc"),
           fromHex("5ba057ed8a3a540d4d34ea062e7ca8b91bf37826c24bce02884adfe514f84a1cfe0bc6d18fab84980825f4c874dfa7434a371f34a2b0e57925b60b26da9494ab"),
        },
        {
           fromHex("871a0d7a5f36c3da1dfce57acd8ab8487c274fad336bc137ebd6ff4658b547c1dcfab65f037aa58f35ef16aff4abe77ba61f65826f7be681b5b6d5a1ea8085e2ae9cd5cf0991878a311b549a6d6af230"),
           fromHex("adecf698b0133cd08c96c86dc70a6cbb76846d42e6cbe863ebeb638f46bbd494f1717066476540dcc23282f6e9cf17bd9b758716d5a1b971c410000bb9a1e81d"),
        },
        {
           fromHex("e1fffa9826cce8b86bccefb8794e48c46cdf372013f782eced1e378269b7be2b7bf51374092261ae120e822be685f2e7a83664bcfbe38fe8633f24e633ffe1988e1bc5acf59a587079a57a910bda60060e85b5f5b6f776f0529639d9cce4bd"),
           fromHex("931d668bf32f2329684494f147eb857a5d8dd58ffe2a1043bcd398b6a149dd0cb48fc397ee9fcf700f1218239223c6035a52e5452ca779eab737708bed0cb712"),
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
