package bmw

import (
    "fmt"
    "bytes"
    "testing"
    "encoding/hex"
)

func fromHex(s string) []byte {
    h, _ := hex.DecodeString(s)
    return h
}

func Test_Hash256(t *testing.T) {
    msg := []byte("test-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-data")

    h := New256()
    h.Write(msg)
    dst := h.Sum(nil)

    if len(dst) == 0 {
        t.Error("Hash make error")
    }
}

func Test_Sum256(t *testing.T) {
    msg := "78AECC1F4DBF27AC146780EEA8DCC56B"
    check := "73092167d7f56feffc58dded2b30b281d170ccd54042dd1f1991189aac1ae5f3"

    dst := Sum256([]byte(msg))

    if fmt.Sprintf("%x", dst) != check {
        t.Errorf("fail, got %x, want %s", dst, check)
    }

}

type testData struct {
    msg []byte
    md []byte
}

func Test_Hash224_Check(t *testing.T) {
   tests := []testData{
        {
           fromHex("616263"),
           fromHex("246607792ad2625430c81e2c4ea1380add5b08fb8075daed4f401dbc"),
        },
        {
           fromHex(""),
           fromHex("e57c183da7e2cd3e90258ca04499b222420f9b6797bbab131b4d286e"),
        },
        {
           fromHex("cc"),
           fromHex("6cf1f720cc1a79eb0a5462bf13efd47499ca52179c6f575147217577"),
        },
        {
           fromHex("41fb"),
           fromHex("6f60c745033efac6e7cc1686cb218b01f17305cf4adb57621185ff17"),
        },
        {
           fromHex("1F877C"),
           fromHex("d94d4e14316300d08f1d34cc6d9d68311b727312be18b0fe5642607c"),
        },
        {
           fromHex("c1ecfdfc"),
           fromHex("11008baaa758782b229e094253336f9cdc5545cc6a0235a7e713b8a3"),
        },
        {
           fromHex("1f66ab4185ed9b6375"),
           fromHex("32f4f41b07860222909953cff34276d6e9cd4107942ade17687a9d71"),
        },
        {
           fromHex("a746273228122f381c3b46e4f1"),
           fromHex("93a4df221b69ed0cda5728a919dd642351595d8535c7c7cd4f0fdd57"),
        },
        {
           fromHex("d8dc8fdefbdce9d44e4cbafe78447bae3b5436102a"),
           fromHex("b6ab1c3434f9ade3bf49300d57d5de093dfdff4160a1376c00f8ddaa"),
        },
        {
           fromHex("aecbb02759f7433d6fcb06963c74061cd83b5b3ffa6f13c6"),
           fromHex("334e70fd7b76e1756374eceee0803dadbd4490d529fddb35f723c37e"),
        },
        {
           fromHex("512a6d292e67ecb2fe486bfe92660953a75484ff4c4f2eca2b0af0edcdd4339c6b2ee4e542"),
           fromHex("62f6649322e091c000dd98ff370c42e351c46b8de5915316799ce6c3"),
        },
        {
           fromHex("f57c64006d9ea761892e145c99df1b24640883da79d9ed5262859dcda8c3c32e05b03d984f1ab4a230242ab6b78d368dc5aaa1e6d3498d53371e84b0c1d4ba"),
           fromHex("19c93ea4ef6a0d579ca1495b2f46d202831718cd30443dd3da92bd63"),
        },
        {
           fromHex("758ea3fea738973db0b8be7e599bbef4519373d6e6dcd7195ea885fc991d896762992759c2a09002912fb08e0cb5b76f49162aeb8cf87b172cf3ad190253df612f77b1f0c532e3b5fc99c2d31f8f65011695a087a35ee4eee5e334c369d8ee5d29f695815d866da99df3f79403"),
           fromHex("42af40cc529470f571a779f4e810b95996ac6fdc2067f58b8ef4d34c"),
        },
        {
           fromHex("2b6db7ced8665ebe9deb080295218426bdaa7c6da9add2088932cdffbaa1c14129bccdd70f369efb149285858d2b1d155d14de2fdb680a8b027284055182a0cae275234cc9c92863c1b4ab66f304cf0621cd54565f5bff461d3b461bd40df28198e3732501b4860eadd503d26d6e69338f4e0456e9e9baf3d827ae685fb1d817"),
           fromHex("7c4a66e78a74d7d0b8ae22b4b84e589117b7364122c2805373f628f9"),
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
           fromHex("82cac4bf6f4c2b41fbcc0e0984e9d8b76d7662f8e1789cdfbd85682acc55577a"),
        },
        {
           fromHex("cc"),
           fromHex("f71289cd66d22657801ae25f5db946f6d2cc9884d70080d84282a5ef083cb70f"),
        },
        {
           fromHex("41fb"),
           fromHex("8f7a69e19a65f1148d02de5e2bf784974e6cf3335cd2b2d07bc3b88463d2be3c"),
        },
        {
           fromHex("1F877C"),
           fromHex("afc964b8ec55fc0bf5880008e484c85cc08f85f10bc9dea42249412c376eba0d"),
        },
        {
           fromHex("c1ecfdfc"),
           fromHex("b4234843e79fc032eff83c144767d6c1cb37bbaba601563b0d972d2f7881e759"),
        },
        {
           fromHex("1f66ab4185ed9b6375"),
           fromHex("a55e732f5713bac92c822b0d80a236d6d1e212fa192fd1f7003c5863c82bf412"),
        },
        {
           fromHex("a746273228122f381c3b46e4f1"),
           fromHex("8337c89a8dda0743dd49ad971f9df3203d8e0c6e93afc1403a6406b55e52f9af"),
        },
        {
           fromHex("d8dc8fdefbdce9d44e4cbafe78447bae3b5436102a"),
           fromHex("92080ed5688d3e9092a843e95e6ecb3bdbe53af87169d2db6a8a77e5e87d3ef6"),
        },
        {
           fromHex("aecbb02759f7433d6fcb06963c74061cd83b5b3ffa6f13c6"),
           fromHex("d61df1b154af4f5e7a3e33e6fc1f3b2dbf9ddb2c253ee5f75b1c1182f88d1058"),
        },
        {
           fromHex("512a6d292e67ecb2fe486bfe92660953a75484ff4c4f2eca2b0af0edcdd4339c6b2ee4e542"),
           fromHex("f709b8830904f2e8b3a964275ea0010422f34b3066928a56ced0381f4839c9b7"),
        },
        {
           fromHex("f57c64006d9ea761892e145c99df1b24640883da79d9ed5262859dcda8c3c32e05b03d984f1ab4a230242ab6b78d368dc5aaa1e6d3498d53371e84b0c1d4ba"),
           fromHex("b24c29300d4ebf8d692ff12085d93ba401b707b7ba53903de3517e20bafb7c98"),
        },
        {
           fromHex("758ea3fea738973db0b8be7e599bbef4519373d6e6dcd7195ea885fc991d896762992759c2a09002912fb08e0cb5b76f49162aeb8cf87b172cf3ad190253df612f77b1f0c532e3b5fc99c2d31f8f65011695a087a35ee4eee5e334c369d8ee5d29f695815d866da99df3f79403"),
           fromHex("714a6bf6f7a22f3ffebbd55dd7ea7efa2ce79a9faaff955deaaf3baec2d32798"),
        },
        {
           fromHex("2b6db7ced8665ebe9deb080295218426bdaa7c6da9add2088932cdffbaa1c14129bccdd70f369efb149285858d2b1d155d14de2fdb680a8b027284055182a0cae275234cc9c92863c1b4ab66f304cf0621cd54565f5bff461d3b461bd40df28198e3732501b4860eadd503d26d6e69338f4e0456e9e9baf3d827ae685fb1d817"),
           fromHex("43d5b6bf86f2cbec3d6eab293d20250a61c5a03ab946fcd2ca078b8ff6e4b60c"),
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
           fromHex("616263"),
           fromHex("411e84c41bd59e1376fc905fe96d2ef58fd59970abba02ca53a7a662f9e6cedb4e7e43bd63717215cd86ea20282f2b36"),
        },
        {
           fromHex(""),
           fromHex("1db2643911391720e712a8c24457ee456fabfd555f479156e4b24278d6f6bcfb03fab1ec2a2626b79f2880216bc29b29"),
        },
        {
           fromHex("cc"),
           fromHex("45d80a7a71b2437242bf0f856a02d4520ffdc3a40c7494bfad67d696f4931a8664605a92b403511208d8fbe0bafde746"),
        },
        {
           fromHex("41fb"),
           fromHex("58ff1cf0dc7af1f52766410f56bfe6cef7d0bd41285cca5991990d654eabab89eb728e3272e7551a66c609c56d6a0b8a"),
        },
        {
           fromHex("1F877C"),
           fromHex("cc0e007927bb15ed4394285367a5b20c121c3a3d542611c90d6f66cdae3fac843a8ac4194852297f73ba790d73324082"),
        },
        {
           fromHex("c1ecfdfc"),
           fromHex("cf9e14dacb9a76ec54a6a197adde81bf29dac7c10fb7239a594afc953c9e101ef65f0ee7dcf05782de25920d579be99d"),
        },
        {
           fromHex("75683dcb556140c522543bb6e9098b21a21e"),
           fromHex("e41d6837cd4b8ad201aed214cb809c931bc930ec992ca1c38d780aaa6b483ecfda5e932c5ddefec9565f95d452561152"),
        },
        {
           fromHex("a05404df5dbb57697e2c16fa29defac8ab3560d6126fa0"),
           fromHex("12adba68d6e3504ef2c839f0d44cafe0a5948c911114fa6afbbd7063ccd2fb26839b51a09829ae33abda1f0fff7e6b70"),
        },
        {
           fromHex("03a18688b10cc0edf83adf0a84808a9718383c4070c6c4f295098699ac2c"),
           fromHex("825776408483e63ba5712e24f211dd5aeffce9f9a85bbcb4059077b63f7b0cb636b99c1b18d5983971afaac76251a753"),
        },
        {
           fromHex("337023370a48b62ee43546f17c4ef2bf8d7ecd1d49f90bab604b839c2e6e5bd21540d29ba27ab8e309a4b7"),
           fromHex("2c79d612c0f115c56ab6f61160ff59d68787fed2e953e22f48803d940693529629887334749547bbb8f8fface35f3878"),
        },
        {
           fromHex("7adc0b6693e61c269f278e6944a5a2d8300981e40022f839ac644387bfac9086650085c2cdc585fea47b9d2e52d65a2b29a7dc370401ef5d60dd0d21f9e2b90fae919319b14b8c5565b0423cefb827d5f1203302a9d01523498a4db10374"),
           fromHex("47da8e570bafd163b4a22e5f2e067b2617c67793aae101335184892e3b7e0ba0676eaa37c2f81af6034e03fc50366a3b"),
        },
        {
           fromHex("f13c972c52cb3cc4a4df28c97f2df11ce089b815466be88863243eb318c2adb1a417cb1041308598541720197b9b1cb5ba2318bd5574d1df2174af14884149ba9b2f446d609df240ce335599957b8ec80876d9a085ae084907bc5961b20bf5f6ca58d5dab38adb"),
           fromHex("9c4b2a9292c1622a05dccf88a163ea63c88d2d6654e37888519da6ed0ffb6fdaa1712524fe500723d556a7285d86013f"),
        },
        {
           fromHex("a62fc595b4096e6336e53fcdfc8d1cc175d71dac9d750a6133d23199eaac288207944cea6b16d27631915b4619f743da2e30a0c00bbdb1bbb35ab852ef3b9aec6b0a8dcc6e9e1abaa3ad62ac0a6c5de765de2c3711b769e3fde44a74016fff82ac46fa8f1797d3b2a726b696e3dea5530439acee3a45c2a51bc32dd055650b"),
           fromHex("a02a1bfb93c2a2b85add236038da97554d127673f57d47e4a420463e54e3199707c4dbc8bb9beb7fb686d89f3a616a6d"),
        },
        {
           fromHex("6a01830af3889a25183244decb508bd01253d5b508ab490d3124afbf42626b2e70894e9b562b288d0a2450cfacf14a0ddae5c04716e5a0082c33981f6037d23d5e045ee1ef2283fb8b6378a914c5d9441627a722c282ff452e25a7ea608d69cee4393a0725d17963d0342684f255496d8a18c2961145315130549311fc07f0312fb78e6077334f87eaa873bee8aa95698996eb21375eb2b4ef53c14401207deb4568398e5dd9a7cf97e8c9663e23334b46912f8344c19efcf8c2ba6f04325f1a27e062b62a58d0766fc6db4d2c6a1928604b0175d872d16b7908ebc041761187cc785526c2a3873feac3a642bb39f5351550af9770c328af7b"),
           fromHex("36c691579bfb984937b27f67e3d5bb807d8bad56d287107a013b3639f9ff26f8830cd69316e6e0d3f19153472af0919b"),
        },
        {
           fromHex("3a3a819c48efde2ad914fbf00e18ab6bc4f14513ab27d0c178a188b61431e7f5623cb66b23346775d386b50e982c493adbbfc54b9a3cd383382336a1a0b2150a15358f336d03ae18f666c7573d55c4fd181c29e6ccfde63ea35f0adf5885cfc0a3d84a2b2e4dd24496db789e663170cef74798aa1bbcd4574ea0bba40489d764b2f83aadc66b148b4a0cd95246c127d5871c4f11418690a5ddf01246a0c80a43c70088b6183639dcfda4125bd113a8f49ee23ed306faac576c3fb0c1e256671d817fc2534a52f5b439f72e424de376f4c565cca82307dd9ef76da5b7c4eb7e085172e328807c02d011ffbf33785378d79dc266f6a5be6bb0e4a92eceebaeb1"),
           fromHex("7aa9e0d9af6aaae485c0773934d710b8e7161465aecdbb5340a9247605651e1cb4d9ae0ffd368091d2c59796a10b6c1f"),
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
           fromHex("6a725655c42bc8a2a20549dd5a233a6a2beb01616975851fd122504e604b46af7d96697d0b6333db1d1709d6df328d2a6c786551b0cce2255e8c7332b4819c0e"),
        },
        {
           fromHex("cc"),
           fromHex("0309cd7a44e6022671e84c43cdb92f613931d1c6b71467c039034b1263c2bf92203e27604bc53fcea9c2df3b10862c9b6fb6e8c617754ef49a2b80f51c74acd3"),
        },
        {
           fromHex("41fb"),
           fromHex("1fd4ac6551d39ef27b5f1f886d7a3a72ec60e0ae2966649c3701952f29b2dbf858ab6e18101d038bbf019299c7fe5f62a4bc3973e089ef929aaf25b9a8bb7d39"),
        },
        {
           fromHex("1F877C"),
           fromHex("8987d458cf27d4c1b1ddd115fe5c15a67af431561812b1d2028c3af0a52fb8f7334205cbe003ceab1446261550870eea6921c2315d750f9c49ad7877590a9bde"),
        },
        {
           fromHex("c1ecfdfc"),
           fromHex("5a443348f0b3330cba5060b16ef21d5597ecdd597603b3e86999099c5595be38f726d10090472daf5ea77315b6ba62b2507a7c08a1b6786dcb30148dd1517882"),
        },
        {
           fromHex("1f66ab4185ed9b6375"),
           fromHex("e072e9d923e334a5c0e129e46d4ee6e5fa2a1494f6cfc4d1498b80470a0b920f2b2d56575a771d8271205d973f23a8da0fcd3de5e569269b50b3bd823dc8d955"),
        },
        {
           fromHex("a746273228122f381c3b46e4f1"),
           fromHex("99f9c27a26186098430839356fd651a6c203e39adc06efb3a6c35c3265fe37f7cd3b4ee520218d820f3189b44341eaa6cd753a472a8fdfd7386cb5e3a1d9dbb7"),
        },
        {
           fromHex("512a6d292e67ecb2fe486bfe92660953a75484ff4c4f2eca2b0af0edcdd4339c6b2ee4e542"),
           fromHex("41d2d44c32a90b30ace1c7f6e4af5c3dc3abdb1ac7365262c56cb1ae6db6b5d42ad2bcfd9228d9dffd5664756e326e9e88d053fd3a3d252211463b7171f5cb5c"),
        },
        {
           fromHex("c8f2b693bd0d75ef99caebdc22adf4088a95a3542f637203e283bbc3268780e787d68d28cc3897452f6a22aa8573ccebf245972a"),
           fromHex("89c23f143c74b2a3ea4e1b52765b01cd38725dd432813816cfedcdef7090c01d9964daf8f0eec99a23b20f1502cc8cb41f77cd35d1e1b1ccffd96821525705e2"),
        },
        {
           fromHex("f57c64006d9ea761892e145c99df1b24640883da79d9ed5262859dcda8c3c32e05b03d984f1ab4a230242ab6b78d368dc5aaa1e6d3498d53371e84b0c1d4ba"),
           fromHex("a94a8bbaaf30da2d1bc52efce0541b8bd109663ad73830261b6179ca31d08cc5abf512ce3de1118de1230b31afd5a01b5d6a49b370beee77a3988f9cbd32618c"),
        },
        {
           fromHex("758ea3fea738973db0b8be7e599bbef4519373d6e6dcd7195ea885fc991d896762992759c2a09002912fb08e0cb5b76f49162aeb8cf87b172cf3ad190253df612f77b1f0c532e3b5fc99c2d31f8f65011695a087a35ee4eee5e334c369d8ee5d29f695815d866da99df3f79403"),
           fromHex("ff96deeadd3c3668f9c9fcf23eabb6c08a908d89b997ed4005fdb4addfdbc165d47cbdc2a9a064d95beddedfe1f5ae0d7a05eed7d1b30d3dc1d3ac8850425575"),
        },
        {
           fromHex("90b28a6aa1fe533915bcb8e81ed6cacdc10962b7ff82474f845eeb86977600cf70b07ba8e3796141ee340e3fce842a38a50afbe90301a3bdcc591f2e7d9de53e495525560b908c892439990a2ca2679c5539ffdf636777ad9c1cdef809cda9e8dcdb451abb9e9c17efa4379abd24b182bd981cafc792640a183b61694301d04c5b3eaad694a6bd4cc06ef5da8fa23b4fa2a64559c5a68397930079d250c51bcf00e2b16a6c49171433b0aadfd80231276560b80458dd77089b7a1bbcc9e7e4b9f881eacd6c92c4318348a13f4914eb27115a1cfc5d16d7fd94954c3532efaca2cab025103b2d02c6fd71da3a77f417d7932685888a"),
           fromHex("2a1f1c7fafbe676d2a7bc67bd80c9387f493643e2395852af8a6846a5ddc191cb17fcaa17bb82266fea390b3e45ded4a15408a29df5ae390a1bc945d5d97c1c7"),
        },
        {
           fromHex("a6fe30dcfcda1a329e82ab50e32b5f50eb25c873c5d2305860a835aecee6264aa36a47429922c4b8b3afd00da16035830edb897831c4e7b00f2c23fc0b15fdc30d85fb70c30c431c638e1a25b51caf1d7e8b050b7f89bfb30f59f0f20fecff3d639abc4255b3868fc45dd81e47eb12ab40f2aac735df5d1dc1ad997cefc4d836b854cee9ac02900036f3867fe0d84afff37bde3308c2206c62c4743375094108877c73b87b2546fe05ea137bedfc06a2796274099a0d554da8f7d7223a48cbf31b7decaa1ebc8b145763e3673168c1b1b715c1cd99ecd3ddb238b06049885ecad9347c2436dff32c771f34a38587a44a82c5d3d137a03caa27e66c8ff6"),
           fromHex("c4966858db87dfc7dae95cb51a8b19dd481f75b3ff554b18458c0f25a285f6135d73ff6f1b498b957e8481f16612d8b52e187bde76b3a8d1a6324a3899f056d8"),
        },
        {
           fromHex("3a3a819c48efde2ad914fbf00e18ab6bc4f14513ab27d0c178a188b61431e7f5623cb66b23346775d386b50e982c493adbbfc54b9a3cd383382336a1a0b2150a15358f336d03ae18f666c7573d55c4fd181c29e6ccfde63ea35f0adf5885cfc0a3d84a2b2e4dd24496db789e663170cef74798aa1bbcd4574ea0bba40489d764b2f83aadc66b148b4a0cd95246c127d5871c4f11418690a5ddf01246a0c80a43c70088b6183639dcfda4125bd113a8f49ee23ed306faac576c3fb0c1e256671d817fc2534a52f5b439f72e424de376f4c565cca82307dd9ef76da5b7c4eb7e085172e328807c02d011ffbf33785378d79dc266f6a5be6bb0e4a92eceebaeb1"),
           fromHex("59d674c09e78b40fadd298ee83fb2cb4468ca96afaa75ce3f4b451c0d353c28a632a0de753800d49fdbd6ea190025c5340036910bdbacc91c2d988b6fb2f8789"),
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
