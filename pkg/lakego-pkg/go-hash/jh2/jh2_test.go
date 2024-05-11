package jh2

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
           fromHex("2c99df889b019309051c60fecc2bd285a774940e43175b76b2626630"),
        },
        {
           fromHex("cc"),
           fromHex("f79c791ac9b9d80ec934312d6b26748481198e3ca78ebb01b2c9ca51"),
        },
        {
           fromHex("41fb"),
           fromHex("bf3ea0f2bc680aaf4aba50167fd8cd661e8cc63df10641ee093dd2ae"),
        },
        {
           fromHex("1F877C"),
           fromHex("385d05cface35fdb84dc180d766330afdce0f8f0c751f8f245192057"),
        },
        {
           fromHex("c1ecfdfc"),
           fromHex("1c9aa60c55022e1a416448980ca6ca9bf8d2fac5324570846aa80c02"),
        },
        {
           fromHex("1f66ab4185ed9b6375"),
           fromHex("a5b30d24b155dd0c84e3efd65ad9afa3f277346a538365a44ab102b4"),
        },
        {
           fromHex("a746273228122f381c3b46e4f1"),
           fromHex("6025cd7cc19e2e22e0260f304703cd3bae970b73a00bb7c4ac928e93"),
        },
        {
           fromHex("d8dc8fdefbdce9d44e4cbafe78447bae3b5436102a"),
           fromHex("daa67d12de6a1642f69940c790fd5a9df6e957f624129cf01e161d5b"),
        },
        {
           fromHex("337023370a48b62ee43546f17c4ef2bf8d7ecd1d49f90bab604b839c2e6e5bd21540d29ba27ab8e309a4b7"),
           fromHex("4d4cc0ed72765eb28fbd5cb8d1309079c36b2fd076fa43d79e71b2ea"),
        },
        {
           fromHex("d8faba1f5194c4db5f176fabfff856924ef627a37cd08cf55608bba8f1e324d7c7f157298eabc4dce7d89ce5162499f9"),
           fromHex("d7039060277847781c13e118e636ae15ccf7302576787bf28790da79"),
        },
        {
           fromHex("de286ba4206e8b005714f80fb1cdfaebde91d29f84603e4a3ebc04686f99a46c9e880b96c574825582e8812a26e5a857ffc6579f63742f"),
           fromHex("b1e2d08e14114f8b393a15a7a07bd77b902c24d18f1cc5a029e446cf"),
        },
        {
           fromHex("f31e8b4f9e0621d531d22a380be5d9abd56faec53cbd39b1fab230ea67184440e5b1d15457bd25f56204fa917fa48e669016cb48c1ffc1e1e45274b3b47379e00a43843cf8601a5551411ec12503e5aac43d8676a1b2297ec7a0800dbfee04292e937f21c005f17411473041"),
           fromHex("aa587f31efbf6b0698529e03d948bcbfc75f1f86ea2d8eb0f4a0a8be"),
        },
        {
           fromHex("2be9bf526c9d5a75d565dd11ef63b979d068659c7f026c08bea4af161d85a462d80e45040e91f4165c074c43ac661380311a8cbed59cc8e4c4518e80cd2c78ab1cabf66bff83eab3a80148550307310950d034a6286c93a1ece8929e6385c5e3bb6ea8a7c0fb6d6332e320e71cc4eb462a2a62e2bfe08f0ccad93e61bedb5dd0b786a728ab666f07e0576d189c92bf9fb20dca49ac2d3956d47385e2"),
           fromHex("8a0efe7a298fa89418ccbca5aef00f2da028ef53688ce50e83f2ed2b"),
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
           fromHex("46e64619c18bb0a92a5e87185a47eef83ca747b8fcc8e1412921357e326df434"),
        },
        {
           fromHex("cc"),
           fromHex("7b1191f13a2667830142541bfc5918543d2a434c7692e70c3e5e9bbdddb7f581"),
        },
        {
           fromHex("41fb"),
           fromHex("ef3eeeae2d2457db084f2a933647d9e77a476eb4e58569a18ad4ba55754f9034"),
        },
        {
           fromHex("1F877C"),
           fromHex("54418f1e9b472e53e2fcc3bb10d1bd13f63b3c416589401389e51896fd6766ad"),
        },
        {
           fromHex("c1ecfdfc"),
           fromHex("8d7e972ca6eeca9b09b829e4d627c72572b6b8555c7aa081e66167e9e4a10f11"),
        },
        {
           fromHex("1f66ab4185ed9b6375"),
           fromHex("443d065a47f394a2bea55f2018343382159c734ca0badad7bf5400a7f7ca151c"),
        },
        {
           fromHex("a746273228122f381c3b46e4f1"),
           fromHex("e9a78bdfbe479d6502e4e35af4d876d42acdc5b647371dcc3f24119314cc4395"),
        },
        {
           fromHex("d8dc8fdefbdce9d44e4cbafe78447bae3b5436102a"),
           fromHex("2bebb287410e17fd292c684673731304da159c67ef3476437d3be133fd274180"),
        },
        {
           fromHex("aecbb02759f7433d6fcb06963c74061cd83b5b3ffa6f13c6"),
           fromHex("dfc2db3010b7efd4d8fc6ff7e97cb1f467a680989813ffd15630601eede1b439"),
        },
        {
           fromHex("512a6d292e67ecb2fe486bfe92660953a75484ff4c4f2eca2b0af0edcdd4339c6b2ee4e542"),
           fromHex("1ef40d478b8f36eb7e4db89ba5b38146061bdd8dbd1884a5a7d408497fbe9d70"),
        },
        {
           fromHex("f5961dfd2b1ffffda4ffbf30560c165bfedab8ce0be525845deb8dc61004b7db38467205f5dcfb34a2acfe96c0"),
           fromHex("d9757caaa51fd67bf7424f3ffbca075e1ca4c4db1f153ddcd4236885660bc85d"),
        },
        {
           fromHex("12d9394888305ac96e65f2bf0e1b18c29c90fe9d714dd59f651f52b88b3008c588435548066ea2fc4c101118c91f32556224a540de6efddbca296ef1fb00341f5b01fecfc146bdb251b3bdad556cd2"),
           fromHex("0bc6f4eb2e00750d5bd4849c9cb28c1f87a31297b8521d895e9a2cec999223de"),
        },
        {
           fromHex("64ec021c9585e01ffe6d31bb50d44c79b6993d72678163db474947a053674619d158016adb243f5c8d50aa92f50ab36e579ff2dabb780a2b529370daa299207cfbcdd3a9a25006d19c4f1fe33e4b1eaec315d8c6ee1e730623fd1941875b924eb57d6d0c2edc4e78d6"),
           fromHex("5a9bd4bc4556bdd4553b117b5d66a0e3df0a79d402502bbfda1c6e65ee277ab8"),
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
           fromHex("2fe5f71b1b3290d3c017fb3c1a4d02a5cbeb03a0476481e25082434a881994b0ff99e078d2c16b105ad069b569315328"),
        },
        {
           fromHex("cc"),
           fromHex("ccfa3732089cb4d49af04daa865cb2376bfa264e527b5eb8486cd09b3fb9a8019140a1ca9df7539efbb3a3118d8e0584"),
        },
        {
           fromHex("41fb"),
           fromHex("5cd8bead6785a56e184f388c2edeae5502ff59b82d214f472c378ac33e451cc16bc91feeb7b7702718431e7c8550be85"),
        },
        {
           fromHex("1F877C"),
           fromHex("05d72081179c4f5e839c88cc991ed7e8625bcc5f1a61a23588e57ea7656dc372fadfacb0626e0d48fd819de3ee96c3ea"),
        },
        {
           fromHex("c1ecfdfc"),
           fromHex("ab94a321da66a0c1385fde960c1a9196a5f3e2d0c68c0778a66f2a663498227c067ba167f99b56cad5e0234723c3ce5e"),
        },
        {
           fromHex("eed7422227613b6f53c9"),
           fromHex("3282d7224f2d3f11bd0ccd8a8b08ec2a1b7227c897656fcdae85770cfca01d9ad890d7e40f6824fbce98af5e99658d80"),
        },
        {
           fromHex("e26193989d06568fe688e75540aea06747d9f851"),
           fromHex("57a7c78bdad234411f4d987202ec68528d6981764fa3540f89b5dea1248b45ab61602d7857e77d78a0882fb932876866"),
        },
        {
           fromHex("47f5697ac8c31409c0868827347a613a3562041c633cf1f1f86865a576e02835ed2c2492"),
           fromHex("afa1cfbe9021b76217ce008d3ba7d00a5049c37a56143f310b30ef1e8ddb15b6d07be3f7727a4d4c655a377924d9a7ee"),
        },
        {
           fromHex("ec0f99711016c6a2a07ad80d16427506ce6f441059fd269442baaa28c6ca037b22eeac49d5d894c0bf66219f2c08e9d0e8ab21de52"),
           fromHex("913df5a45987d9acafafb8f2d61335beb3550aec4cd036c36c60747fcab77ce4838f83fb8b7a9c9507dce0fd56dee6f0"),
        },
        {
           fromHex("1eed9cba179a009ec2ec5508773dd305477ca117e6d569e66b5f64c6bc64801ce25a8424ce4a26d575b8a6fb10ead3fd1992edddeec2ebe7150dc98f63adc3237ef57b91397aa8a7"),
           fromHex("12e72160d3d6f18b6e924b87291cb4f871eac780cc8cef03eed6c8ac71e56748240b07b336594605adc1c7f73b3d2771"),
        },
        {
           fromHex("0d58ac665fa84342e60cefee31b1a4eacdb092f122dfc68309077aed1f3e528f578859ee9e4cefb4a728e946324927b675cd4f4ac84f64db3dacfe850c1dd18744c74ceccd9fe4dc214085108f404eab6d8f452b5442a47d"),
           fromHex("7695fde91be87cf67c4df7827206bb9958efda0e77077c240939c654e57273df5baa2529f393db6d56ed5c3a6fa1e756"),
        },
        {
           fromHex("e35780eb9799ad4c77535d4ddb683cf33ef367715327cf4c4a58ed9cbdcdd486f669f80189d549a9364fa82a51a52654ec721bb3aab95dceb4a86a6afa93826db923517e928f33e3fba850d45660ef83b9876accafa2a9987a254b137c6e140a21691e1069413848"),
           fromHex("84d0a4847aa1683d5d84b9f24bf7065e5219ba24f4f5f34e59cfc076acc78cdf2ab063f73059a96146b38a52ed5cb42e"),
        },
        {
           fromHex("a62fc595b4096e6336e53fcdfc8d1cc175d71dac9d750a6133d23199eaac288207944cea6b16d27631915b4619f743da2e30a0c00bbdb1bbb35ab852ef3b9aec6b0a8dcc6e9e1abaa3ad62ac0a6c5de765de2c3711b769e3fde44a74016fff82ac46fa8f1797d3b2a726b696e3dea5530439acee3a45c2a51bc32dd055650b"),
           fromHex("37fbb48174496057ae36cfd2323f11aaea4aea2072e7692e23b435cefb9681c36d656b5ded64f44837661dc053de3454"),
        },
        {
           fromHex("2be9bf526c9d5a75d565dd11ef63b979d068659c7f026c08bea4af161d85a462d80e45040e91f4165c074c43ac661380311a8cbed59cc8e4c4518e80cd2c78ab1cabf66bff83eab3a80148550307310950d034a6286c93a1ece8929e6385c5e3bb6ea8a7c0fb6d6332e320e71cc4eb462a2a62e2bfe08f0ccad93e61bedb5dd0b786a728ab666f07e0576d189c92bf9fb20dca49ac2d3956d47385e2"),
           fromHex("db9838f316c3376437cbf81ee28108f5009eff5210add766dfad8326314e6e94a307b9abfea67519d68c941ca772c67e"),
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
           fromHex("90ecf2f76f9d2c8017d979ad5ab96b87d58fc8fc4b83060f3f900774faa2c8fabe69c5f4ff1ec2b61d6b316941cedee117fb04b1f4c5bc1b919ae841c50eec4f"),
        },
        {
           fromHex("cc"),
           fromHex("277c93806945992a7f10102f28471af2783fe32003b3f63320810e74f1bc233bf8669ab4b922db9ef13fcdcd4d31193b731eedde98fc87c129c04a4a1071f66f"),
        },
        {
           fromHex("41fb"),
           fromHex("5d80be996ba553a0c68fd539ff3859ced2d1fa627afadde83464a9f67cab6d66a32749b5228482a5f4a11332d62974547cb8ff90eba9ddf03272f873457563f0"),
        },
        {
           fromHex("1F877C"),
           fromHex("fd745541f728856a4fe34d53ec2b17a03c9b83c321ea69e708c354198821aafd98ef2062b566308374763a55aa0291f99a42d9cdbe36952ff58d00a689c2e6a9"),
        },
        {
           fromHex("c1ecfdfc"),
           fromHex("6027c238eb7b1d60b64b72ea11713c52db49fbe9582b6fe9383d0d6f9d120ed85710c2fce6ff2d5a173c5ae7766ed286c0896330df7f308638dab6fc915fc86b"),
        },
        {
           fromHex("1f66ab4185ed9b6375"),
           fromHex("c453e7b2de4ffdcc36459db3e0133a8e535b2dde7d94d13974e1122b1376278150921a70578fa9cd2eb532fde947ecd3c5947c579afedf955f37443e4fb85628"),
        },
        {
           fromHex("fa22874bcc068879e8ef11a69f0722"),
           fromHex("5820186ad15f14c1d74694617bc6ff2a8484b6c61abc224df9dbbb4fd022b3c47e621f0548f40443df8b38dd9c0634c310b7a289cd306f8a995c76880d75d4e2"),
        },
        {
           fromHex("84fb51b517df6c5accb5d022f8f28da09b10232d42320ffc32dbecc3835b29"),
           fromHex("f69d13907bb6453a5582457e4919de099b75e561de956230a34c5905f535232128e5044eee3537fe0945b871be842c91ddf47322d28dd0866426b8e26cf8df77"),
        },
        {
           fromHex("f5961dfd2b1ffffda4ffbf30560c165bfedab8ce0be525845deb8dc61004b7db38467205f5dcfb34a2acfe96c0"),
           fromHex("d0299a1c2731571d94c829e3644d3c048e74dec78ab8b44740e29cf60416500df15e03cad775181739979348b8f0cac95211e8b53bc128d184e4524d37e87199"),
        },
        {
           fromHex("94f7ca8e1a54234c6d53cc734bb3d3150c8ba8c5f880eab8d25fed13793a9701ebe320509286fd8e422e931d99c98da4df7e70ae447bab8cffd92382d8a77760a259fc4fbd72"),
           fromHex("9a80ea1d6aa97286dbe15a4ab5573d342992dd481218b2efff2a0f65f672a2f88483a75ef57595f1cc5888396f7ed0da51d1e52722dff84cc9501bbbd3ace1cc"),
        },
        {
           fromHex("68c8f8849b120e6e0c9969a5866af591a829b92f33cd9a4a3196957a148c49138e1e2f5c7619a6d5edebe995acd81ec8bb9c7b9cfca678d081ea9e25a75d39db04e18d475920ce828b94e72241f24db72546b352a0e4"),
           fromHex("efe5c37175d16148adf7feeabd63f8382c5d559fbeff07dccde749dd482bd05aa77a3a94e397c2170e743e19649671154ffe1a4ae43e439612425ad50b2df266"),
        },
        {
           fromHex("6efcbcaf451c129dbe00b9cef0c3749d3ee9d41c7bd500ade40cdc65dedbbbadb885a5b14b32a0c0d087825201e303288a733842fa7e599c0c514e078f05c821c7a4498b01c40032e9f1872a1c925fa17ce253e8935e4c3c71282242cb716b2089ccc1"),
           fromHex("460b59a081905db18eb4d49de6ca029c8382936fcb965c2080a61690a65c18ccbce879a3c2766444910d32c50935c1055deceb96a065ba7a37f7f4e31877bfa9"),
        },
        {
           fromHex("626f68c18a69a6590159a9c46be03d5965698f2dac3de779b878b3d9c421e0f21b955a16c715c1ec1e22ce3eb645b8b4f263f60660ea3028981eebd6c8c3a367285b691c8ee56944a7cd1217997e1d9c21620b536bdbd5de8925ff71dec6fbc06624ab6b21e329813de90d1e572dfb89a18120c3f606355d25"),
           fromHex("895f5a0c49ba94353d60407b3149a7a26117028cf45cc5f1ce36bac76affbea62dfc61e88e1a3ae3b5b8f550bd0b10b9c696f813abf7f7a0666ca3c4d60b6349"),
        },
        {
           fromHex("842cc583504539622d7f71e7e31863a2b885c56a0ba62db4c2a3f2fd12e79660dc7205ca29a0dc0a87db4dc62ee47a41db36b9ddb3293b9ac4baae7df5c6e7201e17f717ab56e12cad476be49608ad2d50309e7d48d2d8de4fa58ac3cfeafeee48c0a9eec88498e3efc51f54d300d828dddccb9d0b06dd021a29cf5cb5b2506915beb8a11998b8b886e0f9b7a80e97d91a7d01270f9a7717"),
           fromHex("b9a61027a96f3d7fed61812898802ef4b62c893d5e6ab6e22f8530b4d05b53acf1129d91557dc5d9554f431ebf738826dee5434b0913ec201d1d3a6bbc499d6c"),
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
