package blake512

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

type testData struct {
    msg []byte
    md []byte
}

func Test_Hash384_Check(t *testing.T) {
   tests := []testData{
        {
           fromHex(""),
           fromHex("c6cbd89c926ab525c242e6621f2f5fa73aa4afe3d9e24aed727faaadd6af38b620bdb623dd2b4788b1c8086984af8706"),
        },
        {
           fromHex("cc"),
           fromHex("a77e65c0c03ecb831dbcdd50a3c2bce300d55eac002a9c197095518d8514c0b578e3ecb7415291f99ede91d49197dd05"),
        },
        {
           fromHex("1f877c"),
           fromHex("d67cfa1b09c8c050094ea018bb5ecd3ce0c02835325467a8fa79701f0ad6bbd4a34947bbaa2fc5f9379985ccd6a1dc0e"),
        },
        {
           fromHex("c6f50bb74e29"),
           fromHex("5ddb50068ca430bffae7e5a8bbcb2c59171743cce027c0ea937fa2b511848192af2aca98ead30b0850b4d2d1542decdb"),
        },
        {
           fromHex("eed7422227613b6f53c9"),
           fromHex("6659fa5b2c4874d82ae964df895d44fbd9029ea07adea8acfd57c747ab8c6df120b5e485e457692591e3d5acbbb78133"),
        },
        {
           fromHex("3c5871cd619c69a63b540eb5a625"),
           fromHex("0aa19c3d90c3c5436a873a51be500b64da9b8e987015c92927e94c461796966378bbfaf6d6a123c8dd197d20d56b2620"),
        },
        {
           fromHex("c8f2b693bd0d75ef99caebdc22adf4088a95a3542f637203e283bbc3268780e787d68d28cc3897452f6a22aa8573ccebf245972a"),
           fromHex("6b2d02bdd362d73ee156249e00b3c913f3f2f723e6d18f96698248a3b6318081dbb4484e03a5b3b325239f3be4d16efc"),
        },
        {
           fromHex("90078999fd3c35b8afbf4066cbde335891365f0fc75c1286cdd88fa51fab94f9b8def7c9ac582a5dbcd95817afb7d1b48f63704e19c2baa4df347f48d4a6d603013c23f1e9611d595ebac37c"),
           fromHex("7d81a43a11012b37244df3193c580064d39a8a83870f1d0dfcecd5d2f6d59bcb1059053b0039dc3598b1bad71a7da703"),
        },
        {
           fromHex("3c9b46450c0f2cae8e3823f8bdb4277f31b744ce2eb17054bddc6dff36af7f49fb8a2320cc3bdf8e0a2ea29ad3a55de1165d219adeddb5175253e2d1489e9b6fdd02e2c3d3a4b54d60e3a47334c37913c5695378a669e9b72dec32af5434f93f46176ebf044c4784467c700470d0c0b40c8a088c815816"),
           fromHex("d89257ed2483a34e554f7a35accabfa7214abe9bd6ba28ec17b22c637469a1549bf87e72b899ae127af0c83e14ebd9cb"),
        },
        {
           fromHex("83599d93f5561e821bd01a472386bc2ff4efbd4aed60d5821e84aae74d8071029810f5e286f8f17651cd27da07b1eb4382f754cd1c95268783ad09220f5502840370d494beb17124220f6afce91ec8a0f55231f9652433e5ce3489b727716cf4aeba7dcda20cd29aa9a859201253f948dd94395aba9e3852bd1d60dda7ae5dc045b283da006e1cbad83cc13292a315db5553305c628dd091146597"),
           fromHex("6091ecdd39737dc6c76763cefe46087d6d75e1ec6d92fcd51b2ce548f43ab53f421ed3bc5d0377d6d0347735d5406f0e"),
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
           fromHex("a8cfbbd73726062df0c6864dda65defe58ef0cc52a5625090fa17601e1eecd1b628e94f396ae402a00acc9eab77b4d4c2e852aaaa25a636d80af3fc7913ef5b8"),
        },
        {
           fromHex("cc"),
           fromHex("4f0ef594f20172d23504873f596984c64c1583c7b2abb8d8786aa2aeeae1c46c744b61893d661b0733b76d1fe19257dd68e0ef05422ca25d058dfe6c33d68709"),
        },
        {
           fromHex("1f877c"),
           fromHex("b1211367fd8a886674f74d92716e7585f9b6e933edc5ee7f974facdccc481cfa42a0532375b94f2c0dd73d6189a815c2bafb5686d784be81fbb447b0f291272b"),
        },
        {
           fromHex("c6f50bb74e29"),
           fromHex("b6e8a7380df1f007d7c271e7255bbca7714f25029ac1fd6fe92ef74cbcd9e99c112f8ae1a45ccb566ce19d9678a122c612beff5f8eeeee3f3f402fd2781182d4"),
        },
        {
           fromHex("eed7422227613b6f53c9"),
           fromHex("c5633a1b9e45cef38647603cbd9710e1aca4f2fb84f8d56a0d729fd6d480ef05f8a46f1dc0e771ec114aea2f9ad534b70bf03046118a5f2fbdd371442d9d8895"),
        },
        {
           fromHex("47f5697ac8c31409c0868827347a613a3562041c633cf1f1f86865a576e02835ed2c2492"),
           fromHex("7ec5e1adebe2e3be5b7cf5ac81d04a2362b8f2aaff913f143d209040f2083a9d064f7eeaf4c12a54fd26f3b24927788d874bcd1d6db4ae9caaf129fcb9239364"),
        },
        {
           fromHex("0dc45181337ca32a8222fe7a3bf42fc9f89744259cff653504d6051fe84b1a7ffd20cb47d4696ce212a686bb9be9a8ab1c697b6d6a33"),
           fromHex("95932e3f12283fff258cb03d6279bf6937ffc3bf2d4f3baf90f858035863e910db1f1051294817477f7ac6d66eeea0cd141e8c9e822bfb0073afa6bbb41ee907"),
        },
        {
           fromHex("6348f229e7b1df3b770c77544e5166e081850fa1c6c88169db74c76e42eb983facb276ad6a0d1fa7b50d3e3b6fcd799ec97470920a7abed47d288ff883e24ca21c7f8016b93bb9b9e078bdb9703d2b781b616e"),
           fromHex("ad25850a967c6889ac6e62adf5b8fe6a2ba391817fc7221c3b77a15a5e4f04c12f956179f3186710ab1df6dd808351dc7c55affa3f5068548f2117335dc7c82f"),
        },
        {
           fromHex("fd19e01a83eb6ec810b94582cb8fbfa2fcb992b53684fb748d2264f020d3b960cb1d6b8c348c2b54a9fcea72330c2aaa9a24ecdb00c436abc702361a82bb8828b85369b8c72ece0082fe06557163899c2a0efa466c33c04343a839417057399a63a3929be1ee4805d6ce3e5d0d0967fe9004696a5663f4cac9179006a2ceb75542d75d68"),
           fromHex("8b5b19af484b48e8537bb0e82667f45f0ebfad4e8a4024ba6c080fccb8de573891ecc908b96c9b60c9225eba12e2e181f874ea91db03b106696d467420451d91"),
        },
    }

    h := New()

    for i, test := range tests {
        h.Reset()
        h.Write(test.msg)
        sum := h.Sum(nil)

        if !bytes.Equal(sum, test.md) {
            t.Errorf("[%d] New fail, got %x, want %x", i, sum, test.md)
        }

        // =====

        sum2 := Sum(test.msg)

        if !bytes.Equal(sum2[:], test.md) {
            t.Errorf("[%d] Sum fail, got %x, want %x", i, sum2, test.md)
        }
    }
}

var vectors512salt = []struct{ out, in, salt string }{
    {"c20692d6c33b8c57569db0c82a97ace4c0813fdbb357fd9474f6aad35f4736fd3415a5051dc195f8b89de95aa82cb1a1253a4665ea8fffc0e829005e9559854c",
        "",
        "12345678901234561234567890123456"},
    {"7c9972b6d7a104b9220ac06a17d1408af423d3207f216d9ba7159077543ca14780e818d422e30d49be841ad11bd1035d3cf209c48527cd39f272f36924c1f3ae",
        "It's so salty out there!",
        "SALTsaltSaltSALTSALTsaltSaltSALT"},
}

func Test_Hash512_Salt(t *testing.T) {
    for i, v := range vectors512salt {
        h := NewWithSalt([]byte(v.salt))
        h.Write([]byte(v.in))
        res := fmt.Sprintf("%x", h.Sum(nil))
        if res != v.out {
            t.Errorf("%d: expected %q, got %q", i, v.out, res)
        }
    }

    // Check that passing bad salt length panics.
    defer func() {
        if err := recover(); err == nil {
            t.Errorf("expected panic for bad salt length")
        }
    }()

    NewWithSalt([]byte{1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8})
}

var vectors384salt = []struct{ out, in, salt string }{
    {"e8d905ff01866ba45f15a3c1046cb4f97615463c669cf9dcc891ea6a00064739d80268f0af5d0320b1a73544d7a4d4e1",
        "",
        "12345678901234561234567890123456"},
    {"221be11f30249fe556d853bd8920b082c7c4dee5b056a9fd5d64f2a0de9fdc2393058e1e111a63fc73e784d6814a85ad",
        "It's so salty out there!",
        "SALTsaltSaltSALTSALTsaltSaltSALT"},
}

func Test_Hash384_Salt(t *testing.T) {
    for i, v := range vectors384salt {
        h := New384WithSalt([]byte(v.salt))
        h.Write([]byte(v.in))
        res := fmt.Sprintf("%x", h.Sum(nil))
        if res != v.out {
            t.Errorf("%d: expected %q, got %q", i, v.out, res)
        }
    }

    // Check that passing bad salt length panics.
    defer func() {
        if err := recover(); err == nil {
            t.Errorf("expected panic for bad salt length")
        }
    }()

    New384WithSalt([]byte{1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8})
}

