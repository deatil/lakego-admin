package zuc

import (
    "bytes"
    "testing"
    "math/rand"
    "encoding/hex"
)

func Test_Cipher(t *testing.T) {
    random := rand.New(rand.NewSource(99))
    max := 5000

    var encrypted [56]byte
    var decrypted [56]byte

    for i := 0; i < max; i++ {
        key := make([]byte, 16)
        random.Read(key)
        iv := make([]byte, 16)
        random.Read(key)
        value := make([]byte, 56)
        random.Read(value)

        cipher1, err := NewCipher(key, iv)
        if err != nil {
            t.Fatal(err.Error())
        }

        cipher1.XORKeyStream(encrypted[:], value)

        cipher2, err := NewCipher(key, iv)
        if err != nil {
            t.Fatal(err.Error())
        }

        cipher2.XORKeyStream(decrypted[:], encrypted[:])

        if !bytes.Equal(decrypted[:], value[:]) {
            t.Errorf("encryption/decryption failed: % 02x != % 02x\n", decrypted, value)
        }
    }
}

func Test_Cipher256(t *testing.T) {
    random := rand.New(rand.NewSource(99))
    max := 5000

    var encrypted [56]byte
    var decrypted [56]byte

    for i := 0; i < max; i++ {
        key := make([]byte, 32)
        random.Read(key)
        iv := make([]byte, 23)
        random.Read(key)
        value := make([]byte, 56)
        random.Read(value)

        cipher1, err := New256Cipher(key, iv)
        if err != nil {
            t.Fatal(err.Error())
        }

        cipher1.XORKeyStream(encrypted[:], value)

        cipher2, err := New256Cipher(key, iv)
        if err != nil {
            t.Fatal(err.Error())
        }

        cipher2.XORKeyStream(decrypted[:], encrypted[:])

        if !bytes.Equal(decrypted[:], value[:]) {
            t.Errorf("encryption/decryption failed: % 02x != % 02x\n", decrypted, value)
        }
    }
}

func Test_Cipher256WithMacbits(t *testing.T) {
    random := rand.New(rand.NewSource(99))
    max := 5000

    var encrypted [56]byte
    var decrypted [56]byte

    for i := 0; i < max; i++ {
        key := make([]byte, 32)
        random.Read(key)
        iv := make([]byte, 23)
        random.Read(key)
        value := make([]byte, 56)
        random.Read(value)

        cipher1, err := New256CipherWithMacbits(key, iv, 6)
        if err != nil {
            t.Fatal(err.Error())
        }

        cipher1.XORKeyStream(encrypted[:], value)

        cipher2, err := New256CipherWithMacbits(key, iv, 6)
        if err != nil {
            t.Fatal(err.Error())
        }

        cipher2.XORKeyStream(decrypted[:], encrypted[:])

        if !bytes.Equal(decrypted[:], value[:]) {
            t.Errorf("encryption/decryption failed: % 02x != % 02x\n", decrypted, value)
        }
    }
}

var zucEEATests = []struct {
    key       string
    count     uint32
    bearer    uint32
    direction uint32
    in        string
    out       string
}{
    {
        "173d14ba5003731d7a60049470f00a29",
        0x66035492,
        0xf,
        0,
        "6cf65340735552ab0c9752fa6f9025fe0bd675d9005875b2",
        "a6c85fc66afb8533aafc2518dfe784940ee1e4b030238cc8",
    },
    {
        "e5bd3ea0eb55ade866c6ac58bd54302a",
        0x56823,
        0x18,
        1,
        "14a8ef693d678507bbe7270a7f67ff5006c3525b9807e467c4e56000ba338f5d429559036751822246c80d3b38f07f4be2d8ff5805f5132229bde93bbbdcaf382bf1ee972fbf9977bada8945847a2a6c9ad34a667554e04d1f7fa2c33241bd8f01ba220d",
        "131d43e0dea1be5c5a1bfd971d852cbf712d7b4f57961fea3208afa8bca433f456ad09c7417e58bc69cf8866d1353f74865e80781d202dfb3ecff7fcbc3b190fe82a204ed0e350fc0f6f2613b2f2bca6df5a473a57a4a00d985ebad880d6f23864a07b01",
    },
    {
        "e13fed21b46e4e7ec31253b2bb17b3e0",
        0x2738cdaa,
        0x1a,
        0,
        "8d74e20d54894e06d3cb13cb3933065e8674be62adb1c72b3a646965ab63cb7b7854dfdc27e84929f49c64b872a490b13f957b64827e71f41fbd4269a42c97f824537027f86e9f4ad82d1df451690fdd98b6d03f3a0ebe3a312d6b840ba5a1820b2a2c9709c090d245ed267cf845ae41fa975d3333ac3009fd40eba9eb5b885714b768b697138baf21380eca49f644d48689e4215760b906739f0d2b3f091133ca15d981cbe401baf72d05ace05cccb2d297f4ef6a5f58d91246cfa77215b892ab441d5278452795ccb7f5d79057a1c4f77f80d46db2033cb79bedf8e60551ce10c667f62a97abafabbcd6772018df96a282ea737ce2cb331211f60d5354ce78f9918d9c206ca042c9b62387dd709604a50af16d8d35a8906be484cf2e74a9289940364353249b27b4c9ae29eddfc7da6418791a4e7baa0660fa64511f2d685cc3a5ff70e0d2b74292e3b8a0cd6b04b1c790b8ead2703708540dea2fc09c3da770f65449c84d817a4f551055e19ab85018a0028b71a144d96791e9a3577933504eee0060340c69d274e1bf9d805dcbcc1a6faa976800b6ff2b671dc463652fa8a33ee50974c1c21be01eabb2167430269d72ee511c9dde30797c9a25d86ce74f5b961be5fdfb6807814039e7137636bd1d7fa9e09efd2007505906a5ac45dfdeed7757bbee745749c29633350bee0ea6f409df458016",
        "94eaa4aa30a57137ddf09b97b25618a20a13e2f10fa5bf8161a879cc2ae797a6b4cf2d9df31debb9905ccfec97de605d21c61ab8531b7f3c9da5f03931f8a0642de48211f5f52ffea10f392a047669985da454a28f080961a6c2b62daa17f33cd60a4971f48d2d909394a55f48117ace43d708e6b77d3dc46d8bc017d4d1abb77b7428c042b06f2f99d8d07c9879d99600127a31985f1099bbd7d6c1519ede8f5eeb4a610b349ac01ea2350691756bd105c974a53eddb35d1d4100b012e522ab41f4c5f2fde76b59cb8b96d885cfe4080d1328a0d636cc0edc05800b76acca8fef672084d1f52a8bbd8e0993320992c7ffbae17c408441e0ee883fc8a8b05e22f5ff7f8d1b48c74c468c467a028f09fd7ce91109a570a2d5c4d5f4fa18c5dd3e4562afe24ef771901f59af645898acef088abae07e92d52eb2de55045bb1b7c4164ef2d7a6cac15eeb926d7ea2f08b66e1f759f3aee44614725aa3c7482b30844c143ff87b53f1e583c501257dddd096b81268daa303f17234c2333541f0bb8e190648c5807c866d7193228609adb948686f7de294a802cc38f7fe5208f5ea3196d0167b9bdd02f0d2a5221ca508f893af5c4b4bb9f4f520fd84289b3dbe7e61497a7e2a584037ea637b6981127174af57b471df4b2768fd79c1540fb3edf2ea22cb69bec0cf8d933d9c6fdd645e850591cca3d62c0c",
    },
}

func Test_EEACipher(t *testing.T) {
    for i, test := range zucEEATests {
        key, err := hex.DecodeString(test.key)
        if err != nil {
            t.Error(err)
        }

        c, err := NewEEACipher(key, test.count, test.bearer, test.direction)
        if err != nil {
            t.Error(err)
        }

        in, err := hex.DecodeString(test.in)
        if err != nil {
            t.Error(err)
        }

        out := make([]byte, len(in))
        copy(out, in)

        c.XORKeyStream(out, out)
        if hex.EncodeToString(out) != test.out {
            t.Errorf("case %d, expected=%s, result=%s\n", i+1, test.out, hex.EncodeToString(out))
        }
    }
}
