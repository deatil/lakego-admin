package cascade

import (
    "bytes"
    "testing"
    "math/rand"
    "crypto/aes"
    "crypto/des"
    "crypto/cipher"
    "encoding/hex"

    "golang.org/x/crypto/cast5"
    "golang.org/x/crypto/twofish"
    "github.com/deatil/go-cryptobin/cipher/serpent"
    cryptobin_cipher "github.com/deatil/go-cryptobin/cipher"
)

func fromHex(s string) []byte {
    h, _ := hex.DecodeString(s)
    return h
}

func Test_Cipher(t *testing.T) {
    random := rand.New(rand.NewSource(99))
    max := 100

    var encrypted [16]byte
    var decrypted [16]byte

    for i := 0; i < max; i++ {
        key := make([]byte, 16)
        random.Read(key)
        key2 := make([]byte, 8)
        random.Read(key2)
        value := make([]byte, 16)
        random.Read(value)

        c1, err := aes.NewCipher(key)
        if err != nil {
            t.Fatal(err)
        }
        c2, err := des.NewCipher(key2)
        if err != nil {
            t.Fatal(err)
        }

        cipher1, err := NewCipher(c1, c2)
        if err != nil {
            t.Fatal(err.Error())
        }

        cipher1.Encrypt(encrypted[:], value)

        if bytes.Equal(encrypted[:], value[:]) {
            t.Errorf("fail: encrypted equal plaintext \n")
        }

        cipher2, err := NewCipher(c1, c2)
        if err != nil {
            t.Fatal(err.Error())
        }

        cipher2.Decrypt(decrypted[:], encrypted[:])

        if !bytes.Equal(decrypted[:], value[:]) {
            t.Errorf("encryption/decryption failed: % 02x != % 02x\n", decrypted, value)
        }
    }
}

var newTwofishCipher = func(key []byte) (cipher.Block, error) {
    return twofish.NewCipher(key)
}

var newCast5Cipher = func(key []byte) (cipher.Block, error) {
    return cast5.NewCipher(key)
}

var cipTests = []struct {
    cip1   func([]byte) (cipher.Block, error)
    cip2   func([]byte) (cipher.Block, error)
    key    []byte
    plain  []byte
    cipher []byte
}{
    // [Cascade(Serpent,Twofish)]
    {
        serpent.NewCipher,
        newTwofishCipher,
        fromHex("B50638F695AFA16F9378D43374CA8568600135ECD1E513838722366346BC4B2101422291558FAA30A3196CBEB42E67F4C075882482897F72A8A30AE9B3AD426D"),
        fromHex("0000000000000000000000000000000000000000000000000000000000000000"),
        fromHex("E78516D21D23DA501939C24C48BCC79DE78516D21D23DA501939C24C48BCC79D"),
    },
    {
        serpent.NewCipher,
        newTwofishCipher,
        fromHex("9E8F6BC09768AED8F533FA4FC35FF6FEB8020FFBC8350DDFD20ACA7ECF1889CFBFCD78E261B9A3CD825401AFA7ADCDFA88DBA8230FB92D4B942C25EE92F27A02"),
        fromHex("47CB8147C5290D6F94FBF3351777087FA731610A3F66E3CCFA6D9B18F980E687"),
        fromHex("F234E056923B3DB26AABC8F604F0CE2C1A7F4C35B0B74958014D791668FF6BF4"),
    },
    {
        serpent.NewCipher,
        newTwofishCipher,
        fromHex("1EF34E47005028F2D95120052855C6001225200A333CA4D7D5A356B5554EE2AE7EBC9BA57BADA0DAFC84C2187C51CB3CCB5EEE40F27C00537FFFCA2851DD8BD8"),
        fromHex("B9A28D32734EF678BACD5539FF9FF951AF81F44AFE223256E5D8898FB862A767B90BD2D95E17E4411D02D49481CCE4191EE2C7AE8EBDF6312BDC66317AD42140"),
        fromHex("065E390C4FD10E9929F30D89A67E0D4CFA3AF90BEF46B2B435B53CBE0B7DD1B612D4C5E2D03028B488000C06517434FC70F7B62C273CA5DEBD9CA7034D853087"),
    },

    // [Cascade(Serpent,AES-256)]
    {
        serpent.NewCipher,
        aes.NewCipher,
        fromHex("EE426051D1ADCE09AC02E2023331F273BB1B2C4C5905DEDA3E1032CCD0DB56115B011F05688F781E3F790364968E06DC6E7BD5FA38DB068CBD34A85B6B3A9458"),
        fromHex("06CEB2B4FD2F0A27B3C90D77D2E9BBD3665A8DCAC9187B1EE9F6A60D39042A9D3719883B3E87845B9D4A8BE258379959775969CBF5768A359797B2FA19FC2FCC"),
        fromHex("05FFBF6E8097FC746FFAD8C3306E6DB668148796180F26CA5DE06AE76DE16D078A0E72B259982423ED96FF95719DEB160CEFE7697752B0CFA984A18DDCEF2EC0"),
    },
    {
        serpent.NewCipher,
        aes.NewCipher,
        fromHex("CDCD23F5518DB5DAE8C69B56EB352D4F3C4A64A5FFC8E5BC2511B8310993C48EFA30A0F9E2B98A0FB1FE64173E6A8038047AEBAE22E17392FE32CF1D0DE3BB76"),
        fromHex("FBAF0DE6C09D10EB31F21A7C784BF453F82F51EFFA8B363EE6B33DF15204F43445170DED1E39AB922548ED82AAADED6BF470A5226B69D025FE3D532AADDA069C464D2C8A65E1A18698BD521AFB3053229C1539626392031F8C36229FF3178A7F5C716E30DBEFDDD4AC2113071977B795A8B29DA7F467471A996FB63136387C28"),
        fromHex("7ED1F730EED52DFB63E073A40EAE404E443ACEB9A3B55132E740ACE1EEDF99D0F22B3F2326E2E124594E75ED1915C8D155F24269254B22B6E8C53E9F64E70552D5E3004782C6C47341EBF8716B59DAB49B512B6DF7F9D7FB914FFA56F7F89B561B6A5DFE9334B7561144B25FE0F57BEBB4058EC7D9EEA57AB62825A86312BBC3"),
    },

    // [Cascade(Serpent,CAST-128)]
    {
        serpent.NewCipher,
        newCast5Cipher,
        fromHex("EFA9CC5F3E245AB463CC60A5015CB0F663676760832CEE6C633A518112E518D45DD4B627E9507CDB03A1ADD870E28362"),
        fromHex("27EDE4B2A3784A33898FA330167317BF7354072672D49DD03D13D3F0856CF3D9C17C1237565E7320BDD23C03BDE195A4FE58623A983DB9C308D5A976D92CD6A2"),
        fromHex("2D7096A03BAB4DBDABEDB9F069FE68C3E12ED65ACCE43ECF7F6D810B5EEC36A522B605715BE12003E324436652BEA06BD289DBE886A5DE9E51CFF6C065A21F2B"),
    },
}

func Test_Check(t *testing.T) {
    for _, tt := range cipTests {
        c1, err := tt.cip1(tt.key[:32])
        if err != nil {
            t.Fatal(err)
        }
        c2, err := tt.cip2(tt.key[32:])
        if err != nil {
            t.Fatal(err)
        }

        c, _ := NewCipher(c1, c2)

        b := make([]byte, len(tt.plain))
        cryptobin_cipher.
            NewECBEncrypter(c).
            CryptBlocks(b[:], tt.plain)
        if !bytes.Equal(b[:], tt.cipher) {
            t.Errorf("encrypt failed: got %x, want %x", b, tt.cipher)
        }

        cryptobin_cipher.
            NewECBDecrypter(c).
            CryptBlocks(b[:], tt.cipher)
        if !bytes.Equal(b[:], tt.plain) {
            t.Errorf("decrypt failed: got %x, want %x", b, tt.plain)
        }
    }
}
