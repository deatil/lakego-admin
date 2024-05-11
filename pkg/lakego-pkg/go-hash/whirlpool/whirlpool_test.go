package whirlpool_test

import (
    "fmt"
    "bytes"
    "testing"
    "encoding/hex"

    "github.com/deatil/go-hash/whirlpool"
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

func Test_Hash_Check(t *testing.T) {
   tests := []testData{
        {
           fromString(""),
           fromHex("19FA61D75522A4669B44E39C1D2E1726C530232130D407F89AFEE0964997F7A73E83BE698B288FEBCF88E3E03C4F0757EA8964E59B63D93708B138CC42A66EB3"),
        },
        {
           fromString("a"),
           fromHex("8ACA2602792AEC6F11A67206531FB7D7F0DFF59413145E6973C45001D0087B42D11BC645413AEFF63A42391A39145A591A92200D560195E53B478584FDAE231A"),
        },
        {
           fromString("abc"),
           fromHex("4E2448A4C6F486BB16B6562C73B4020BF3043E3A731BCE721AE1B303D97E6D4C7181EEBDB6C57E277D0E34957114CBD6C797FC9D95D8B582D225292076D4EEF5"),
        },
        {
           fromString("message digest"),
           fromHex("378C84A4126E2DC6E56DCC7458377AAC838D00032230F53CE1F5700C0FFB4D3B8421557659EF55C106B4B52AC5A4AAA692ED920052838F3362E86DBD37A8903E"),
        },
        {
           fromString("abcdefghijklmnopqrstuvwxyz"),
           fromHex("F1D754662636FFE92C82EBB9212A484A8D38631EAD4238F5442EE13B8054E41B08BF2A9251C30B6A0B8AAE86177AB4A6F68F673E7207865D5D9819A3DBA4EB3B"),
        },
        {
           fromString("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"),
           fromHex("DC37E008CF9EE69BF11F00ED9ABA26901DD7C28CDEC066CC6AF42E40F82F3A1E08EBA26629129D8FB7CB57211B9281A65517CC879D7B962142C65F5A7AF01467"),
        },
        {
           fromString("12345678901234567890123456789012345678901234567890123456789012345678901234567890"),
           fromHex("466EF18BABB0154D25B9D38A6414F5C08784372BCCB204D6549C4AFADB6014294D5BD8DF2A6C44E538CD047B2681A51A2C60481E88C5A20B2C2A80CF3A9A083B"),
        },
        {
           fromString("abcdbcdecdefdefgefghfghighijhijk"),
           fromHex("2A987EA40F917061F5D6F0A0E4644F488A7A5A52DEEE656207C562F988E95C6916BDC8031BC5BE1B7B947639FE050B56939BAAA0ADFF9AE6745B7B181C3BE3FD"),
        },
    }

    h := whirlpool.New()

    for i, test := range tests {
        h.Reset()
        h.Write(test.msg)
        sum := h.Sum(nil)

        if !bytes.Equal(sum, test.md) {
            t.Errorf("[%d] New fail, got %x, want %x", i, sum, test.md)
        }

        // =====

        sum2 := whirlpool.Sum(test.msg)

        if !bytes.Equal(sum2[:], test.md) {
            t.Errorf("[%d] Sum fail, got %x, want %x", i, sum2, test.md)
        }
    }
}

func Test_Check(t *testing.T) {
    data := "abcdefghij"
    hashed := "717163DE24809FFCF7FF6D5ABA72B8D67C2129721953C252A4DDFB107614BE857CBD76A9D5927DE14633D6BDC9DDF335160B919DB5C6F12CB2E6549181912EEF"

    h := whirlpool.New()
    h.Write([]byte(data))

    s := fmt.Sprintf("%X", h.Sum(nil))
    if s != hashed {
        t.Fatalf("got %s, want %s", s, hashed)
    }
}

func Test_SumCheck(t *testing.T) {
    data := "abcdefghij"
    hashed := "717163DE24809FFCF7FF6D5ABA72B8D67C2129721953C252A4DDFB107614BE857CBD76A9D5927DE14633D6BDC9DDF335160B919DB5C6F12CB2E6549181912EEF"

    s := fmt.Sprintf("%X", whirlpool.Sum([]byte(data)))
    if s != hashed {
        t.Fatalf("Sum got %s, want %s", s, hashed)
    }

}

func Test_Hash0_Check(t *testing.T) {
   tests := []testData{
        {
           fromString(""),
           fromHex("B3E1AB6EAF640A34F784593F2074416ACCD3B8E62C620175FCA0997B1BA2347339AA0D79E754C308209EA36811DFA40C1C32F1A2B9004725D987D3635165D3C8"),
        },
        {
           fromString("The quick brown fox jumps over the lazy dog"),
           fromHex("4F8F5CB531E3D49A61CF417CD133792CCFA501FD8DA53EE368FED20E5FE0248C3A0B64F98A6533CEE1DA614C3A8DDEC791FF05FEE6D971D57C1348320F4EB42D"),
        },
        {
           fromString("The quick brown fox jumps over the lazy eog"),
           fromHex("228FBF76B2A93469D4B25929836A12B7D7F2A0803E43DABA0C7FC38BC11C8F2A9416BBCF8AB8392EB2AB7BCB565A64AC50C26179164B26084A253CAF2E012676"),
        },
    }

    h := whirlpool.New0()

    for i, test := range tests {
        h.Reset()
        h.Write(test.msg)
        sum := h.Sum(nil)

        if !bytes.Equal(sum, test.md) {
            t.Errorf("[%d] New0 fail, got %x, want %x", i, sum, test.md)
        }

        // =====

        sum2 := whirlpool.Sum0(test.msg)

        if !bytes.Equal(sum2[:], test.md) {
            t.Errorf("[%d] Sum0 fail, got %x, want %x", i, sum2, test.md)
        }
    }
}

func Test_Hash1_Check(t *testing.T) {
   tests := []testData{
        {
           fromString(""),
           fromHex("470F0409ABAA446E49667D4EBE12A14387CEDBD10DD17B8243CAD550A089DC0FEEA7AA40F6C2AAAB71C6EBD076E43C7CFCA0AD32567897DCB5969861049A0F5A"),
        },
        {
           fromString("The quick brown fox jumps over the lazy dog"),
           fromHex("3CCF8252D8BBB258460D9AA999C06EE38E67CB546CFFCF48E91F700F6FC7C183AC8CC3D3096DD30A35B01F4620A1E3A20D79CD5168544D9E1B7CDF49970E87F1"),
        },
        {
           fromString("The quick brown fox jumps over the lazy eog"),
           fromHex("C8C15D2A0E0DE6E6885E8A7D9B8A9139746DA299AD50158F5FA9EECDDEF744F91B8B83C617080D77CB4247B1E964C2959C507AB2DB0F1F3BF3E3B299CA00CAE3"),
        },
    }

    h := whirlpool.New1()

    for i, test := range tests {
        h.Reset()
        h.Write(test.msg)
        sum := h.Sum(nil)

        if !bytes.Equal(sum, test.md) {
            t.Errorf("[%d] New1 fail, got %x, want %x", i, sum, test.md)
        }

        // =====

        sum2 := whirlpool.Sum1(test.msg)

        if !bytes.Equal(sum2[:], test.md) {
            t.Errorf("[%d] Sum1 fail, got %x, want %x", i, sum2, test.md)
        }
    }
}
