package drbg

import (
    "hash"
    "bytes"
    "testing"
    "crypto/sha1"
    "encoding/hex"
)

var testsHmac = []struct {
    newHash               func() hash.Hash
    entropyInput          string
    nonce                 string
    personalizationString string
    v0                    string
    entropyInputReseed    string
    additionalInputReseed string
    v1                    string
    additionalInput1      string
    v2                    string
    additionalInput2      string
    returnbits1           string
    v3                    string
}{
    {
        sha1.New,
        "1610b828ccd27de08ceea032a20e9208",
        "492cf1709242f6b5",
        "",
        "065cfd06fdee4ecdc39772ff0b14d292a95b34e700000000",
        "72d28c908edaf9a4d1e526d8f2ded544",
        "",
        "1757f8319f5f1a2fc080a951e1720bb062b0acf100000000",
        "",
        "ba6cc8ff04012c59bee77003b34cdad06498a19b00000000",
        "",
        "c38d96ac451375356f7fb62ead7dcc4e826edfa27fe4541f6ec5797855d844829b9560e3cb1c7a0bd9382ce607f574ebcbd01c33f87a40fec24082e0c4b3ad9ca4d3fa515aebd623ec0577313a74780c",
        "bcdadafea1fc17e0814dc4d6b89138727ab7537300000000",
    },
    {
        sha1.New,
        "d9bab5cedca96f6178d64509a0dfdc5e",
        "dad8989414450e01",
        "",
        "42dedc27246e6f21947388b464abb0d19b62a3b200000000",
        "72d28c908edaf9a4d1e526d8f2ded544",
        "",
        "687a6f97a1e530c389748f755501a4ea3fc9b34100000000",
        "",
        "60058aa9e07037a1f3d5acae44174ba1e96b8ff100000000",
        "",
        "662877ed2f9158b0a5d19ae87cd509a8622b5d751ba540b42c469c38dc8067873f3b19c17536fe36126ab2d6b28b890dace4f640e2113d22e4ef3aefbf8f73f1367d5cc660caf7ed9f24de1da0748728",
        "ac487d562cd4cebec05d8b3ec48497256f3c7f3f00000000",
    },
}

func Test_HMAC(t *testing.T) {
    for _, test := range testsHmac {
        entropyInput, _ := hex.DecodeString(test.entropyInput)
        nonce, _ := hex.DecodeString(test.nonce)
        personalizationString, _ := hex.DecodeString(test.personalizationString)
        v0, _ := hex.DecodeString(test.v0)
        hd, err := NewHMAC(test.newHash, entropyInput, nonce, personalizationString)
        if err != nil {
            t.Fatal(err)
        }

        if !bytes.Equal(hd.v[:len(v0)], v0) {
            t.Errorf("not same v0 %x, want %x", hd.v[:len(v0)], v0)
        }

        // Reseed
        entropyInputReseed, _ := hex.DecodeString(test.entropyInputReseed)
        additionalInputReseed, _ := hex.DecodeString(test.additionalInputReseed)
        v1, _ := hex.DecodeString(test.v1)
        hd.Reseed(entropyInputReseed, additionalInputReseed)

        if !bytes.Equal(hd.v[:len(v0)], v1) {
            t.Errorf("not same v1 %x, want %x", hd.v[:len(v0)], v1)
        }

        // Generate 1
        returnbits1, _ := hex.DecodeString(test.returnbits1)
        v2, _ := hex.DecodeString(test.v2)
        output := make([]byte, len(returnbits1))
        additionalInput1, _ := hex.DecodeString(test.additionalInput1)
        hd.Generate(output, additionalInput1)
        if !bytes.Equal(hd.v[:len(v0)], v2) {
            t.Errorf("not same v2 %x, want %x", hd.v[:len(v0)], v2)
        }

        // Generate 2
        v3, _ := hex.DecodeString(test.v3)
        additionalInput2, _ := hex.DecodeString(test.additionalInput2)
        hd.Generate(output, additionalInput2)
        if !bytes.Equal(hd.v[:len(v0)], v3) {
            t.Errorf("not same v3 %x, want %x", hd.v[:len(v0)], v3)
        }

        if !bytes.Equal(returnbits1, output) {
            t.Errorf("not expected return bits %x, want %x", output, returnbits1)
        }
    }
}
