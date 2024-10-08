package pgp_s2k

import (
    "hash"
    "bytes"
    "testing"
    "crypto/sha1"
    "crypto/sha512"
    "encoding/hex"
)

func fromHex(s string) []byte {
    h, _ := hex.DecodeString(s)
    return h
}

type testVector struct {
    password string
    salt     []byte
    iter     int
    output   []byte
}

var sha1TestVectors = []testVector{
    {
        "",
        fromHex(""),
        1,
        fromHex("DA39A3EE5E6B"),
    },
    {
        "hello",
        fromHex(""),
        1,
        fromHex("AAF4C61D"),
    },
    {
        "hello",
        fromHex("01020304"),
        1,
        fromHex("10295AC1"),
    },
    {
        "bar",
        fromHex("01020304"),
        1,
        fromHex("BD8AAC6B9EA9CAE04EAE6A91C6133B58B5D9A61C14F355516ED9370456"),
    },
    {
        "bar",
        fromHex("04030201"),
        31,
        fromHex("2AF5A99B54F093789FD657F19BD245AF7604D0F6AE06F66602A46A08AE"),
    },
    {
        "ilikepie",
        fromHex("2AE6E5831A717917"),
        65536,
        fromHex("A32F874A4CF95DFAD8359302B395455C"),
    },
    {
        "passphrase",
        fromHex("0102030405060708"),
        1,
        fromHex("eec8929a31187dd3a9a7ce5a97d96a67706382bbef70fe3b2a3aeeaf176bce252c117970a51fd8b770a69f8ecb199505395bd7b0c0760d6a38ac82900b23fe3b"),
    },
    {
        "passphrase",
        fromHex("0102030405060708"),
        65536,
        fromHex("24ce08a4a31de2208acdc15347def7a63492d38a0c08f80533a746279d91cb25e1b6b740b09e20a4884ca1944d506eb200753761066e8d4b24957c2593388457"),
    },
    {
        "passphrase",
        fromHex("0102030405060708"),
        10000000,
        fromHex("09efbd3599e2453c6cf1749a7ed169514a12d1a721549468c6d0ef6737fa3e27ab6d100f9839694fc70c484a42b00ef87463d07e2aafb92033843a4bd5f37971"),
    },
}

var sha384TestVectors = []testVector{
    {
        "passphrase",
        fromHex("0102030405060708"),
        1,
        fromHex("ea024c2de8af9a3edfbac9422f7b17e17c3165147b43f4edd58b55af9a412d07e0631f431a7e0028fbb145d9d5e059a888f1a7526cd338b1b6082a8681b446fa"),
    },
    {
        "passphrase",
        fromHex("0102030405060708"),
        18,
        fromHex("ea024c2de8af9a3edfbac9422f7b17e17c3165147b43f4edd58b55af9a412d07e0631f431a7e0028fbb145d9d5e059a888f1a7526cd338b1b6082a8681b446fa"),
    },
    {
        "passphrase",
        fromHex("0102030405060708"),
        19,
        fromHex("491aa377a1a9526d53b118587a03f85f5dc64568f3aabaad66aafc923397fb74d7017a6a4812bff2d9beddcbc6a0dbd3b96a3f9a69b637d68670acd48d4dfa4e"),
    },
    {
        "passphrase",
        fromHex("0102030405060708"),
        1000000,
        fromHex("af4986488f4e53ac4f7991a0bb8de15441ba1070481fe63b126ff3de2e1072f568dd3d6c5887d008925d27649494ae6f4860e141d5eeabe4f93745ca9cb8e08c"),
    },

}

func testHash(t *testing.T, h func() hash.Hash, hashName string, vectors []testVector) {
    for i, v := range vectors {
        o := Key(h, []byte(v.password), v.salt, v.iter, len(v.output))
        if !bytes.Equal(o, v.output) {
            t.Errorf("%s %d: want %x, got %x", hashName, i, v.output, o)
        }
    }
}

func TestWithSHA1(t *testing.T) {
    testHash(t, sha1.New, "SHA1", sha1TestVectors)
}

func TestWithSHA384(t *testing.T) {
    testHash(t, sha512.New384, "SHA384", sha384TestVectors)
}
