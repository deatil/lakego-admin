package x509

import (
    "testing"

    cryptobin_test "github.com/deatil/go-cryptobin/tool/test"
)

func Test_RegisterHash(t *testing.T) {
    defer func() {
        if err := recover(); err == nil {
            t.Error("RegisterHash shouild panic")
        }
    }()

    RegisterHash(maxHash+1, SM3.New)
}

func Test_New_Panic(t *testing.T) {
    defer func() {
        if err := recover(); err == nil {
            t.Error("Hash New shouild panic")
        }
    }()

    var tHash = maxHash+1

    tHash.New()
}

func Test_Size_Panic(t *testing.T) {
    defer func() {
        if err := recover(); err == nil {
            t.Error("Hash Size shouild panic")
        }
    }()

    var tHash = maxHash+1

    tHash.Size()
}

func Test_Size(t *testing.T) {
    eq := cryptobin_test.AssertEqualT(t)

    eq(SHA1.Size(), 20, "Test_Size-SHA1")
    eq(BLAKE2b_256.Size(), 32, "Test_Size-BLAKE2b_256")
    eq(BLAKE2b_512.Size(), 64, "Test_Size-BLAKE2b_512")
}

func Test_newHash(t *testing.T) {
    notempty := cryptobin_test.AssertNotEmptyT(t)

    notempty(newHashBlake2s_256(), "Test_newHash-newHashBlake2s_256")
    notempty(newHashBlake2b_256(), "Test_newHash-newHashBlake2b_256")
    notempty(newHashBlake2b_384(), "Test_newHash-newHashBlake2b_384")
    notempty(newHashBlake2b_512(), "Test_newHash-newHashBlake2b_512")
    notempty(newHashGOST34112001(), "Test_newHash-newHashGOST34112001")
}

func Test_String(t *testing.T) {
    eq := cryptobin_test.AssertEqualT(t)

    tests := []struct {
        hash  Hash
        check string
    }{
        {MD4, "MD4"},
        {MD5, "MD5"},
        {SHA1, "SHA-1"},
        {SHA224, "SHA-224"},
        {SHA256, "SHA-256"},
        {SHA384, "SHA-384"},
        {SHA512, "SHA-512"},
        {MD5SHA1, "MD5+SHA1"},
        {RIPEMD160, "RIPEMD-160"},
        {SHA3_224, "SHA3-224"},
        {SHA3_256, "SHA3-256"},
        {SHA3_384, "SHA3-384"},
        {SHA3_512, "SHA3-512"},
        {SHA512_224, "SHA-512/224"},
        {SHA512_256, "SHA-512/256"},
        {BLAKE2s_256, "BLAKE2s-256"},
        {BLAKE2b_256, "BLAKE2b-256"},
        {BLAKE2b_384, "BLAKE2b-384"},
        {BLAKE2b_512, "BLAKE2b-512"},
        {SM3, "SM3"},
        {GOST34112001, "GOST34112001"},
        {GOST34112012256, "GOST34112012256"},
        {GOST34112012512, "GOST34112012512"},
        {maxHash, "unknown hash value 24"},
    }

    for _, td := range tests {
        t.Run(td.check, func(t *testing.T) {
            eq(td.hash.String(), td.check, "Test_String-"+td.check)
        })
    }
}
