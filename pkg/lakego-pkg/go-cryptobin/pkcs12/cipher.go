package pkcs12

import(
    "github.com/deatil/go-cryptobin/pkcs/pbes1"
)

// Add Cipher and Get Cipher
var (
    AddCipher = pbes1.AddCipher
    GetCipher = pbes1.GetCipher
)

// Cipher list
var (
    CipherSHA1And3DES    = pbes1.SHA1And3DES
    CipherSHA1And2DES    = pbes1.SHA1And2DES
    CipherSHA1AndRC2_128 = pbes1.SHA1AndRC2_128
    CipherSHA1AndRC2_40  = pbes1.SHA1AndRC2_40
    CipherSHA1AndRC4_128 = pbes1.SHA1AndRC4_128
    CipherSHA1AndRC4_40  = pbes1.SHA1AndRC4_40

    CipherMD5AndCAST5   = pbes1.MD5AndCAST5
    CipherSHAAndTwofish = pbes1.SHAAndTwofish
)
