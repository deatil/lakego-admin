package pbes1

import(
    "github.com/deatil/go-cryptobin/pkcs/pbes1"
    "github.com/deatil/go-cryptobin/tool/bmp_string"
)

// BmpStringZeroTerminated returns s encoded in UCS-2 with a zero terminator.
var BmpStringZeroTerminated = bmp_string.BmpStringZeroTerminated

// 别名
type (
    Cipher = pbes1.Cipher
)

var (
    AddCipher = pbes1.AddCipher
    GetCipher = pbes1.GetCipher

    // 帮助函数
    GetCipherFromName   = pbes1.GetCipherFromName
    CheckCipherFromName = pbes1.CheckCipherFromName
    GetCipherName       = pbes1.GetCipherName
    CheckCipher         = pbes1.CheckCipher
)

// 加密方式
var (
    // pkcs12
    SHA1AndRC4_128 = pbes1.SHA1AndRC4_128
    SHA1AndRC4_40  = pbes1.SHA1AndRC4_40
    SHA1And3DES    = pbes1.SHA1And3DES
    SHA1And2DES    = pbes1.SHA1And2DES
    SHA1AndRC2_128 = pbes1.SHA1AndRC2_128
    SHA1AndRC2_40  = pbes1.SHA1AndRC2_40

    MD5AndCAST5   = pbes1.MD5AndCAST5
    SHAAndTwofish = pbes1.SHAAndTwofish

    // PBES1
    MD2AndDES     = pbes1.MD2AndDES
    MD2AndRC2_64  = pbes1.MD2AndRC2_64
    MD5AndDES     = pbes1.MD5AndDES
    MD5AndRC2_64  = pbes1.MD5AndRC2_64
    SHA1AndDES    = pbes1.SHA1AndDES
    SHA1AndRC2_64 = pbes1.SHA1AndRC2_64
)
