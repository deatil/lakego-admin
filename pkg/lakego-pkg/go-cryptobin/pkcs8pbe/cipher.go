package pkcs8pbe

import(
    "github.com/deatil/go-cryptobin/pkcs/pbes1"
)

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
)

// 加密方式
var (
    // pcks12 模式
    SHA1And3DES    = pbes1.SHA1And3DES
    SHA1And2DES    = pbes1.SHA1And2DES
    SHA1AndRC2_128 = pbes1.SHA1AndRC2_128
    SHA1AndRC2_40  = pbes1.SHA1AndRC2_40
    SHA1AndRC4_128 = pbes1.SHA1AndRC4_128
    SHA1AndRC4_40  = pbes1.SHA1AndRC4_40

    // pkcs5-v1.5 模式
    MD2AndDES     = pbes1.MD2AndDES
    MD2AndRC2_64  = pbes1.MD2AndRC2_64
    MD5AndDES     = pbes1.MD5AndDES
    MD5AndRC2_64  = pbes1.MD5AndRC2_64
    SHA1AndDES    = pbes1.SHA1AndDES
    SHA1AndRC2_64 = pbes1.SHA1AndRC2_64
)
