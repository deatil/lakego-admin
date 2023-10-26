package pkcs8

import(
    "github.com/deatil/go-cryptobin/pkcs/pbes2"
)

// 别名
type (
    Cipher = pbes2.Cipher
)

var (
    AddCipher = pbes2.AddCipher
    GetCipher = pbes2.GetCipher

    // 帮助函数
    GetCipherFromName   = pbes2.GetCipherFromName
    CheckCipherFromName = pbes2.CheckCipherFromName
)

// 加密方式
var (
    DESCBC     = pbes2.DESCBC
    DESEDE3CBC = pbes2.DESEDE3CBC

    RC2CBC     = pbes2.RC2CBC
    RC2_40CBC  = pbes2.RC2_40CBC
    RC2_64CBC  = pbes2.RC2_64CBC
    RC2_128CBC = pbes2.RC2_128CBC

    RC5CBC     = pbes2.RC5CBC
    RC5_128CBC = pbes2.RC5_128CBC
    RC5_192CBC = pbes2.RC5_192CBC
    RC5_256CBC = pbes2.RC5_256CBC

    AES128ECB = pbes2.AES128ECB
    AES128CBC = pbes2.AES128CBC
    AES128OFB = pbes2.AES128OFB
    AES128CFB = pbes2.AES128CFB
    AES128GCM = pbes2.AES128GCM
    AES128CCM = pbes2.AES128CCM

    AES192ECB = pbes2.AES192ECB
    AES192CBC = pbes2.AES192CBC
    AES192OFB = pbes2.AES192OFB
    AES192CFB = pbes2.AES192CFB
    AES192GCM = pbes2.AES192GCM
    AES192CCM = pbes2.AES192CCM

    AES256ECB = pbes2.AES256ECB
    AES256CBC = pbes2.AES256CBC
    AES256OFB = pbes2.AES256OFB
    AES256CFB = pbes2.AES256CFB
    AES256GCM = pbes2.AES256GCM
    AES256CCM = pbes2.AES256CCM

    SM4ECB  = pbes2.SM4ECB
    SM4CBC  = pbes2.SM4CBC
    SM4OFB  = pbes2.SM4OFB
    SM4CFB  = pbes2.SM4CFB
    SM4CFB1 = pbes2.SM4CFB1
    SM4CFB8 = pbes2.SM4CFB8
    SM4GCM  = pbes2.SM4GCM
    SM4CCM  = pbes2.SM4CCM
)
