package pbes2

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
    GetCipherName       = pbes2.GetCipherName
    CheckCipher         = pbes2.CheckCipher
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

    GostCipher = pbes2.GostCipher

    ARIA128ECB = pbes2.ARIA128ECB
    ARIA128CBC = pbes2.ARIA128CBC
    ARIA128CFB = pbes2.ARIA128CFB
    ARIA128OFB = pbes2.ARIA128OFB
    ARIA128CTR = pbes2.ARIA128CTR
    ARIA128GCM = pbes2.ARIA128GCM
    ARIA128CCM = pbes2.ARIA128CCM

    ARIA192ECB = pbes2.ARIA192ECB
    ARIA192CBC = pbes2.ARIA192CBC
    ARIA192CFB = pbes2.ARIA192CFB
    ARIA192OFB = pbes2.ARIA192OFB
    ARIA192CTR = pbes2.ARIA192CTR
    ARIA192GCM = pbes2.ARIA192GCM
    ARIA192CCM = pbes2.ARIA192CCM

    ARIA256ECB = pbes2.ARIA256ECB
    ARIA256CBC = pbes2.ARIA256CBC
    ARIA256CFB = pbes2.ARIA256CFB
    ARIA256OFB = pbes2.ARIA256OFB
    ARIA256CTR = pbes2.ARIA256CTR
    ARIA256GCM = pbes2.ARIA256GCM
    ARIA256CCM = pbes2.ARIA256CCM

    Misty1CBC = pbes2.Misty1CBC

    Serpent128ECB = pbes2.Serpent128ECB
    Serpent128CBC = pbes2.Serpent128CBC
    Serpent128OFB = pbes2.Serpent128OFB
    Serpent128CFB = pbes2.Serpent128CFB

    Serpent192ECB = pbes2.Serpent192ECB
    Serpent192CBC = pbes2.Serpent192CBC
    Serpent192OFB = pbes2.Serpent192OFB
    Serpent192CFB = pbes2.Serpent192CFB

    Serpent256ECB = pbes2.Serpent256ECB
    Serpent256CBC = pbes2.Serpent256CBC
    Serpent256OFB = pbes2.Serpent256OFB
    Serpent256CFB = pbes2.Serpent256CFB

    // seed
    SeedECB = pbes2.SeedECB
    SeedCBC = pbes2.SeedCBC
    SeedOFB = pbes2.SeedOFB
    SeedCFB = pbes2.SeedCFB

    Seed256ECB = pbes2.Seed256ECB
    Seed256CBC = pbes2.Seed256CBC
    Seed256OFB = pbes2.Seed256OFB
    Seed256CFB = pbes2.Seed256CFB
)
