package key

// Pkcs1 Cipher 列表
var Pkcs1Ciphers = []string{
    "DESCBC",
    "DESEDE3CBC",

    "AES128CBC",
    "AES192CBC",
    "AES256CBC",
}

// Pkcs8Pbe Cipher 列表
var Pkcs8PbeCiphers = []string{
    "MD5AndDES",
    "SHA1AndDES",
    "SHA1And3DES",
    "SHA1AndRC4_128",
    "SHA1AndRC4_40",
}

// Pkcs8 Cipher 列表
var Pkcs8Ciphers = []string{
    "DESCBC",
    "DESEDE3CBC",

    "AES128ECB",
    "AES128CBC",
    "AES128OFB",
    "AES128CFB",
    "AES128GCM",
    "AES128GCMb",
    "AES128CCM",
    "AES128CCMb",

    "AES192ECB",
    "AES192CBC",
    "AES192OFB",
    "AES192CFB",
    "AES192GCM",
    "AES192GCMb",
    "AES192CCM",
    "AES192CCMb",

    "AES256ECB",
    "AES256CBC",
    "AES256OFB",
    "AES256CFB",
    "AES256GCM",
    "AES256GCMb",
    "AES256CCM",
    "AES256CCMb",

    "SM4ECB",
    "SM4CBC",
    "SM4OFB",
    "SM4CFB",
    "SM4CFB8",
    "SM4GCM",
    "SM4GCMb",
    "SM4CCM",
    "SM4CCMb",
}

// Pkcs8 hash 列表
var Pkcs8Hashes = []string{
    "MD5",
    "SHA1",
    "SHA224",
    "SHA256",
    "SHA384",
    "SHA512",
    "SHA512_224",
    "SHA512_256",
    "SM3",
}

