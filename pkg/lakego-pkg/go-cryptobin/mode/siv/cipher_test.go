// To the extent possible under law, the author have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.
// http://creativecommons.org/publicdomain/zero/1.0/

package siv

import (
    "bytes"
    "testing"
    "crypto/aes"
    "encoding/hex"
    "encoding/json"
)

type aesSIVExample struct {
    name       string
    key        []byte
    ad         [][]byte
    plaintext  []byte
    ciphertext []byte
}

var testData = map[string]string{}

func init() {
    testData["aes_cmac.tjson"] = `{
    "list":[
        {
            "key:d16":"2b7e151628aed2a6abf7158809cf4f3c",
            "message:d16":"",
            "tag:d16":"bb1d6929e95937287fa37d129b756746"
        },
        {
            "key:d16":"2b7e151628aed2a6abf7158809cf4f3c",
            "message:d16":"6bc1bee22e409f96e93d7e117393172a",
            "tag:d16":"070a16b46b4d4144f79bdd9dd04a287c"
        },
        {
            "key:d16":"2b7e151628aed2a6abf7158809cf4f3c",
            "message:d16":"6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411",
            "tag:d16":"dfa66747de9ae63030ca32611497c827"
        },
        {
            "key:d16":"2b7e151628aed2a6abf7158809cf4f3c",
            "message:d16":"6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
            "tag:d16":"51f0bebf7e3b9d92fc49741779363cfe"
        },
        {
            "key:d16":"603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
            "message:d16":"",
            "tag:d16":"028962f61b7bf89efc6b551f4667d983"
        },
        {
            "key:d16":"603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
            "message:d16":"6bc1bee22e409f96e93d7e117393172a",
            "tag:d16":"28a7023f452e8f82bd4bf28d8c37c35c"
        },
        {
            "key:d16":"603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
            "message:d16":"6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411",
            "tag:d16":"aaf3d8f1de5640c232f5b169b9c911e6"
        },
        {
            "key:d16":"603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
            "message:d16":"6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
            "tag:d16":"e1992190549f6ed5696a2c056c315410"
        }
    ]
}
`
    testData["aes_pmac.tjson"] = `{
  "list":[
    {
      "name:s":"PMAC-AES-128-0B",
      "key:d16":"000102030405060708090a0b0c0d0e0f",
      "message:d16":"",
      "tag:d16":"4399572cd6ea5341b8d35876a7098af7"
    },
    {
      "name:s":"PMAC-AES-128-3B",
      "key:d16":"000102030405060708090a0b0c0d0e0f",
      "message:d16":"000102",
      "tag:d16":"256ba5193c1b991b4df0c51f388a9e27"
    },
    {
      "name:s":"PMAC-AES-128-16B",
      "key:d16":"000102030405060708090a0b0c0d0e0f",
      "message:d16":"000102030405060708090a0b0c0d0e0f",
      "tag:d16":"ebbd822fa458daf6dfdad7c27da76338"
    },
    {
      "name:s":"PMAC-AES-128-20B",
      "key:d16":"000102030405060708090a0b0c0d0e0f",
      "message:d16":"000102030405060708090a0b0c0d0e0f10111213",
      "tag:d16":"0412ca150bbf79058d8c75a58c993f55"
    },
    {
      "name:s":"PMAC-AES-128-32B",
      "key:d16":"000102030405060708090a0b0c0d0e0f",
      "message:d16":"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
      "tag:d16":"e97ac04e9e5e3399ce5355cd7407bc75"
    },
    {
      "name:s":"PMAC-AES-128-34B",
      "key:d16":"000102030405060708090a0b0c0d0e0f",
      "message:d16":"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021",
      "tag:d16":"5cba7d5eb24f7c86ccc54604e53d5512"
    },
    {
      "name:s":"PMAC-AES-128-1000B",
      "key:d16":"000102030405060708090a0b0c0d0e0f",
      "message:d16":"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
      "tag:d16":"c2c9fa1d9985f6f0d2aff915a0e8d910"
    },
    {
      "name:s":"PMAC-AES-256-0B",
      "key:d16":"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
      "message:d16":"",
      "tag:d16":"e620f52fe75bbe87ab758c0624943d8b"
    },
    {
      "name:s":"PMAC-AES-256-3B",
      "key:d16":"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
      "message:d16":"000102",
      "tag:d16":"ffe124cc152cfb2bf1ef5409333c1c9a"
    },
    {
      "name:s":"PMAC-AES-256-16B",
      "key:d16":"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
      "message:d16":"000102030405060708090a0b0c0d0e0f",
      "tag:d16":"853fdbf3f91dcd36380d698a64770bab"
    },
    {
      "name:s":"PMAC-AES-256-20B",
      "key:d16":"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
      "message:d16":"000102030405060708090a0b0c0d0e0f10111213",
      "tag:d16":"7711395fbe9dec19861aeb96e052cd1b"
    },
    {
      "name:s":"PMAC-AES-256-32B",
      "key:d16":"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
      "message:d16":"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
      "tag:d16":"08fa25c28678c84d383130653e77f4c0"
    },
    {
      "name:s":"PMAC-AES-256-34B",
      "key:d16":"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
      "message:d16":"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021",
      "tag:d16":"edd8a05f4b66761f9eee4feb4ed0c3a1"
    },
    {
      "name:s":"PMAC-AES-256-1000B",
      "key:d16":"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
      "message:d16":"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
      "tag:d16":"69aa77f231eb0cdff960f5561d29a96e"
    }
  ]
}
`
    testData["aes_pmac_siv.tjson"] = `{
  "list":[
    {
      "name:s":"AES-PMAC-SIV-128-TV1: Deterministic Authenticated Encryption Example",
      "key:d16":"fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
      "ad:A<d16>":[
        "101112131415161718191a1b1c1d1e1f2021222324252627"
      ],
      "plaintext:d16":"112233445566778899aabbccddee",
      "ciphertext:d16":"8c4b814216140fc9b34a41716aa61633ea66abe16b2f6e4bceeda6e9077f"
    },
    {
      "name:s":"AES-PMAC-SIV-128-TV2: Nonce-Based Authenticated Encryption Example",
      "key:d16":"7f7e7d7c7b7a79787776757473727170404142434445464748494a4b4c4d4e4f",
      "ad:A<d16>":[
        "00112233445566778899aabbccddeeffdeaddadadeaddadaffeeddccbbaa99887766554433221100",
        "102030405060708090a0",
        "09f911029d74e35bd84156c5635688c0"
      ],
      "plaintext:d16":"7468697320697320736f6d6520706c61696e7465787420746f20656e6372797074207573696e67205349562d414553",
      "ciphertext:d16":"acb9cbc95dbed8e766d25ad59deb65bcda7aff9214153273f88e89ebe580c77defc15d28448f420e0a17d42722e6d42776849aa3bec375c5a05e54f519e9fd"
    },
    {
      "name:s":"AES-PMAC-SIV-128-TV3: Empty Authenticated Data And Plaintext Example",
      "key:d16":"fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
      "ad:A<d16>":[],
      "plaintext:d16":"",
      "ciphertext:d16":"19f25e5ea8a96ef27067d4626fdd3677"
    },
    {
      "name:s":"AES-PMAC-SIV-128-TV4: Nonce-Based Authenticated Encryption With Large Message Example",
      "key:d16":"fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
      "ad:A<d16>":[
        "101112131415161718191a1b1c1d1e1f2021222324252627"
      ],
      "plaintext:d16":"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f70",
      "ciphertext:d16":"34cbb315120924e6ad05240a1582018b3dc965941308e0535680344cf9cf40cb5aa00b449548f9a4d9718fd22057d19f5ea89450d2d3bf905e858aaec4fc594aa27948ea205ca90102fc463f5c1cbbfb171d296d727ec77f892fb192a4eb9897b7d48d50e474a1238f02a82b122a7b16aa5cc1c04b10b839e478662ff1cec7cabc"
    },
    {
      "name:s":"AES-PMAC-SIV-256-TV1: 256-bit key with one associated data field",
      "key:d16":"fffefdfcfbfaf9f8f7f6f5f4f3f2f1f06f6e6d6c6b6a69686766656463626160f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff000102030405060708090a0b0c0d0e0f",
      "ad:A<d16>":[
        "101112131415161718191a1b1c1d1e1f2021222324252627"
      ],
      "plaintext:d16":"112233445566778899aabbccddee",
      "ciphertext:d16":"77097bb3e160988e8b262c1942f983885f826d0d7e047e975e2fc4ea6776"
    },
    {
      "name:s":"AES-PMAC-SIV-256-TV2: 256-bit key with three associated data fields",
      "key:d16":"7f7e7d7c7b7a797877767574737271706f6e6d6c6b6a69686766656463626160404142434445464748494a4b4c4d4e4f505152535455565758595a5b5b5d5e5f",
      "ad:A<d16>":[
        "00112233445566778899aabbccddeeffdeaddadadeaddadaffeeddccbbaa99887766554433221100",
        "102030405060708090a0",
        "09f911029d74e35bd84156c5635688c0"
      ],
      "plaintext:d16":"7468697320697320736f6d6520706c61696e7465787420746f20656e6372797074207573696e67205349562d414553",
      "ciphertext:d16":"cd07d56dca0fe1569b8ecb3cf2346604290726e12529fc5948546b6be39fed9cd8652256c594c8f56208c7496789de8dfb4f161627c91482f9ecf809652a9e"
    },
    {
      "name:s":"AES-PMAC-SIV-256-TV3: Nonce-Based Authenticated Encryption With Large Message Example",
      "key:d16":"7f7e7d7c7b7a797877767574737271706f6e6d6c6b6a69686766656463626160404142434445464748494a4b4c4d4e4f505152535455565758595a5b5b5d5e5f",
      "ad:A<d16>":[
        "101112131415161718191a1b1c1d1e1f2021222324252627"
      ],
      "plaintext:d16":"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f70",
      "ciphertext:d16":"045ba64522c5c980835674d1c5a9264eca3e9f7aceafe9b5485b33f7d2c9114fe5c4b24f9c814d88e78b6150028d630289d023015b8569af338de0af8534827732b365ace1ac99d278431b22eafe31b94297b1c6a2de41383ed8b39f17e748aea128a8bd7d0ee80ec899f1b940c9c0463f22fc2b5a145cb6e90a32801dd1950f92"
    }
  ]
}
`
    testData["aes_siv.tjson"] = `{
    "list":[
        {
            "name:s":"Deterministic Authenticated Encryption Example",
            "key:d16":"fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
            "ad:A<d16>":[
                "101112131415161718191a1b1c1d1e1f2021222324252627"
            ],
            "plaintext:d16":"112233445566778899aabbccddee",
            "ciphertext:d16":"85632d07c6e8f37f950acd320a2ecc9340c02b9690c4dc04daef7f6afe5c"
        },
        {
            "name:s":"Nonce-Based Authenticated Encryption Example",
            "key:d16":"7f7e7d7c7b7a79787776757473727170404142434445464748494a4b4c4d4e4f",
            "ad:A<d16>":[
                "00112233445566778899aabbccddeeffdeaddadadeaddadaffeeddccbbaa99887766554433221100",
                "102030405060708090a0",
                "09f911029d74e35bd84156c5635688c0"
            ],
            "plaintext:d16":"7468697320697320736f6d6520706c61696e7465787420746f20656e6372797074207573696e67205349562d414553",
            "ciphertext:d16":"7bdb6e3b432667eb06f4d14bff2fbd0fcb900f2fddbe404326601965c889bf17dba77ceb094fa663b7a3f748ba8af829ea64ad544a272e9c485b62a3fd5c0d"
        },
        {
            "name:s":"Empty Authenticated Data And Plaintext Example",
            "key:d16":"fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
            "ad:A<d16>":[],
            "plaintext:d16":"",
            "ciphertext:d16":"f2007a5beb2b8900c588a7adf599f172"
        },
        {
            "name:s":"NIST SIV test vectors (256-bit subkeys #1)",
            "key:d16":"fffefdfcfbfaf9f8f7f6f5f4f3f2f1f06f6e6d6c6b6a69686766656463626160f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff000102030405060708090a0b0c0d0e0f",
            "ad:A<d16>":[
                "101112131415161718191a1b1c1d1e1f2021222324252627"
            ],
            "plaintext:d16":"112233445566778899aabbccddee",
            "ciphertext:d16":"f125274c598065cfc26b0e71575029088b035217e380cac8919ee800c126"
        },
        {
            "name:s":"NIST SIV test vectors (256-bit subkeys #2)",
            "key:d16":"7f7e7d7c7b7a797877767574737271706f6e6d6c6b6a69686766656463626160404142434445464748494a4b4c4d4e4f505152535455565758595a5b5b5d5e5f",
            "ad:A<d16>":[
                "00112233445566778899aabbccddeeffdeaddadadeaddadaffeeddccbbaa99887766554433221100",
                "102030405060708090a0",
                "09f911029d74e35bd84156c5635688c0"
            ],
            "plaintext:d16":"7468697320697320736f6d6520706c61696e7465787420746f20656e6372797074207573696e67205349562d414553",
            "ciphertext:d16":"85b8167310038db7dc4692c0281ca35868181b2762f3c24f2efa5fb80cb143516ce6c434b898a6fd8eb98a418842f51f66fc67de43ac185a66dd72475bbb08"
        },
        {
            "name:s":"Empty Authenticated Data And Block-Size Plaintext Example",
            "key:d16":"fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
            "ad:A<d16>":[],
            "plaintext:d16":"00112233445566778899aabbccddeeff",
            "ciphertext:d16":"f304f912863e303d5b540e5057c7010c942ffaf45b0e5ca5fb9a56a5263bb065"
        }
    ]
}
`
}

// Load test vectors
func loadAESSIVExamples(filename string) []aesSIVExample {
    var examplesJSON map[string]interface{}

    exampleData := testData[filename]

    if err := json.Unmarshal([]byte(exampleData), &examplesJSON); err != nil {
        panic(err)
    }

    examplesArray := examplesJSON["list"].([]interface{})

    if examplesArray == nil {
        panic("no toplevel 'list' key in " + filename)
    }

    result := make([]aesSIVExample, len(examplesArray))

    for i, exampleJSON := range examplesArray {
        example := exampleJSON.(map[string]interface{})

        name := example["name:s"].(string)

        keyHex := example["key:d16"].(string)
        key := make([]byte, hex.DecodedLen(len(keyHex)))

        if _, err := hex.Decode(key, []byte(keyHex)); err != nil {
            panic(err)
        }

        adHeaders := example["ad:A<d16>"].([]interface{})
        ad := make([][]byte, len(adHeaders))

        for j, adHeader := range adHeaders {
            adHeaderHex := adHeader.(string)
            adDecoded := make([]byte, hex.DecodedLen(len(adHeaderHex)))

            if _, err := hex.Decode(adDecoded, []byte(adHeaderHex)); err != nil {
                panic(err)
            }

            ad[j] = adDecoded
        }

        plaintextHex := example["plaintext:d16"].(string)
        plaintext := make([]byte, hex.DecodedLen(len(plaintextHex)))

        if _, err := hex.Decode(plaintext, []byte(plaintextHex)); err != nil {
            panic(err)
        }

        ciphertextHex := example["ciphertext:d16"].(string)
        ciphertext := make([]byte, hex.DecodedLen(len(ciphertextHex)))

        if _, err := hex.Decode(ciphertext, []byte(ciphertextHex)); err != nil {
            panic(err)
        }

        result[i] = aesSIVExample{name, key, ad, plaintext, ciphertext}
    }

    return result
}

func TestAESCMACSIV(t *testing.T) {
    for i, v := range loadAESSIVExamples("aes_siv.tjson") {
        n := len(v.key)
        macBlock, _ := aes.NewCipher(v.key[:n/2])
        ctrBlock, _ := aes.NewCipher(v.key[n/2:])

        c, err := NewCMACCipher(macBlock, ctrBlock)
        if err != nil {
            t.Errorf("NewCMACCipher: %d: %s", i, err)
        }

        ct, err := c.Seal(nil, v.plaintext, v.ad...)
        if err != nil {
            t.Errorf("Seal: %d: %s", i, err)
        }
        if !bytes.Equal(v.ciphertext, ct) {
            t.Errorf("Seal: %d: expected: %x\ngot: %x", i, v.ciphertext, ct)
        }
        pt, err := c.Open(nil, ct, v.ad...)
        if err != nil {
            t.Errorf("Open: %d: %s", i, err)
        }
        if !bytes.Equal(v.plaintext, pt) {
            t.Errorf("Open: %d: expected: %x\ngot: %x", i, v.plaintext, pt)
        }
    }
}

func TestAESPMACSIV(t *testing.T) {
    for i, v := range loadAESSIVExamples("aes_pmac_siv.tjson") {
        n := len(v.key)
        macBlock, _ := aes.NewCipher(v.key[:n/2])
        ctrBlock, _ := aes.NewCipher(v.key[n/2:])

        c, err := NewPMACCipher(macBlock, ctrBlock)
        if err != nil {
            t.Errorf("NewPMACCipher: %d: %s", i, err)
        }

        ct, err := c.Seal(nil, v.plaintext, v.ad...)
        if err != nil {
            t.Errorf("Seal: %d: %s", i, err)
        }
        if !bytes.Equal(v.ciphertext, ct) {
            t.Errorf("Seal: %d: expected: %x\ngot: %x", i, v.ciphertext, ct)
        }
        pt, err := c.Open(nil, ct, v.ad...)
        if err != nil {
            t.Errorf("Open: %d: %s", i, err)
        }
        if !bytes.Equal(v.plaintext, pt) {
            t.Errorf("Open: %d: expected: %x\ngot: %x", i, v.plaintext, pt)
        }
    }
}

func TestAESCMACSIVAppend(t *testing.T) {
    v := loadAESSIVExamples("aes_siv.tjson")[0]

    n := len(v.key)
    macBlock, _ := aes.NewCipher(v.key[:n/2])
    ctrBlock, _ := aes.NewCipher(v.key[n/2:])

    c, err := NewCMACCipher(macBlock, ctrBlock)
    if err != nil {
        t.Fatalf("NewCMACCipher: %s", err)
    }
    out := []byte{1, 2, 3, 4}
    x, err := c.Seal(out, v.plaintext, v.ad...)
    if err != nil {
        t.Fatalf("Seal: %s", err)
    }
    if !bytes.Equal(x[:4], out[:4]) {
        t.Fatalf("Seal: didn't correctly append")
    }

    out = make([]byte, 4, 100)
    x, err = c.Seal(out, v.plaintext, v.ad...)
    if err != nil {
        t.Fatalf("Seal: %s", err)
    }
    if !bytes.Equal(x[:4], out[:4]) {
        t.Fatalf("Seal: didn't correctly append with sufficient capacity")
    }

    out = make([]byte, 4)
    x, err = c.Open(out, v.ciphertext, v.ad...)
    if err != nil {
        t.Fatalf("Open: %s", err)
    }
    if !bytes.Equal(x[:4], out[:4]) {
        t.Fatalf("Open: didn't correctly append")
    }

    out = make([]byte, 4, 100)
    x, err = c.Open(out, v.ciphertext, v.ad...)
    if err != nil {
        t.Fatalf("Open: %s", err)
    }
    if !bytes.Equal(x[:4], out[:4]) {
        t.Fatalf("Open: didn't correctly append with sufficient capacity")
    }
}
