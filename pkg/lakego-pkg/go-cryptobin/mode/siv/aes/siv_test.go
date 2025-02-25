package aes

import (
    "bytes"
    "testing"
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
    var examplesJSON map[string]any

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

func Test_AEADAESCMACSIV(t *testing.T) {
    v := loadAESSIVExamples("aes_siv.tjson")[0]
    nonce := v.ad[0]

    c, err := NewCMAC(v.key, len(nonce))
    if err != nil {
        t.Fatal(err)
    }

    ct := c.Seal(nil, nonce, v.plaintext, nil)
    if !bytes.Equal(v.ciphertext, ct) {
        t.Errorf("Seal: expected: %x\ngot: %x", v.ciphertext, ct)
    }

    pt, err := c.Open(nil, nonce, ct, nil)
    if err != nil {
        t.Errorf("Open: %s", err)
    }

    if !bytes.Equal(v.plaintext, pt) {
        t.Errorf("Open: expected: %x\ngot: %x", v.plaintext, pt)
    }
}

func TestAEADAESPMACSIV(t *testing.T) {
    v := loadAESSIVExamples("aes_pmac_siv.tjson")[0]
    nonce := v.ad[0]

    c, err := NewPMAC(v.key, len(nonce))
    if err != nil {
        t.Fatal(err)
    }

    ct := c.Seal(nil, nonce, v.plaintext, nil)
    if !bytes.Equal(v.ciphertext, ct) {
        t.Errorf("Seal: expected: %x\ngot: %x", v.ciphertext, ct)
    }

    pt, err := c.Open(nil, nonce, ct, nil)
    if err != nil {
        t.Errorf("Open: %s", err)
    }

    if !bytes.Equal(v.plaintext, pt) {
        t.Errorf("Open: expected: %x\ngot: %x", v.plaintext, pt)
    }
}
