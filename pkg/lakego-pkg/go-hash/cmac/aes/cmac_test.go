package aes

import (
    "bytes"
    "testing"
    "encoding/hex"
    "encoding/json"
)

type cmacAESExample struct {
    key     []byte
    message []byte
    tag     []byte
}

var testData = `
{
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

// Load test vectors
func loadCMACAESExamples() []cmacAESExample {
    var examplesJSON map[string]any

    exampleData := []byte(testData)

    if err := json.Unmarshal(exampleData, &examplesJSON); err != nil {
        panic(err)
    }

    examplesArray := examplesJSON["list"].([]any)

    if examplesArray == nil {
        panic("no toplevel 'list' key in aes_cmac.tjson")
    }

    result := make([]cmacAESExample, len(examplesArray))

    for i, exampleJSON := range examplesArray {
        example := exampleJSON.(map[string]any)

        keyHex := example["key:d16"].(string)
        key := make([]byte, hex.DecodedLen(len(keyHex)))

        if _, err := hex.Decode(key, []byte(keyHex)); err != nil {
            panic(err)
        }

        messageHex := example["message:d16"].(string)
        message := make([]byte, hex.DecodedLen(len(messageHex)))

        if _, err := hex.Decode(message, []byte(messageHex)); err != nil {
            panic(err)
        }

        tagHex := example["tag:d16"].(string)
        tag := make([]byte, hex.DecodedLen(len(tagHex)))

        if _, err := hex.Decode(tag, []byte(tagHex)); err != nil {
            panic(err)
        }

        result[i] = cmacAESExample{key, message, tag}
    }

    return result
}

func TestCMACAES(t *testing.T) {
    for i, tt := range loadCMACAESExamples() {
        d, err := New(tt.key)
        if err != nil {
            t.Errorf("test %d: NewCipher: %s", i, err)
            continue
        }

        n, err := d.Write(tt.message)
        if err != nil || n != len(tt.message) {
            t.Errorf("test %d: Write %d: %d, %s", i, len(tt.message), n, err)
            continue
        }

        sum := d.Sum(nil)
        if !bytes.Equal(sum, tt.tag) {
            t.Errorf("test %d: tag mismatch\n\twant %x\n\thave %x\n\t", i, tt.tag, sum)
            continue
        }
    }
}

func TestWrite(t *testing.T) {
    cmacAESTests := loadCMACAESExamples()
    tt := cmacAESTests[len(cmacAESTests)-1]

    d, err := New(tt.key)
    if err != nil {
        t.Fatal(err)
    }

    // Test writing byte-by-byte
    for _, b := range tt.message {
        _, err := d.Write([]byte{b})
        if err != nil {
            t.Fatal(err)
        }
    }
    sum := d.Sum(nil)
    if !bytes.Equal(sum, tt.tag) {
        t.Fatalf("write bytes: tag mismatch\n\twant %x\n\thave %x\n\t", tt.tag, sum)
    }

    // Test writing halves
    d.Reset()

    _, err = d.Write(tt.message[:len(tt.message)/2])
    if err != nil {
        t.Fatal(err)
    }

    _, err = d.Write(tt.message[len(tt.message)/2:])
    if err != nil {
        t.Fatal(err)
    }

    sum = d.Sum(nil)
    if !bytes.Equal(sum, tt.tag) {
        t.Fatalf("write halves: tag mismatch\n\twant %x\n\thave %x\n\t", tt.tag, sum)
    }

    // Test writing third, then the rest
    d.Reset()
    _, err = d.Write(tt.message[:len(tt.message)/3])
    if err != nil {
        t.Fatal(err)
    }

    _, err = d.Write(tt.message[len(tt.message)/3:])
    if err != nil {
        t.Fatal(err)
    }

    sum = d.Sum(nil)
    if !bytes.Equal(sum, tt.tag) {
        t.Fatalf("write third: tag mismatch\n\twant %x\n\thave %x\n\t", tt.tag, sum)
    }

    // Test continuing after Sum
    d.Reset()

    _, err = d.Write(tt.message[:len(tt.message)/2])
    if err != nil {
        t.Fatal(err)
    }

    sum = d.Sum(nil)

    _, err = d.Write(tt.message[len(tt.message)/2:])
    if err != nil {
        t.Fatal(err)
    }

    sum = d.Sum(nil)
    if !bytes.Equal(sum, tt.tag) {
        t.Fatalf("continue after Sum: tag mismatch\n\twant %x\n\thave %x\n\t", tt.tag, sum)
    }
}

func BenchmarkCMAC_AES128(b *testing.B) {
    cmacAESTests := loadCMACAESExamples()

    v := make([]byte, 1024)
    out := make([]byte, 16)
    b.SetBytes(int64(len(v)))
    for i := 0; i < b.N; i++ {
        d, _ := New(cmacAESTests[0].key)
        _, err := d.Write(v)
        if err != nil {
            panic(err)
        }
        out = d.Sum(out[:0])
    }
}
