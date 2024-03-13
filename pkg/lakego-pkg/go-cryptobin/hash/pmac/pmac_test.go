package pmac

import (
    "fmt"
    "bytes"
    "testing"
    "crypto/aes"
    "crypto/des"
    "encoding/hex"
    "encoding/json"
)

// A cipher.Block mock, simulating block ciphers
// with any block size.
type dummyCipher int

func (c dummyCipher) BlockSize() int { return int(c) }

func (c dummyCipher) Encrypt(dst, src []byte) { copy(dst, src) }

func (c dummyCipher) Decrypt(dst, src []byte) { copy(dst, src) }

type pmacAESExample struct {
    key     []byte
    message []byte
    tag     []byte
}

var testPmacData = `
{
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

// Load test vectors
func loadPMACAESExamples() []pmacAESExample {
    var examplesJSON map[string]interface{}

    exampleData := []byte(testPmacData)

    if err := json.Unmarshal(exampleData, &examplesJSON); err != nil {
        panic(err)
    }

    examplesArray := examplesJSON["list"].([]interface{})

    if examplesArray == nil {
        panic("no toplevel 'list' key in aes_pmac.tjson")
    }

    result := make([]pmacAESExample, len(examplesArray))

    for i, exampleJSON := range examplesArray {
        example := exampleJSON.(map[string]interface{})

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

        result[i] = pmacAESExample{key, message, tag}
    }

    return result
}

func TestPMACAES(t *testing.T) {
    for i, tt := range loadPMACAESExamples() {
        c, err := aes.NewCipher(tt.key)
        if err != nil {
            t.Errorf("test %d: NewCipher: %s", i, err)
            continue
        }
        d, _ := New(c)
        n, err := d.Write(tt.message)
        if err != nil || n != len(tt.message) {
            t.Errorf("test %d: Write %d: %d, %s", i, len(tt.message), n, err)
            continue
        }
        sum := d.Sum(nil)
        if !bytes.Equal(sum, tt.tag) {
            t.Errorf("test %d: tag mismatch\n\twant %x\n\thave %x", i, tt.tag, sum)
            continue
        }
    }
}

func TestWrite(t *testing.T) {
    pmacAESTests := loadPMACAESExamples()
    tt := pmacAESTests[len(pmacAESTests)-1]
    c, err := aes.NewCipher(tt.key)
    if err != nil {
        t.Fatal(err)
    }
    d, _ := New(c)

    // Test writing byte-by-byte
    for _, b := range tt.message {
        _, err := d.Write([]byte{b})
        if err != nil {
            t.Fatal(err)
        }
    }
    sum := d.Sum(nil)
    if !bytes.Equal(sum, tt.tag) {
        t.Fatalf("write bytes: tag mismatch\n\twant %x\n\thave %x", tt.tag, sum)
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
        t.Fatalf("write halves: tag mismatch\n\twant %x\n\thave %x", tt.tag, sum)
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
        t.Fatalf("write third: tag mismatch\n\twant %x\n\thave %x", tt.tag, sum)
    }
}

func TestSum(t *testing.T) {
    c, err := aes.NewCipher(make([]byte, 16))
    if err != nil {
        t.Fatalf("Could not create AES instance: %s", err)
    }

    msg := make([]byte, 64)
    for i := range msg {
        h, err := New(c)
        if err != nil {
            t.Fatalf("Iteration %d: Failed to create CMAC instance: %s", i, err)
        }

        h.Write(msg[:i])
        tag0 := h.Sum(nil)

        tag1, err := Sum(msg[:i], c, c.BlockSize())
        if err != nil {
            t.Fatalf("Iteration %d: Failed to compute CMAC tag: %s", i, err)
        }

        if !bytes.Equal(tag0, tag1) {
            t.Fatalf("Iteration %d: Sum differ from cmac.Sum\n Sum: %s \n cmac.Sum %s", i, hex.EncodeToString(tag0), hex.EncodeToString(tag1))
        }
    }

    _, err = Sum(nil, dummyCipher(20), 20)
    if err == nil {
        t.Fatalf("cmac.Sum allowed invalid block size: %d", 20)
    }
}

func TestVerify(t *testing.T) {
    var mac [16]byte
    mac[0] = 128

    if Verify(mac[:], nil, dummyCipher(20), 20) {
        t.Fatalf("cmac.Verify allowed invalid block size: %d", 20)
    }
}

func BenchmarkPMAC_AES128(b *testing.B) {
    pmacAESTests := loadPMACAESExamples()
    c, _ := aes.NewCipher(pmacAESTests[0].key)
    v := make([]byte, 1024)
    out := make([]byte, 16)
    b.SetBytes(int64(len(v)))
    for i := 0; i < b.N; i++ {
        d, _ := New(c)
        _, err := d.Write(v)
        if err != nil {
            panic(err)
        }
        out = d.Sum(out[:0])
    }
}

func Test_DES_Check(t *testing.T) {
    key := []byte("test1235")
    in := []byte("nonce-asdfg")
    check := "40b82d71e4d30a9d"

    block, err := des.NewCipher(key)
    if err != nil {
        t.Fatal(err)
    }

    h, _ := New(block)
    h.Write(in)

    out := h.Sum(nil)

    if fmt.Sprintf("%x", out) != check {
        t.Errorf("Check error. got %x, want %s", out, check)
    }
}
