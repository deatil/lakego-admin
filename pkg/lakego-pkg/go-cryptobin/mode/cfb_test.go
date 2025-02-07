package cipher

import (
    "testing"
    "crypto/aes"
    "encoding/hex"

    cryptobin_test "github.com/deatil/go-cryptobin/tool/test"
)

func fromHex(s string) []byte {
    h, _ := hex.DecodeString(s)
    return h
}

func Test_CFB1(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertNoError := cryptobin_test.AssertNoErrorT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    key := []byte("kkinjkijeel22plo")
    iv := []byte("11injkijkol22plo")
    plaintext := []byte("kjinjkijkolkdplokjinjkijkolkdplo")

    c, err := aes.NewCipher(key)
    assertNoError(err, "Test_CFB1")

    mode := NewCFB1Encrypter(c, iv)
    ciphertext := make([]byte, len(plaintext))
    mode.XORKeyStream(ciphertext, plaintext)

    mode2 := NewCFB1Decrypter(c, iv)
    plaintext2 := make([]byte, len(ciphertext))
    mode2.XORKeyStream(plaintext2, ciphertext)

    assertNotEmpty(plaintext2, "Test_CFB1")

    assertEqual(plaintext2, plaintext, "Test_CFB1-Equal")
}

func Test_CFB8(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertNoError := cryptobin_test.AssertNoErrorT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    key := []byte("kkinjkijeel22plo")
    iv := []byte("11injkijkol22plo")
    plaintext := []byte("kjinjkijkolkdplokjinjkijkolkdplo")

    c, err := aes.NewCipher(key)
    assertNoError(err, "Test_CFB8")

    mode := NewCFB8Encrypter(c, iv)
    ciphertext := make([]byte, len(plaintext))
    mode.XORKeyStream(ciphertext, plaintext)

    mode2 := NewCFB8Decrypter(c, iv)
    plaintext2 := make([]byte, len(ciphertext))
    mode2.XORKeyStream(plaintext2, ciphertext)

    assertNotEmpty(plaintext2, "Test_CFB8")

    assertEqual(plaintext2, plaintext, "Test_CFB8-Equal")
}

func Test_CFB16(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertNoError := cryptobin_test.AssertNoErrorT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    key := []byte("kkinjkijeel22plo")
    iv := []byte("11injkijkol22plo")
    plaintext := []byte("kjinjkijkolkdplokjinjkijkolkdplo")

    c, err := aes.NewCipher(key)
    assertNoError(err, "Test_CFB16")

    mode := NewCFB16Encrypter(c, iv)
    ciphertext := make([]byte, len(plaintext))
    mode.XORKeyStream(ciphertext, plaintext)

    mode2 := NewCFB16Decrypter(c, iv)
    plaintext2 := make([]byte, len(ciphertext))
    mode2.XORKeyStream(plaintext2, ciphertext)

    assertNotEmpty(plaintext2, "Test_CFB16")

    assertEqual(plaintext2, plaintext, "Test_CFB16-Equal")
}

func Test_CFB32(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertNoError := cryptobin_test.AssertNoErrorT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    key := []byte("kkinjkijeel22plo")
    iv := []byte("11injkijkol22plo")
    plaintext := []byte("kjinjkijkolkdplokjinjkijkolkdplo")

    c, err := aes.NewCipher(key)
    assertNoError(err, "Test_CFB32")

    mode := NewCFB32Encrypter(c, iv)
    ciphertext := make([]byte, len(plaintext))
    mode.XORKeyStream(ciphertext, plaintext)

    mode2 := NewCFB32Decrypter(c, iv)
    plaintext2 := make([]byte, len(ciphertext))
    mode2.XORKeyStream(plaintext2, ciphertext)

    assertNotEmpty(plaintext2, "Test_CFB32")

    assertEqual(plaintext2, plaintext, "Test_CFB32-Equal")
}

func Test_CFB64(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertNoError := cryptobin_test.AssertNoErrorT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    key := []byte("kkinjkijeel22plo")
    iv := []byte("11injkijkol22plo")
    plaintext := []byte("kjinjkijkolkdplokjinjkijkolkdplo")

    c, err := aes.NewCipher(key)
    assertNoError(err, "Test_CFB64")

    mode := NewCFB64Encrypter(c, iv)
    ciphertext := make([]byte, len(plaintext))
    mode.XORKeyStream(ciphertext, plaintext)

    mode2 := NewCFB64Decrypter(c, iv)
    plaintext2 := make([]byte, len(ciphertext))
    mode2.XORKeyStream(plaintext2, ciphertext)

    assertNotEmpty(plaintext2, "Test_CFB64")

    assertEqual(plaintext2, plaintext, "Test_CFB64-Equal")
}

func Test_CFB1_Check(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertNoError := cryptobin_test.AssertNoErrorT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    for _, td := range testCFBDataCFB1s {
        t.Run(td.name, func(t *testing.T) {
            key := td.key
            iv := td.iv
            plaintext := td.pt
            ciphertext := td.ct

            c, err := aes.NewCipher(key)
            assertNoError(err, "Test_CFB1_Check")

            mode := NewCFB1Encrypter(c, iv)
            ciphertext2 := make([]byte, len(plaintext))
            mode.XORKeyStream(ciphertext2, plaintext)

            assertNotEmpty(ciphertext2, "Test_CFB1_Check-en")
            assertEqual(ciphertext2, ciphertext, "Test_CFB1_Check-En-Equal")

            mode2 := NewCFB1Decrypter(c, iv)
            plaintext2 := make([]byte, len(ciphertext))
            mode2.XORKeyStream(plaintext2, ciphertext)

            assertNotEmpty(plaintext2, "Test_CFB1_Check-de")
            assertEqual(plaintext2, plaintext, "Test_CFB1_Check-de-Equal")
        })
    }
}

func Test_CFB8_Check(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertNoError := cryptobin_test.AssertNoErrorT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    for _, td := range testCFBDataCFB8s {
        t.Run(td.name, func(t *testing.T) {
            key := td.key
            iv := td.iv
            plaintext := td.pt
            ciphertext := td.ct

            c, err := aes.NewCipher(key)
            assertNoError(err, "Test_CFB8_Check")

            mode := NewCFB8Encrypter(c, iv)
            ciphertext2 := make([]byte, len(plaintext))
            mode.XORKeyStream(ciphertext2, plaintext)

            assertNotEmpty(ciphertext2, "Test_CFB8_Check-en")
            assertEqual(ciphertext2, ciphertext, "Test_CFB8_Check-En-Equal")

            mode2 := NewCFB8Decrypter(c, iv)
            plaintext2 := make([]byte, len(ciphertext))
            mode2.XORKeyStream(plaintext2, ciphertext)

            assertNotEmpty(plaintext2, "Test_CFB8_Check-de")
            assertEqual(plaintext2, plaintext, "Test_CFB8_Check-de-Equal")
        })
    }
}

type testCFBData struct {
    name string
    key []byte
    iv []byte
    pt []byte
    ct []byte
}

var testCFBDataCFB1s = []testCFBData{
    // aes-128-cfb1
    // openssl_encrypt($ciphertext, 'aes-128-cfb1', $key, OPENSSL_RAW_DATA, $iv)
    {
        name: "aes-128-cfb1",
        key: []byte("1234567890123456"),
        iv: []byte("1234567890123456"),
        pt: []byte("1234567890123456kjinjkijkolkdplo"),
        ct: fromHex("30e3dc321759cf32de8e61f8d8ec1f06815579015709cf431d90d1cca05d325a"),
    },
    // aes-192-cfb1
    {
        name: "aes-192-cfb1",
        key: []byte("123456789012345678123456"),
        iv: []byte("1234567890123456"),
        pt: []byte("1234567890123456kjinjkijkolkdplo"),
        ct: fromHex("44720dd655b839000c450d559352f9c28387a548aacb381558085dc58a22131c"),
    },
    // aes-256-cfb1
    {
        name: "aes-256-cfb1",
        key: []byte("12345678901234561234567890123456"),
        iv: []byte("1234567890123456"),
        pt: []byte("1234567890123456kjinjkijkolkdplo"),
        ct: fromHex("b29d0ced46b5748ca45f46b256df26599168563ddc5107fc2200a6e91c43faa5"),
    },
}

var testCFBDataCFB8s = []testCFBData{
    // aes-128-cfb8
    // openssl_encrypt($ciphertext, 'aes-128-cfb8', $key, OPENSSL_RAW_DATA, $iv)
    {
        name: "aes-128-cfb8",
        key: []byte("1234567890123456"),
        iv: []byte("1234567890123456"),
        pt: []byte("1234567890123456kjinjkijkolkdplo"),
        ct: fromHex("44c879d38fe1213291b16d4646aed6c29dd8446053b1b717b88e1a57264cbdd9"),
    },
    // aes-192-cfb8
    {
        name: "aes-192-cfb8",
        key: []byte("123456789012345678123456"),
        iv: []byte("1234567890123456"),
        pt: []byte("1234567890123456kjinjkijkolkdplo"),
        ct: fromHex("79cfca16c01c3bc03c363d6a2dafe4bac54cc1f38df5c9b7822faa83742bdf76"),
    },
    // aes-256-cfb8
    {
        name: "aes-256-cfb8",
        key: []byte("12345678901234561234567890123456"),
        iv: []byte("1234567890123456"),
        pt: []byte("1234567890123456kjinjkijkolkdplo"),
        ct: fromHex("c224e5020f80b79bff4da58e747fef1d240f315430af0863d3aceb488c4d3df7"),
    },
}
