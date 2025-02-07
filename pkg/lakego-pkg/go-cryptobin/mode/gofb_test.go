package cipher

import (
    "testing"
    "encoding/hex"

    "github.com/deatil/go-cryptobin/cipher/gost"
    cryptobin_test "github.com/deatil/go-cryptobin/tool/test"
)

func Test_GOFB(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertNoError := cryptobin_test.AssertNoErrorT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    key := []byte("kkinjkijeel22plokkinjkijeel22plo")
    iv := []byte("11injkij")
    plaintext := []byte("kjinjkijkolkdplokjinjkijkolkdplokjinjkijkolkdplokjinjkijkolkdplokjinjkijkolkdplokjinjkijkolkdplokjinjkijkolkdplokjinjkijkolkdplokjinjkijkolkdplokjinjkijkolkdplokjinjkijkolkdplokjinjkijkolkdplokjinjkijkolkdplokjinjkijkolkdplokjinjkijkolkdplokjinjkijkolkdplokjinjkijkolkdplokjinjkijkolkdplo")

    c, err := gost.NewCipher(key, gost.SboxGost2814789TestParamSet)
    assertNoError(err, "Test_GOFB-NewCipher")

    ofb := NewGOFB(c, iv)
    ciphertext := make([]byte, len(plaintext))
    ofb.XORKeyStream(ciphertext, plaintext)

    ofb2 := NewGOFB(c, iv)
    plaintext2 := make([]byte, len(ciphertext))
    ofb2.XORKeyStream(plaintext2, ciphertext)

    assertNotEmpty(plaintext2, "Test_GOFB-XORKeyStream")

    assertEqual(plaintext2, plaintext, "Test_GOFB-Equal")
}

var testGOFBSBox_1 = [][]byte{
    {0xE, 0x3, 0xC, 0xD, 0x1, 0xF, 0xA, 0x9, 0xB, 0x6, 0x2, 0x7, 0x5, 0x0, 0x8, 0x4},
    {0xD, 0x9, 0x0, 0x4, 0x7, 0x1, 0x3, 0xB, 0x6, 0xC, 0x2, 0xA, 0xF, 0xE, 0x5, 0x8},
    {0x8, 0xB, 0xA, 0x7, 0x1, 0xD, 0x5, 0xC, 0x6, 0x3, 0x9, 0x0, 0xF, 0xE, 0x2, 0x4},
    {0xD, 0x7, 0xC, 0x9, 0xF, 0x0, 0x5, 0x8, 0xA, 0x2, 0xB, 0x6, 0x4, 0x3, 0x1, 0xE},
    {0xB, 0x4, 0x6, 0x5, 0x0, 0xF, 0x1, 0xC, 0x9, 0xE, 0xD, 0x8, 0x3, 0x7, 0xA, 0x2},
    {0xD, 0xF, 0x9, 0x4, 0x2, 0xC, 0x5, 0xA, 0x6, 0x0, 0x3, 0x8, 0x7, 0xE, 0x1, 0xB},
    {0xF, 0xE, 0x9, 0x5, 0xB, 0x2, 0x1, 0x8, 0x6, 0x0, 0xD, 0x3, 0x4, 0x7, 0xC, 0xA},
    {0xA, 0x3, 0xE, 0x2, 0x0, 0x1, 0x4, 0x6, 0xB, 0x8, 0xC, 0x7, 0xD, 0x5, 0xF, 0x9},
}

func Test_GOFB_Check(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertNoError := cryptobin_test.AssertNoErrorT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    key, _ := hex.DecodeString("0A43145BA8B9E9FF0AEA67D3F26AD87854CED8D9017B3D33ED81301F90FDF993")
    iv, _ := hex.DecodeString("8001069080010690")
    plaintext, _ := hex.DecodeString("094C912C5EFDD703D42118971694580B")

    c, err := gost.NewCipher(key, testGOFBSBox_1)
    assertNoError(err, "Test_GOFB_Check-NewCipher")

    ciphertext1, _ := hex.DecodeString("2707B58DF039D1A64460735FFE76D55F")

    ofb := NewGOFB(c, iv)
    ciphertext := make([]byte, len(plaintext))
    ofb.XORKeyStream(ciphertext, plaintext)

    assertNotEmpty(ciphertext, "Test_GOFB_Check-XORKeyStream")

    assertEqual(ciphertext, ciphertext1, "Test_GOFB_Check-Equal")
}

func Test_GOFB_Check_2(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertNoError := cryptobin_test.AssertNoErrorT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    key, _ := hex.DecodeString("0A43145BA8B9E9FF0AEA67D3F26AD87854CED8D9017B3D33ED81301F90FDF993")
    iv, _ := hex.DecodeString("800107A0800107A0")
    plaintext, _ := hex.DecodeString("FE780800E0690083F20C010CF00C0329")

    c, err := gost.NewCipher(key, testGOFBSBox_1)
    assertNoError(err, "Test_GOFB_Check-NewCipher")

    ciphertext1, _ := hex.DecodeString("9AF623DFF948B413B53171E8D546188D")

    ofb := NewGOFB(c, iv)
    ciphertext := make([]byte, len(plaintext))
    ofb.XORKeyStream(ciphertext, plaintext)

    assertNotEmpty(ciphertext, "Test_GOFB_Check-XORKeyStream")

    assertEqual(ciphertext, ciphertext1, "Test_GOFB_Check-Equal")
}
