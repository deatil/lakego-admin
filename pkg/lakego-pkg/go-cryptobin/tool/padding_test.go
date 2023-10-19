package tool

import (
    // "fmt"
    "testing"

    "github.com/deatil/go-cryptobin/tool/test"
)

func Test_PKCS7Padding(t *testing.T) {
    assertError := test.AssertErrorT(t)
    assertEqual := test.AssertEqualT(t)
    assertNotEmpty := test.AssertNotEmptyT(t)

    bs := 16

    in := []byte("T002262537000")
    out := append(in, []byte{byte(3), byte(3), byte(3)}...)

    inpadding := NewPadding().PKCS7Padding(in, bs)
    assertNotEmpty(inpadding, "PKCS7Padding-padding")
    assertEqual(inpadding, out, "PKCS7Padding-padding")

    unpadding, err := NewPadding().PKCS7UnPadding(out)
    assertNotEmpty(unpadding, "PKCS7Padding-unpadding")
    assertEqual(unpadding, in, "PKCS7Padding-unpadding")

    assertError(err, "PKCS7Padding-unpadding")
}

func Test_PKCS5Padding(t *testing.T) {
    assertError := test.AssertErrorT(t)
    assertEqual := test.AssertEqualT(t)
    assertNotEmpty := test.AssertNotEmptyT(t)

    in := []byte("T002262537000")
    out := append(in, []byte{byte(3), byte(3), byte(3)}...)

    inpadding := NewPadding().PKCS5Padding(in)
    assertNotEmpty(inpadding, "PKCS5Padding-padding")
    assertEqual(inpadding, out, "PKCS5Padding-padding")

    unpadding, err := NewPadding().PKCS5UnPadding(out)
    assertNotEmpty(unpadding, "PKCS5Padding-unpadding")
    assertEqual(unpadding, in, "PKCS5Padding-unpadding")

    assertError(err, "PKCS5Padding-unpadding")
}

func Test_ZeroPadding(t *testing.T) {
    assertError := test.AssertErrorT(t)
    assertEqual := test.AssertEqualT(t)
    assertNotEmpty := test.AssertNotEmptyT(t)

    bs := 8

    in := []byte("T002262537000")
    out := append(in, []byte{byte(0), byte(0), byte(0)}...)

    inpadding := NewPadding().ZeroPadding(in, bs)
    assertNotEmpty(inpadding, "ZeroPadding-padding")
    assertEqual(inpadding, out, "ZeroPadding-padding")

    unpadding, err := NewPadding().ZeroUnPadding(out)
    assertNotEmpty(unpadding, "ZeroPadding-unpadding")
    assertEqual(unpadding, in, "ZeroPadding-unpadding")

    assertError(err, "ZeroPadding-unpadding")
}

func Test_ISO97971Padding(t *testing.T) {
    assertError := test.AssertErrorT(t)
    assertEqual := test.AssertEqualT(t)
    assertNotEmpty := test.AssertNotEmptyT(t)

    bs := 8

    in := []byte("T002262537000")
    out := append(in, []byte{byte(128), byte(0), byte(0)}...)

    inpadding := NewPadding().ISO97971Padding(in, bs)
    assertNotEmpty(inpadding, "ISO97971Padding-padding")
    assertEqual(inpadding, out, "ISO97971Padding-padding")

    unpadding, err := NewPadding().ISO97971UnPadding(out)
    assertNotEmpty(unpadding, "ISO97971Padding-unpadding")
    assertEqual(unpadding, in, "ISO97971Padding-unpadding")

    assertError(err, "ISO97971Padding-unpadding")
}

func Test_PBOC2Padding(t *testing.T) {
    assertError := test.AssertErrorT(t)
    assertEqual := test.AssertEqualT(t)
    assertNotEmpty := test.AssertNotEmptyT(t)

    bs := 8

    in := []byte("T002262537000")
    out := append(in, []byte{byte(128), byte(0), byte(0)}...)

    inpadding := NewPadding().PBOC2Padding(in, bs)
    assertNotEmpty(inpadding, "PBOC2Padding-padding")
    assertEqual(inpadding, out, "PBOC2Padding-padding")

    unpadding, err := NewPadding().PBOC2UnPadding(out)
    assertNotEmpty(unpadding, "PBOC2Padding-unpadding")
    assertEqual(unpadding, in, "PBOC2Padding-unpadding")

    assertError(err, "PBOC2Padding-unpadding")
}

func Test_X923Padding(t *testing.T) {
    assertError := test.AssertErrorT(t)
    assertEqual := test.AssertEqualT(t)
    assertNotEmpty := test.AssertNotEmptyT(t)

    bs := 8

    in := []byte("T002262537000")
    out := append(in, []byte{byte(0), byte(0), byte(3)}...)

    inpadding := NewPadding().X923Padding(in, bs)
    assertNotEmpty(inpadding, "X923Padding-padding")
    assertEqual(inpadding, out, "X923Padding-padding")

    unpadding, err := NewPadding().X923UnPadding(out)
    assertNotEmpty(unpadding, "X923Padding-unpadding")
    assertEqual(unpadding, in, "X923Padding-unpadding")

    assertError(err, "X923Padding-unpadding")
}

func Test_ISO10126Padding(t *testing.T) {
    assertError := test.AssertErrorT(t)
    assertEqual := test.AssertEqualT(t)
    assertNotEmpty := test.AssertNotEmptyT(t)

    bs := 8

    in := []byte("T002262537000")

    inpadding := NewPadding().ISO10126Padding(in, bs)
    assertNotEmpty(inpadding, "ISO10126Padding-padding")

    unpadding, err := NewPadding().ISO10126UnPadding(inpadding)
    assertNotEmpty(unpadding, "ISO10126Padding-unpadding")

    assertEqual(unpadding, in, "ISO10126Padding-unpadding")

    assertError(err, "ISO10126Padding-unpadding")
}

func Test_ISO7816_4Padding(t *testing.T) {
    assertError := test.AssertErrorT(t)
    assertEqual := test.AssertEqualT(t)
    assertNotEmpty := test.AssertNotEmptyT(t)

    bs := 8

    in := []byte("T002262537000")
    out := append(in, []byte{0x80, 0x00, 0x00}...)

    inpadding := NewPadding().ISO7816_4Padding(in, bs)
    assertNotEmpty(inpadding, "ISO7816_4Padding-padding")
    assertEqual(inpadding, out, "ISO7816_4Padding-padding")

    unpadding, err := NewPadding().ISO7816_4UnPadding(out)
    assertNotEmpty(unpadding, "ISO7816_4Padding-unpadding")
    assertEqual(unpadding, in, "ISO7816_4Padding-unpadding")

    assertError(err, "ISO7816_4Padding-unpadding")
}

func Test_TBCPadding(t *testing.T) {
    assertError := test.AssertErrorT(t)
    assertEqual := test.AssertEqualT(t)
    assertNotEmpty := test.AssertNotEmptyT(t)

    bs := 8

    in := []byte("T002262537000")
    out := append(in, []byte{0xFF, 0xFF, 0xFF}...)

    inpadding := NewPadding().TBCPadding(in, bs)
    assertNotEmpty(inpadding, "TBCPadding-padding")
    assertEqual(inpadding, out, "TBCPadding-padding")

    unpadding, err := NewPadding().TBCUnPadding(out)
    assertNotEmpty(unpadding, "TBCPadding-unpadding")
    assertEqual(unpadding, in, "TBCPadding-unpadding")

    assertError(err, "TBCPadding-unpadding")
}

func Test_TBCPadding_2(t *testing.T) {
    assertError := test.AssertErrorT(t)
    assertEqual := test.AssertEqualT(t)
    assertNotEmpty := test.AssertNotEmptyT(t)

    bs := 8

    in := []byte("T002262537001")
    out := append(in, []byte{0x00, 0x00, 0x00}...)

    inpadding := NewPadding().TBCPadding(in, bs)
    assertNotEmpty(inpadding, "TBCPadding_2-padding")
    assertEqual(inpadding, out, "TBCPadding_2-padding")

    unpadding, err := NewPadding().TBCUnPadding(out)
    assertNotEmpty(unpadding, "TBCPadding_2-unpadding")
    assertEqual(unpadding, in, "TBCPadding_2-unpadding")

    assertError(err, "TBCPadding_2-unpadding")
}

func Test_PKCS1Padding(t *testing.T) {
    assertError := test.AssertErrorT(t)
    assertEqual := test.AssertEqualT(t)
    assertNotEmpty := test.AssertNotEmptyT(t)

    bs := 28 // 28 - 3 - 13 = 12
    bt := "00" // 00 | 01 | 02

    in := []byte("T002262537001")

    inpadding := NewPadding().PKCS1Padding(in, bs, bt)
    assertNotEmpty(inpadding, "PKCS1Padding-padding")

    unpadding, err := NewPadding().PKCS1UnPadding(inpadding)
    assertNotEmpty(unpadding, "PKCS1Padding-unpadding")

    assertEqual(unpadding, in, "PKCS1Padding-unpadding")

    assertError(err, "PKCS1Padding-unpadding")

    // fmt.Println(inpadding)
    // assertEqual(unpadding, "123", "PKCS1Padding-unpadding")
}
