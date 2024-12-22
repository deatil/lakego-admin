package padding

import (
    "testing"
    "reflect"

    "github.com/deatil/go-cryptobin/tool/test"
)

func Test_Interface(t *testing.T) {
    var _ Padding = NewPKCS7()
    var _ Padding = NewPKCS5()
    var _ Padding = NewZero()
    var _ Padding = NewISO97971()
    var _ Padding = NewPBOC2()
    var _ Padding = NewX923()
    var _ Padding = NewISO10126()
    var _ Padding = NewISO7816_4()
    var _ Padding = NewTBC()
    var _ Padding = NewPKCS1("00")
}

func Test_PKCS7Padding(t *testing.T) {
    assertError := test.AssertErrorT(t)
    assertEqual := test.AssertEqualT(t)
    assertNotEmpty := test.AssertNotEmptyT(t)

    bs := 16

    in := []byte("T002262537000")
    out := append(in, []byte{byte(3), byte(3), byte(3)}...)

    inpadding := NewPKCS7().Padding(in, bs)
    assertNotEmpty(inpadding, "PKCS7Padding-padding")
    assertEqual(inpadding, out, "PKCS7Padding-padding")

    unpadding, err := NewPKCS7().UnPadding(out)
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

    inpadding := NewPKCS5().Padding(in, 8)
    assertNotEmpty(inpadding, "PKCS5Padding-padding")
    assertEqual(inpadding, out, "PKCS5Padding-padding")

    unpadding, err := NewPKCS5().UnPadding(out)
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

    inpadding := NewZero().Padding(in, bs)
    assertNotEmpty(inpadding, "ZeroPadding-padding")
    assertEqual(inpadding, out, "ZeroPadding-padding")

    unpadding, err := NewZero().UnPadding(out)
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

    inpadding := NewISO97971().Padding(in, bs)
    assertNotEmpty(inpadding, "ISO97971Padding-padding")
    assertEqual(inpadding, out, "ISO97971Padding-padding")

    unpadding, err := NewISO97971().UnPadding(out)
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

    inpadding := NewPBOC2().Padding(in, bs)
    assertNotEmpty(inpadding, "PBOC2Padding-padding")
    assertEqual(inpadding, out, "PBOC2Padding-padding")

    unpadding, err := NewPBOC2().UnPadding(out)
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

    inpadding := NewX923().Padding(in, bs)
    assertNotEmpty(inpadding, "X923Padding-padding")
    assertEqual(inpadding, out, "X923Padding-padding")

    unpadding, err := NewX923().UnPadding(out)
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

    inpadding := NewISO10126().Padding(in, bs)
    assertNotEmpty(inpadding, "ISO10126Padding-padding")

    unpadding, err := NewISO10126().UnPadding(inpadding)
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

    inpadding := NewISO7816_4().Padding(in, bs)
    assertNotEmpty(inpadding, "ISO7816_4Padding-padding")
    assertEqual(inpadding, out, "ISO7816_4Padding-padding")

    unpadding, err := NewISO7816_4().UnPadding(out)
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

    inpadding := NewTBC().Padding(in, bs)
    assertNotEmpty(inpadding, "TBCPadding-padding")
    assertEqual(inpadding, out, "TBCPadding-padding")

    unpadding, err := NewTBC().UnPadding(out)
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

    inpadding := NewTBC().Padding(in, bs)
    assertNotEmpty(inpadding, "TBCPadding_2-padding")
    assertEqual(inpadding, out, "TBCPadding_2-padding")

    unpadding, err := NewTBC().UnPadding(out)
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

    inpadding := NewPKCS1(bt).Padding(in, bs)
    assertNotEmpty(inpadding, "PKCS1Padding-padding")

    unpadding, err := NewPKCS1(bt).UnPadding(inpadding)
    assertNotEmpty(unpadding, "PKCS1Padding-unpadding")

    assertEqual(unpadding, in, "PKCS1Padding-unpadding")

    assertError(err, "PKCS1Padding-unpadding")

    // fmt.Println(inpadding)
    // assertEqual(unpadding, "123", "PKCS1Padding-unpadding")
}

func Test_ISO97971_Pad(t *testing.T) {
    iso9797 := NewISO97971()

    tests := []struct {
        name string
        src  []byte
        want []byte
    }{
        {"16 bytes", []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
        {"15 bytes", []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14}, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 0x80}},
        {"14 bytes", []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13}, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 0x80, 0}},
        {"13 bytes", []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 0x80, 0, 0}},
        {"12 bytes", []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11}, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x80, 0, 0, 0}},
        {"11 bytes", []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10}, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 0x80, 0, 0, 0, 0}},
        {"10 bytes", []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0x80, 0, 0, 0, 0, 0}},
        {"9 bytes", []byte{0, 1, 2, 3, 4, 5, 6, 7, 8}, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 0x80, 0, 0, 0, 0, 0, 0}},
        {"8 bytes", []byte{0, 1, 2, 3, 4, 5, 6, 7}, []byte{0, 1, 2, 3, 4, 5, 6, 7, 0x80, 0, 0, 0, 0, 0, 0, 0}},
        {"7 bytes", []byte{0, 1, 2, 3, 4, 5, 6}, []byte{0, 1, 2, 3, 4, 5, 6, 0x80, 0, 0, 0, 0, 0, 0, 0, 0}},
        {"6 bytes", []byte{0, 1, 2, 3, 4, 5}, []byte{0, 1, 2, 3, 4, 5, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
        {"5 bytes", []byte{0, 1, 2, 3, 4}, []byte{0, 1, 2, 3, 4, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
        {"4 bytes", []byte{0, 1, 2, 3}, []byte{0, 1, 2, 3, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
        {"3 bytes", []byte{0, 1, 2}, []byte{0, 1, 2, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
        {"2 bytes", []byte{0, 1}, []byte{0, 1, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
        {"1 bytes", []byte{0}, []byte{0, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
        {"0 bytes", []byte{}, []byte{0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            if got := iso9797.Padding(tt.src, 16); !reflect.DeepEqual(got, tt.want) {
                t.Errorf("ISO97971.Padding() = %v, want %v", got, tt.want)
            }
        })
    }
}

func Test_ISO97971_Unpad(t *testing.T) {
    iso9797 := NewISO97971()

    tests := []struct {
        name    string
        want    []byte
        src     []byte
        wantErr bool
    }{
        {"16 bytes", []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, false},
        {"15 bytes", []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14}, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 0x80}, false},
        {"14 bytes", []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13}, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 0x80, 0}, false},
        {"13 bytes", []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 0x80, 0, 0}, false},
        {"12 bytes", []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11}, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x80, 0, 0, 0}, false},
        {"11 bytes", []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10}, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 0x80, 0, 0, 0, 0}, false},
        {"10 bytes", []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0x80, 0, 0, 0, 0, 0}, false},
        {"9 bytes", []byte{0, 1, 2, 3, 4, 5, 6, 7, 8}, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 0x80, 0, 0, 0, 0, 0, 0}, false},
        {"8 bytes", []byte{0, 1, 2, 3, 4, 5, 6, 7}, []byte{0, 1, 2, 3, 4, 5, 6, 7, 0x80, 0, 0, 0, 0, 0, 0, 0}, false},
        {"7 bytes", []byte{0, 1, 2, 3, 4, 5, 6}, []byte{0, 1, 2, 3, 4, 5, 6, 0x80, 0, 0, 0, 0, 0, 0, 0, 0}, false},
        {"6 bytes", []byte{0, 1, 2, 3, 4, 5}, []byte{0, 1, 2, 3, 4, 5, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0}, false},
        {"5 bytes", []byte{0, 1, 2, 3, 4}, []byte{0, 1, 2, 3, 4, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, false},
        {"4 bytes", []byte{0, 1, 2, 3}, []byte{0, 1, 2, 3, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, false},
        {"3 bytes", []byte{0, 1, 2}, []byte{0, 1, 2, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, false},
        {"2 bytes", []byte{0, 1}, []byte{0, 1, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, false},
        {"1 bytes", []byte{0}, []byte{0, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, false},
        {"0 bytes", []byte{}, []byte{0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, false},

        {"1 bytes with tag", []byte{0x80}, []byte{0x80, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, false},
        {"3 bytes with tag", []byte{0x80, 0, 0x80}, []byte{0x80, 0, 0x80, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, false},
        {"19 bytes with tag", []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 0x80, 0, 0x80}, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 0x80, 0, 0x80, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, false},
        {"invalid src length", nil, []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, true},
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            got, err := iso9797.UnPadding(tt.src)
            if (err != nil) != tt.wantErr {
                t.Errorf("case %v: ISO97971.UnPadding() error = %v, wantErr %v", tt.name, err, tt.wantErr)
                return
            }

            if !reflect.DeepEqual(got, tt.want) {
                t.Errorf("case %v: ISO97971.UnPadding() = %#v, want %#v", tt.name, got, tt.want)
            }
        })
    }
}

func Test_X923_Pad(t *testing.T) {
    x923 := NewX923()

    tests := []struct {
        name string
        src  []byte
        want []byte
    }{
        {"16 bytes", []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 16}},
        {"15 bytes", []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14}, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 1}},
        {"14 bytes", []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13}, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 0, 2}},
        {"13 bytes", []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 0, 0, 3}},
        {"12 bytes", []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11}, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0, 0, 0, 4}},
        {"11 bytes", []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10}, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 0, 0, 0, 0, 5}},
        {"10 bytes", []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 0, 0, 0, 0, 6}},
        {"9 bytes", []byte{0, 1, 2, 3, 4, 5, 6, 7, 8}, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, 0, 0, 0, 7}},
        {"8 bytes", []byte{0, 1, 2, 3, 4, 5, 6, 7}, []byte{0, 1, 2, 3, 4, 5, 6, 7, 0, 0, 0, 0, 0, 0, 0, 8}},
        {"7 bytes", []byte{0, 1, 2, 3, 4, 5, 6}, []byte{0, 1, 2, 3, 4, 5, 6, 0, 0, 0, 0, 0, 0, 0, 0, 9}},
        {"6 bytes", []byte{0, 1, 2, 3, 4, 5}, []byte{0, 1, 2, 3, 4, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10}},
        {"5 bytes", []byte{0, 1, 2, 3, 4}, []byte{0, 1, 2, 3, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 11}},
        {"4 bytes", []byte{0, 1, 2, 3}, []byte{0, 1, 2, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 12}},
        {"3 bytes", []byte{0, 1, 2}, []byte{0, 1, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 13}},
        {"2 bytes", []byte{0, 1}, []byte{0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 14}},
        {"1 bytes", []byte{0}, []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 15}},
        {"0 bytes", []byte{}, []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 16}},
    }
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            if got := x923.Padding(tt.src, 16); !reflect.DeepEqual(got, tt.want) {
                t.Errorf("ansiX923Padding.Padding() = %v, want %v", got, tt.want)
            }
        })
    }
}

func Test_X923_Unpad(t *testing.T) {
    x923 := NewX923()

    tests := []struct {
        name    string
        want    []byte
        src     []byte
        wantErr bool
    }{
        {"16 bytes", []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 16}, false},
        {"15 bytes", []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14}, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 1}, false},
        {"14 bytes", []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13}, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 0, 2}, false},
        {"13 bytes", []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 0, 0, 3}, false},
        {"12 bytes", []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11}, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0, 0, 0, 4}, false},
        {"11 bytes", []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10}, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 0, 0, 0, 0, 5}, false},
        {"10 bytes", []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 0, 0, 0, 0, 6}, false},
        {"9 bytes", []byte{0, 1, 2, 3, 4, 5, 6, 7, 8}, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, 0, 0, 0, 7}, false},
        {"8 bytes", []byte{0, 1, 2, 3, 4, 5, 6, 7}, []byte{0, 1, 2, 3, 4, 5, 6, 7, 0, 0, 0, 0, 0, 0, 0, 8}, false},
        {"7 bytes", []byte{0, 1, 2, 3, 4, 5, 6}, []byte{0, 1, 2, 3, 4, 5, 6, 0, 0, 0, 0, 0, 0, 0, 0, 9}, false},
        {"6 bytes", []byte{0, 1, 2, 3, 4, 5}, []byte{0, 1, 2, 3, 4, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10}, false},
        {"5 bytes", []byte{0, 1, 2, 3, 4}, []byte{0, 1, 2, 3, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 11}, false},
        {"4 bytes", []byte{0, 1, 2, 3}, []byte{0, 1, 2, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 12}, false},
        {"3 bytes", []byte{0, 1, 2}, []byte{0, 1, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 13}, false},
        {"2 bytes", []byte{0, 1}, []byte{0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 14}, false},
        {"1 bytes", []byte{2}, []byte{2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 15}, false},
        {"0 bytes", []byte{}, []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 16}, false},

        // {"invalid src length", nil, []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 15}, true},
        {"invalid padding length", nil, []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 17}, true},
        {"invalid padding bytes", nil, []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 14, 15}, true},
    }
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            got, err := x923.UnPadding(tt.src)
            if (err != nil) != tt.wantErr {
                t.Errorf("ansiX923Padding.UnPadding() error = %v, wantErr %v", err, tt.wantErr)
                return
            }

            if !reflect.DeepEqual(got, tt.want) {
                t.Errorf("ansiX923Padding.UnPadding() = %#v, want %#v", got, tt.want)
            }
        })
    }
}

func Test_ISO7816_4_Pad(t *testing.T) {
    iso9797 := NewISO7816_4()

    tests := []struct {
        name string
        src  []byte
        want []byte
    }{
        {"16 bytes", []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
        {"15 bytes", []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14}, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 0x80}},
        {"14 bytes", []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13}, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 0x80, 0}},
        {"13 bytes", []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 0x80, 0, 0}},
        {"12 bytes", []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11}, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x80, 0, 0, 0}},
        {"11 bytes", []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10}, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 0x80, 0, 0, 0, 0}},
        {"10 bytes", []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0x80, 0, 0, 0, 0, 0}},
        {"9 bytes", []byte{0, 1, 2, 3, 4, 5, 6, 7, 8}, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 0x80, 0, 0, 0, 0, 0, 0}},
        {"8 bytes", []byte{0, 1, 2, 3, 4, 5, 6, 7}, []byte{0, 1, 2, 3, 4, 5, 6, 7, 0x80, 0, 0, 0, 0, 0, 0, 0}},
        {"7 bytes", []byte{0, 1, 2, 3, 4, 5, 6}, []byte{0, 1, 2, 3, 4, 5, 6, 0x80, 0, 0, 0, 0, 0, 0, 0, 0}},
        {"6 bytes", []byte{0, 1, 2, 3, 4, 5}, []byte{0, 1, 2, 3, 4, 5, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
        {"5 bytes", []byte{0, 1, 2, 3, 4}, []byte{0, 1, 2, 3, 4, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
        {"4 bytes", []byte{0, 1, 2, 3}, []byte{0, 1, 2, 3, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
        {"3 bytes", []byte{0, 1, 2}, []byte{0, 1, 2, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
        {"2 bytes", []byte{0, 1}, []byte{0, 1, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
        {"1 bytes", []byte{0}, []byte{0, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
        {"0 bytes", []byte{}, []byte{0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            if got := iso9797.Padding(tt.src, 16); !reflect.DeepEqual(got, tt.want) {
                t.Errorf("ISO97971.Padding() = %v, want %v", got, tt.want)
            }
        })
    }
}

func Test_ISO7816_4_Unpad(t *testing.T) {
    iso9797 := NewISO7816_4()

    tests := []struct {
        name    string
        want    []byte
        src     []byte
        wantErr bool
    }{
        {"16 bytes", []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, false},
        {"15 bytes", []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14}, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 0x80}, false},
        {"14 bytes", []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13}, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 0x80, 0}, false},
        {"13 bytes", []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 0x80, 0, 0}, false},
        {"12 bytes", []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11}, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x80, 0, 0, 0}, false},
        {"11 bytes", []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10}, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 0x80, 0, 0, 0, 0}, false},
        {"10 bytes", []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0x80, 0, 0, 0, 0, 0}, false},
        {"9 bytes", []byte{0, 1, 2, 3, 4, 5, 6, 7, 8}, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 0x80, 0, 0, 0, 0, 0, 0}, false},
        {"8 bytes", []byte{0, 1, 2, 3, 4, 5, 6, 7}, []byte{0, 1, 2, 3, 4, 5, 6, 7, 0x80, 0, 0, 0, 0, 0, 0, 0}, false},
        {"7 bytes", []byte{0, 1, 2, 3, 4, 5, 6}, []byte{0, 1, 2, 3, 4, 5, 6, 0x80, 0, 0, 0, 0, 0, 0, 0, 0}, false},
        {"6 bytes", []byte{0, 1, 2, 3, 4, 5}, []byte{0, 1, 2, 3, 4, 5, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0}, false},
        {"5 bytes", []byte{0, 1, 2, 3, 4}, []byte{0, 1, 2, 3, 4, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, false},
        {"4 bytes", []byte{0, 1, 2, 3}, []byte{0, 1, 2, 3, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, false},
        {"3 bytes", []byte{0, 1, 2}, []byte{0, 1, 2, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, false},
        {"2 bytes", []byte{0, 1}, []byte{0, 1, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, false},
        {"1 bytes", []byte{0}, []byte{0, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, false},
        {"0 bytes", []byte{}, []byte{0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, false},

        {"1 bytes with tag", []byte{0x80}, []byte{0x80, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, false},
        {"3 bytes with tag", []byte{0x80, 0, 0x80}, []byte{0x80, 0, 0x80, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, false},
        {"19 bytes with tag", []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 0x80, 0, 0x80}, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 0x80, 0, 0x80, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, false},
        {"invalid src length", nil, []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, true},
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            got, err := iso9797.UnPadding(tt.src)
            if (err != nil) != tt.wantErr {
                t.Errorf("case %v: ISO97971.UnPadding() error = %v, wantErr %v", tt.name, err, tt.wantErr)
                return
            }

            if !reflect.DeepEqual(got, tt.want) {
                t.Errorf("case %v: ISO97971.UnPadding() = %#v, want %#v", tt.name, got, tt.want)
            }
        })
    }
}

func Test_PKCS7_Pad(t *testing.T) {
    pkcs7 := NewPKCS7()

    tests := []struct {
        name string
        src  []byte
        want []byte
    }{
        {"16 bytes", []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16}},
        {"15 bytes", []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14}, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 1}},
        {"14 bytes", []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13}, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 2, 2}},
        {"13 bytes", []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 3, 3, 3}},
        {"12 bytes", []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11}, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 4, 4, 4, 4}},
        {"11 bytes", []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10}, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 5, 5, 5, 5, 5}},
        {"10 bytes", []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 6, 6, 6, 6, 6, 6}},
        {"9 bytes", []byte{0, 1, 2, 3, 4, 5, 6, 7, 8}, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 7, 7, 7, 7, 7, 7, 7}},
        {"8 bytes", []byte{0, 1, 2, 3, 4, 5, 6, 7}, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 8, 8, 8, 8, 8, 8, 8}},
        {"7 bytes", []byte{0, 1, 2, 3, 4, 5, 6}, []byte{0, 1, 2, 3, 4, 5, 6, 9, 9, 9, 9, 9, 9, 9, 9, 9}},
        {"6 bytes", []byte{0, 1, 2, 3, 4, 5}, []byte{0, 1, 2, 3, 4, 5, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10}},
        {"5 bytes", []byte{0, 1, 2, 3, 4}, []byte{0, 1, 2, 3, 4, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11}},
        {"4 bytes", []byte{0, 1, 2, 3}, []byte{0, 1, 2, 3, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12}},
        {"3 bytes", []byte{0, 1, 2}, []byte{0, 1, 2, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13}},
        {"2 bytes", []byte{0, 1}, []byte{0, 1, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14}},
        {"1 bytes", []byte{0}, []byte{0, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15}},
        {"0 bytes", []byte{}, []byte{16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16}},
    }
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            if got := pkcs7.Padding(tt.src, 16); !reflect.DeepEqual(got, tt.want) {
                t.Errorf("PKCS7.Padding() = %v, want %v", got, tt.want)
            }
        })
    }
}

func Test_PKCS7_Unpad(t *testing.T) {
    pkcs7 := NewPKCS7()
    tests := []struct {
        name    string
        want    []byte
        src     []byte
        wantErr bool
    }{
        {"16 bytes", []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16}, false},
        {"15 bytes", []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14}, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 1}, false},
        {"14 bytes", []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13}, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 2, 2}, false},
        {"13 bytes", []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 3, 3, 3}, false},
        {"12 bytes", []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11}, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 4, 4, 4, 4}, false},
        {"11 bytes", []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10}, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 5, 5, 5, 5, 5}, false},
        {"10 bytes", []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 6, 6, 6, 6, 6, 6}, false},
        {"9 bytes", []byte{0, 1, 2, 3, 4, 5, 6, 7, 8}, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 7, 7, 7, 7, 7, 7, 7}, false},
        {"8 bytes", []byte{0, 1, 2, 3, 4, 5, 6, 7}, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 8, 8, 8, 8, 8, 8, 8}, false},
        {"7 bytes", []byte{0, 1, 2, 3, 4, 5, 6}, []byte{0, 1, 2, 3, 4, 5, 6, 9, 9, 9, 9, 9, 9, 9, 9, 9}, false},
        {"6 bytes", []byte{0, 1, 2, 3, 4, 5}, []byte{0, 1, 2, 3, 4, 5, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10}, false},
        {"5 bytes", []byte{0, 1, 2, 3, 4}, []byte{0, 1, 2, 3, 4, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11}, false},
        {"4 bytes", []byte{0, 1, 2, 3}, []byte{0, 1, 2, 3, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12}, false},
        {"3 bytes", []byte{0, 1, 2}, []byte{0, 1, 2, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13}, false},
        {"2 bytes", []byte{0, 1}, []byte{0, 1, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14}, false},
        {"1 bytes", []byte{0}, []byte{0, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15}, false},
        {"0 bytes", []byte{}, []byte{16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16}, false},

        {"invalid src length", nil, []byte{0, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15}, true},
        {"invalid padding byte", nil, []byte{0, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 17}, true},
        {"inconsistent padding bytes", nil, []byte{0, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 14, 15}, true},
    }
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            got, err := pkcs7.UnPadding(tt.src)
            if (err != nil) != tt.wantErr {
                t.Errorf("PKCS7.UnPadding() error = %v, wantErr %v", err, tt.wantErr)
                return
            }

            if !reflect.DeepEqual(got, tt.want) {
                t.Errorf("PKCS7.UnPadding() = %#v, want %#v", got, tt.want)
            }
        })
    }
}

func Test_PKCS5_Pad(t *testing.T) {
    pkcs5 := NewPKCS5()

    tests := []struct {
        name string
        src  []byte
        want []byte
    }{
        {"8 bytes", []byte{0, 1, 2, 3, 4, 5, 6, 7}, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 8, 8, 8, 8, 8, 8, 8}},
        {"7 bytes", []byte{0, 1, 2, 3, 4, 5, 6}, []byte{0, 1, 2, 3, 4, 5, 6, 1}},
        {"6 bytes", []byte{0, 1, 2, 3, 4, 5}, []byte{0, 1, 2, 3, 4, 5, 2, 2}},
        {"5 bytes", []byte{0, 1, 2, 3, 4}, []byte{0, 1, 2, 3, 4, 3, 3, 3}},
        {"4 bytes", []byte{0, 1, 2, 3}, []byte{0, 1, 2, 3, 4, 4, 4, 4}},
        {"3 bytes", []byte{0, 1, 2}, []byte{0, 1, 2, 5, 5, 5, 5, 5}},
        {"2 bytes", []byte{0, 1}, []byte{0, 1, 6, 6, 6, 6, 6, 6}},
        {"1 bytes", []byte{0}, []byte{0, 7, 7, 7, 7, 7, 7, 7}},
        {"0 bytes", []byte{}, []byte{8, 8, 8, 8, 8, 8, 8, 8}},
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            if got := pkcs5.Padding(tt.src, 8); !reflect.DeepEqual(got, tt.want) {
                t.Errorf("PKCS5.Padding() = %v, want %v", got, tt.want)
            }
        })
    }
}

func Test_PKCS5_Unpad(t *testing.T) {
    pkcs5 := NewPKCS5()

    tests := []struct {
        name    string
        want    []byte
        src     []byte
        wantErr bool
    }{
        {"8 bytes", []byte{0, 1, 2, 3, 4, 5, 6, 7}, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 8, 8, 8, 8, 8, 8, 8}, false},
        {"7 bytes", []byte{0, 1, 2, 3, 4, 5, 6}, []byte{0, 1, 2, 3, 4, 5, 6, 1}, false},
        {"6 bytes", []byte{0, 1, 2, 3, 4, 5}, []byte{0, 1, 2, 3, 4, 5, 2, 2}, false},
        {"5 bytes", []byte{0, 1, 2, 3, 4}, []byte{0, 1, 2, 3, 4, 3, 3, 3}, false},
        {"4 bytes", []byte{0, 1, 2, 3}, []byte{0, 1, 2, 3, 4, 4, 4, 4}, false},
        {"3 bytes", []byte{0, 1, 2}, []byte{0, 1, 2, 5, 5, 5, 5, 5}, false},
        {"2 bytes", []byte{0, 1}, []byte{0, 1, 6, 6, 6, 6, 6, 6}, false},
        {"1 bytes", []byte{0}, []byte{0, 7, 7, 7, 7, 7, 7, 7}, false},
        {"0 bytes", []byte{}, []byte{8, 8, 8, 8, 8, 8, 8, 8}, false},

        {"invalid src length", nil, []byte{0, 7, 7, 7, 7, 7, 7}, true},
        {"invalid padding byte", nil, []byte{0, 7, 7, 7, 7, 7, 7, 8}, true},
        {"inconsistent padding bytes", nil, []byte{0, 7, 7, 7, 7, 7, 6, 7}, true},
    }
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            got, err := pkcs5.UnPadding(tt.src)
            if (err != nil) != tt.wantErr {
                t.Errorf("PKCS5.UnPadding() error = %v, wantErr %v", err, tt.wantErr)
                return
            }

            if !reflect.DeepEqual(got, tt.want) {
                t.Errorf("PKCS5.UnPadding() = %#v, want %#v", got, tt.want)
            }
        })
    }
}

func Test_Zero_Pad(t *testing.T) {
    zero := NewZero()

    tests := []struct {
        name string
        src  []byte
        want []byte
    }{
        {"16 bytes", []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
        {"15 bytes", []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14}, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 0}},
        {"14 bytes", []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13}, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 0, 0}},
        {"13 bytes", []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 0, 0, 0}},
        {"12 bytes", []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11}, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0, 0, 0, 0}},
        {"11 bytes", []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10}, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 0, 0, 0, 0, 0}},
        {"10 bytes", []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 0, 0, 0, 0, 0}},
        {"9 bytes", []byte{0, 1, 2, 3, 4, 5, 6, 7, 8}, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, 0, 0, 0, 0}},
        {"8 bytes", []byte{0, 1, 2, 3, 4, 5, 6, 7}, []byte{0, 1, 2, 3, 4, 5, 6, 7, 0, 0, 0, 0, 0, 0, 0, 0}},
        {"7 bytes", []byte{0, 1, 2, 3, 4, 5, 6}, []byte{0, 1, 2, 3, 4, 5, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
        {"6 bytes", []byte{0, 1, 2, 3, 4, 5}, []byte{0, 1, 2, 3, 4, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
        {"5 bytes", []byte{0, 1, 2, 3, 4}, []byte{0, 1, 2, 3, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
        {"4 bytes", []byte{0, 1, 2, 3}, []byte{0, 1, 2, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
        {"3 bytes", []byte{0, 1, 2}, []byte{0, 1, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
        {"2 bytes", []byte{0, 1}, []byte{0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
        {"1 bytes", []byte{0}, []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
        {"0 bytes", []byte{}, []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
    }
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            if got := zero.Padding(tt.src, 16); !reflect.DeepEqual(got, tt.want) {
                t.Errorf("Zero.Padding() = %v, want %v", got, tt.want)
            }
        })
    }
}

func Test_Zero_Unpad(t *testing.T) {
    zero := NewZero()

    tests := []struct {
        name    string
        want    []byte
        src     []byte
        wantErr bool
    }{
        {"16 bytes", []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, false},
        {"15 bytes", []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14}, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 0}, false},
        {"14 bytes", []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13}, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 0, 0}, false},
        {"13 bytes", []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 0, 0, 0}, false},
        {"12 bytes", []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11}, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0, 0, 0, 0}, false},
        {"11 bytes", []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10}, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 0, 0, 0, 0, 0}, false},
        {"10 bytes", []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 0, 0, 0, 0, 0}, false},
        {"9 bytes", []byte{0, 1, 2, 3, 4, 5, 6, 7, 8}, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, 0, 0, 0, 0}, false},
        {"8 bytes", []byte{0, 1, 2, 3, 4, 5, 6, 7}, []byte{0, 1, 2, 3, 4, 5, 6, 7, 0, 0, 0, 0, 0, 0, 0, 0}, false},
        {"7 bytes", []byte{0, 1, 2, 3, 4, 5, 6}, []byte{0, 1, 2, 3, 4, 5, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0}, false},
        {"6 bytes", []byte{0, 1, 2, 3, 4, 5}, []byte{0, 1, 2, 3, 4, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, false},
        {"5 bytes", []byte{0, 1, 2, 3, 4}, []byte{0, 1, 2, 3, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, false},
        {"4 bytes", []byte{0, 1, 2, 3}, []byte{0, 1, 2, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, false},
        {"3 bytes", []byte{0, 1, 2}, []byte{0, 1, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, false},
        {"2 bytes", []byte{0, 1}, []byte{0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, false},
        {"1 bytes", []byte{1}, []byte{1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, false},
        {"0 bytes", []byte{}, []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, false},
    }
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            got, err := zero.UnPadding(tt.src)
            if (err != nil) != tt.wantErr {
                t.Errorf("Zero.UnPadding() error = %v, wantErr %v", err, tt.wantErr)
                return
            }

            if !reflect.DeepEqual(got, tt.want) {
                t.Errorf("Zero.UnPadding() = %#v, want %#v", got, tt.want)
            }
        })
    }
}

func Test_PBOC2_Pad(t *testing.T) {
    pboc2 := NewPBOC2()

    tests := []struct {
        name string
        src  []byte
        want []byte
    }{
        {"16 bytes", []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
        {"15 bytes", []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14}, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 0x80}},
        {"14 bytes", []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13}, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 0x80, 0}},
        {"13 bytes", []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 0x80, 0, 0}},
        {"12 bytes", []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11}, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x80, 0, 0, 0}},
        {"11 bytes", []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10}, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 0x80, 0, 0, 0, 0}},
        {"10 bytes", []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0x80, 0, 0, 0, 0, 0}},
        {"9 bytes", []byte{0, 1, 2, 3, 4, 5, 6, 7, 8}, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 0x80, 0, 0, 0, 0, 0, 0}},
        {"8 bytes", []byte{0, 1, 2, 3, 4, 5, 6, 7}, []byte{0, 1, 2, 3, 4, 5, 6, 7, 0x80, 0, 0, 0, 0, 0, 0, 0}},
        {"7 bytes", []byte{0, 1, 2, 3, 4, 5, 6}, []byte{0, 1, 2, 3, 4, 5, 6, 0x80, 0, 0, 0, 0, 0, 0, 0, 0}},
        {"6 bytes", []byte{0, 1, 2, 3, 4, 5}, []byte{0, 1, 2, 3, 4, 5, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
        {"5 bytes", []byte{0, 1, 2, 3, 4}, []byte{0, 1, 2, 3, 4, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
        {"4 bytes", []byte{0, 1, 2, 3}, []byte{0, 1, 2, 3, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
        {"3 bytes", []byte{0, 1, 2}, []byte{0, 1, 2, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
        {"2 bytes", []byte{0, 1}, []byte{0, 1, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
        {"1 bytes", []byte{0}, []byte{0, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
        {"0 bytes", []byte{}, []byte{0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            if got := pboc2.Padding(tt.src, 16); !reflect.DeepEqual(got, tt.want) {
                t.Errorf("PBOC2.Padding() = %v, want %v", got, tt.want)
            }
        })
    }
}

func Test_PBOC2_Unpad(t *testing.T) {
    pboc2 := NewPBOC2()

    tests := []struct {
        name    string
        want    []byte
        src     []byte
        wantErr bool
    }{
        {"16 bytes", []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, false},
        {"15 bytes", []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14}, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 0x80}, false},
        {"14 bytes", []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13}, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 0x80, 0}, false},
        {"13 bytes", []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 0x80, 0, 0}, false},
        {"12 bytes", []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11}, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x80, 0, 0, 0}, false},
        {"11 bytes", []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10}, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 0x80, 0, 0, 0, 0}, false},
        {"10 bytes", []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0x80, 0, 0, 0, 0, 0}, false},
        {"9 bytes", []byte{0, 1, 2, 3, 4, 5, 6, 7, 8}, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 0x80, 0, 0, 0, 0, 0, 0}, false},
        {"8 bytes", []byte{0, 1, 2, 3, 4, 5, 6, 7}, []byte{0, 1, 2, 3, 4, 5, 6, 7, 0x80, 0, 0, 0, 0, 0, 0, 0}, false},
        {"7 bytes", []byte{0, 1, 2, 3, 4, 5, 6}, []byte{0, 1, 2, 3, 4, 5, 6, 0x80, 0, 0, 0, 0, 0, 0, 0, 0}, false},
        {"6 bytes", []byte{0, 1, 2, 3, 4, 5}, []byte{0, 1, 2, 3, 4, 5, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0}, false},
        {"5 bytes", []byte{0, 1, 2, 3, 4}, []byte{0, 1, 2, 3, 4, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, false},
        {"4 bytes", []byte{0, 1, 2, 3}, []byte{0, 1, 2, 3, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, false},
        {"3 bytes", []byte{0, 1, 2}, []byte{0, 1, 2, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, false},
        {"2 bytes", []byte{0, 1}, []byte{0, 1, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, false},
        {"1 bytes", []byte{0}, []byte{0, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, false},
        {"0 bytes", []byte{}, []byte{0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, false},

        {"1 bytes with tag", []byte{0x80}, []byte{0x80, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, false},
        {"3 bytes with tag", []byte{0x80, 0, 0x80}, []byte{0x80, 0, 0x80, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, false},
        {"19 bytes with tag", []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 0x80, 0, 0x80}, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 0x80, 0, 0x80, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, false},
        {"invalid src length", nil, []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, true},
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            got, err := pboc2.UnPadding(tt.src)
            if (err != nil) != tt.wantErr {
                t.Errorf("case %v: PBOC2.UnPadding() error = %v, wantErr %v", tt.name, err, tt.wantErr)
                return
            }

            if !reflect.DeepEqual(got, tt.want) {
                t.Errorf("case %v: PBOC2.UnPadding() = %#v, want %#v", tt.name, got, tt.want)
            }
        })
    }
}

func Test_TBC_Pad(t *testing.T) {
    tbc := NewTBC()

    tests := []struct {
        name string
        src  []byte
        want []byte
    }{
        {"16 bytes", []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
        {"15 bytes", []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14}, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 0xFF}},
        {"14 bytes", []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13}, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 0, 0}},
        {"13 bytes", []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 0xFF, 0xFF, 0xFF}},
        {"12 bytes", []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11}, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0, 0, 0, 0}},
        {"11 bytes", []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10}, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}},
        {"10 bytes", []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 0, 0, 0, 0, 0}},
        {"9 bytes", []byte{0, 1, 2, 3, 4, 5, 6, 7, 8}, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}},
        {"8 bytes", []byte{0, 1, 2, 3, 4, 5, 6, 7}, []byte{0, 1, 2, 3, 4, 5, 6, 7, 0, 0, 0, 0, 0, 0, 0, 0}},
        {"7 bytes", []byte{0, 1, 2, 3, 4, 5, 6}, []byte{0, 1, 2, 3, 4, 5, 6, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}},
        {"6 bytes", []byte{0, 1, 2, 3, 4, 5}, []byte{0, 1, 2, 3, 4, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
        {"5 bytes", []byte{0, 1, 2, 3, 4}, []byte{0, 1, 2, 3, 4, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}},
        {"4 bytes", []byte{0, 1, 2, 3}, []byte{0, 1, 2, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
        {"3 bytes", []byte{0, 1, 2}, []byte{0, 1, 2, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}},
        {"2 bytes", []byte{0, 1}, []byte{0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
        {"1 bytes", []byte{0}, []byte{0, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}},
        {"0 bytes", []byte{}, []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}},
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            if got := tbc.Padding(tt.src, 16); !reflect.DeepEqual(got, tt.want) {
                t.Errorf("TBC.Padding() = %v, want %v", got, tt.want)
            }
        })
    }
}

func Test_TBC_Unpad(t *testing.T) {
    tbc := NewTBC()

    tests := []struct {
        name    string
        want    []byte
        src     []byte
        wantErr bool
    }{
        {"16 bytes", []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, false},
        {"15 bytes", []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14}, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 0xFF}, false},
        {"14 bytes", []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13}, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 0, 0}, false},
        {"13 bytes", []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 0xFF, 0xFF, 0xFF}, false},
        {"12 bytes", []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11}, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0, 0, 0, 0}, false},
        {"11 bytes", []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10}, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}, false},
        {"10 bytes", []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 0, 0, 0, 0, 0}, false},
        {"9 bytes", []byte{0, 1, 2, 3, 4, 5, 6, 7, 8}, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}, false},
        {"8 bytes", []byte{0, 1, 2, 3, 4, 5, 6, 7}, []byte{0, 1, 2, 3, 4, 5, 6, 7, 0, 0, 0, 0, 0, 0, 0, 0}, false},
        {"7 bytes", []byte{0, 1, 2, 3, 4, 5, 6}, []byte{0, 1, 2, 3, 4, 5, 6, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}, false},
        {"6 bytes", []byte{0, 1, 2, 3, 4, 5}, []byte{0, 1, 2, 3, 4, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, false},
        {"5 bytes", []byte{0, 1, 2, 3, 4}, []byte{0, 1, 2, 3, 4, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}, false},
        {"4 bytes", []byte{0, 1, 2, 3}, []byte{0, 1, 2, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, false},
        {"3 bytes", []byte{0, 1, 2}, []byte{0, 1, 2, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}, false},
        {"2 bytes", []byte{0, 1}, []byte{0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, false},
        {"1 bytes", []byte{0}, []byte{0, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}, false},
        {"0 bytes", []byte{}, []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}, false},

        // {"invalid src length", nil, []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, true},
        {"invalid padding byte", nil, []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}, true},
        {"inconsistent padding bytes", nil, []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 55, 0xFF}, true},
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            got, err := tbc.UnPadding(tt.src)
            if (err != nil) != tt.wantErr {
                t.Errorf("TBC.UnPadding() error = %v, wantErr %v", err, tt.wantErr)
                return
            }

            if !reflect.DeepEqual(got, tt.want) {
                t.Errorf("TBC.UnPadding() = %#v, want %#v", got, tt.want)
            }
        })
    }
}
