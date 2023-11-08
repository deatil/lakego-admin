package asn1

import (
    "io"
    "math"
    "bytes"
    "errors"
    "unicode/utf16"
    "testing"
    "crypto/hmac"
    "crypto/sha1"
    "encoding/binary"
    "encoding/base64"

    cryptobin_pbkdf "github.com/deatil/go-cryptobin/kdf/pbkdf"
)

func init() {
    objectIdentifierTestData = append(objectIdentifierTestData, berObjectIdentifierTestData...)
    unmarshalTestData = append(unmarshalTestData, berUnmarshalTestData...)
    tagAndLengthData = berTagAndLengthData
}

// @init
var berObjectIdentifierTestData = []objectIdentifierTest{
    // large object identifier value, seen on some SNMP devices
    // See ber_64bit_test.go for none 32-bit compatible examples.
    {
        []byte{
            0x2b, 0x06, 0x01, 0x02, 0x01, 0x1f, 0x01, 0x01,
            0x01, 0x01, 0x84, 0x88, 0x90, 0x80, 0x23},
        true,
        []int{1, 3, 6, 1, 2, 1, 31, 1, 1, 1, 1, 1090781219},
    },
}

// berTagAndLengthData replaces the tagAndLengthData contents, this makes it easier to see which test has failed
// as they are numbered
var berTagAndLengthData = []tagAndLengthTest{
    {[]byte{0x80, 0x01}, true, tagAndLength{2, 0, 1, false, false}},
    {[]byte{0xa0, 0x01}, true, tagAndLength{2, 0, 1, true, false}},
    {[]byte{0x02, 0x00}, true, tagAndLength{0, 2, 0, false, false}},
    {[]byte{0xfe, 0x00}, true, tagAndLength{3, 30, 0, true, false}},
    {[]byte{0x1f, 0x1f, 0x00}, true, tagAndLength{0, 31, 0, false, false}},
    {[]byte{0x1f, 0x81, 0x00, 0x00}, true, tagAndLength{0, 128, 0, false, false}},
    {[]byte{0x1f, 0x81, 0x80, 0x01, 0x00}, true, tagAndLength{0, 0x4001, 0, false, false}},
    {[]byte{0x00, 0x81, 0x80}, true, tagAndLength{0, 0, 128, false, false}},
    {[]byte{0x00, 0x82, 0x01, 0x00}, true, tagAndLength{0, 0, 256, false, false}},
    {[]byte{0x00, 0x83, 0x01, 0x00}, false, tagAndLength{}},
    {[]byte{0x1f, 0x85}, false, tagAndLength{}},
    // {[]byte{0x30, 0x80}, false, tagAndLength{}},
    // Lengths up to the maximum size of an int should work.
    {[]byte{0xa0, 0x84, 0x7f, 0xff, 0xff, 0xff}, true, tagAndLength{2, 0, 0x7fffffff, true, false}},
    // Lengths that would overflow an int should be rejected.
    {[]byte{0xa0, 0x84, 0x80, 0x00, 0x00, 0x00}, false, tagAndLength{}},
    // Tag numbers which would overflow int32 are rejected. (The value below is 2^31.)
    {[]byte{0x1f, 0x88, 0x80, 0x80, 0x80, 0x00, 0x00}, false, tagAndLength{}},
    // Tag numbers that fit in an int32 are valid. (The value below is 2^31 - 1.)
    {[]byte{0x1f, 0x87, 0xFF, 0xFF, 0xFF, 0x7F, 0x00}, true, tagAndLength{tag: math.MaxInt32}},
    // Long tag number form may not be used for tags that fit in short form.
    {[]byte{0x1f, 0x1e, 0x00}, false, tagAndLength{}},
    // Superfluous zeros in the length should be a accepted (different from DER).
    {[]byte{0xa0, 0x82, 0x00, 0xff}, true, tagAndLength{2, 0, 0xff, true, false}},
    // Lengths that would overflow an int should be rejected.
    {[]byte{0xa0, 0x84, 0x88, 0x90, 0x80, 0x23}, false, tagAndLength{}},
    // Long length form may be used for lengths that fit in short form (different from DER).
    {[]byte{0xa0, 0x81, 0x7f}, true, tagAndLength{2, 0, 0x7f, true, false}},
    // Indefinite length.
    {[]byte{0x30, 0x80, 0x02, 0x01, 0x04, 0x00, 0x00}, true, tagAndLength{0, 16, 3, true, true}},
}

type TestExplicitIndefinite struct {
    T    TestContextSpecificTags2 `asn1:"explicit,tag:2,set"`
    Ints []int                    `asn1:"explicit,application"`
}

var berUnmarshalTestData = []struct {
    in  []byte
    out interface{}
}{
    {
        []byte{0x30, 0x80, 0x31, 0x80, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02, 0x02, 0x01, 0x03, 0x00, 0x00, 0x00, 0x00},
        &TestSet{Ints: []int{1, 2, 3}},
    },
    {
        []byte{0x30, 0x80, 0x13, 0x03, 0x66, 0x6f, 0x6f, 0x02, 0x01, 0x22, 0x02, 0x01, 0x33, 0x00, 0x00},
        &TestElementsAfterString{"foo", 0x22, 0x33},
    },
    {
        []byte{0x30, 0x80, 0xa2, 0x80, 0x31, 0x08, 0xa1, 0x03, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02, 0x00, 0x00,
        0x60, 0x80, 0x30, 0x80, 0x02, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
        &TestExplicitIndefinite{TestContextSpecificTags2{1, 2}, []int{2}}},
}

var sm2Pkcs12 = "MIACAQMwgAYJKoZIhvcNAQcBoIAkgASCA+gwgDCABgkqhkiG9w0BBwGggCSABIHNMIHKMIHHBgsqhkiG" +
    "9w0BDAoBAqB2MHQwKAYKKoZIhvcNAQwBAzAaBBRBCcN+h46YwoEjCwYsx5R2Ggq3HgICBAAESFoOSL36" +
    "Ku1nQYesdqh09xuQFCbr5Ozm5+aF91Bbs0tdRheyKY8JvC4VCzX2AsCrevOFb3io6teNdkcmFOeDOhSE" +
    "VYuzJIHZZTFAMBkGCSqGSIb3DQEJFDEMHgoAQQAgAEsAZQB5MCMGCSqGSIb3DQEJFTEWBBSlqw4sTrXP" +
    "Y1Io0OetvRz8sQyBQgAAAAAAADCABgkqhkiG9w0BBwaggDCAAgEAMIAGCSqGSIb3DQEHATAoBgoqhkiG" +
    "9w0BDAEGMBoEFJb7ThL0KhfqB5ov1gQFeYRZWmZ/AgIEAKCABIICwBv1XgH3DfbaauQS27Gb036glq1K" +
    "n/seDdCLdUROkxMa1HzXiyeDGB48ekgHYSLqzCNdnry2NZvMWoVPTaYvgF04DhZxPTcSYxWOPQL2+LX0" +
    "GwEdjidQvGF1jze+R4uUxyXg9HXmxJ7jtl5djgHsPVeKIaQXSHQCcM1gYwsGDkV14zhrUfDiCw7LxMMg" +
    "9To+x3g0Tx/ZcuCF5gmj8jgzsM7AqlPp/+UrVri/LB+mDE/IhRWL3Bkp+wBrTrIoQFLGQVQS3McWX+tx" +
    "C4OXtLzTjoTu5VosvXDDxDhsrSfZNNztZTw6z2l48IY5O7vMUsFkW7eCkiLuek5ck1uhv50lqNvEEbsk" +
    "uMj7j3fyZnBZAj0ieODo3Uu6fdKpTy0ysmKcPDMMES/5ASjDz3Zk/56vLr09s7uTTH4+xOZViP/T5y28" +
    "40qrcefN2fmtOtyuUGO71ul+/LpXKch4atDR9jSv5ovyXhKKxfCOfHW2oV43aJwA66+uElR+ZsjwyLmA" +
    "p0f12HdxeKJIWX4yDQiAJ9n/F3W3nBMpmZBNwEVdUE6+OoZUU93dD6BExMC27DuiaH622Mi2ydfkW+l2" +
    "frehlTl0CmontrmpkJ30u/U25x6fI8wB0aXVd3IzWPYe0yMdnPZlOLajjer2DU6T4KD6spR3Cp0Vg1GW" +
    "XTTj3gROAw9tKbJCWKLCkadhzHSnJ1Y9edjcwmIOWBZtM94julcKeviMW0DSwHojJy4bD2DO7fQv+JPg" +
    "uG6Xlm5zajxOsnuUy0AzqRywTKplCQwa/U9i65FNBhsRSNE2Cmx8EXuWMxigQO3gyyQsUMrIpoUSzzQL" +
    "vcIE5UCMvP69G5r5C9TSvQ2pKeAvkUIckMZkaA/lMqKkM55dOeFa60AX/Qj2WO0Yu6y18eaMSXnvwMWv" +
    "B2UywrHDBB4iEu2+kNke7EUSzQbItlBZzJgAAAAAAAAAAAAAAAAAAAAAAAAwPTAhMAkGBSsOAwIaBQAE" +
    "FJbJE8lKP08n4Y6jWYZcGrL6sy2gBBSkmhIJK3GKeGqMUxotT1on92p3FgICBAAAAA=="

type AlgorithmIdentifier2 struct {
    Algorithm  ObjectIdentifier
    Parameters RawValue `asn1:"optional"`
}

type contentInfo struct {
    ContentType ObjectIdentifier
    Content     RawValue `asn1:"tag:0,explicit,optional"`
}

// from PKCS#7:
type digestInfo struct {
    Algorithm AlgorithmIdentifier2
    Digest    []byte
}

type macData struct {
    Mac        digestInfo
    MacSalt    []byte
    Iterations int `asn1:"optional,default:1"`
}

func (this macData) Verify(message []byte, password []byte) bool {
    h := sha1.New

    hashSize := h().Size()

    key := cryptobin_pbkdf.Key(h, hashSize, 64, this.MacSalt, password, this.Iterations, 3, hashSize)

    mac := hmac.New(h, key)
    mac.Write(message)
    expectedMAC := mac.Sum(nil)

    if !hmac.Equal(this.Mac.Digest, expectedMAC) {
        return false
    }

    return true
}

type pfxPdu struct {
    Version  int
    AuthSafe contentInfo
    MacData  macData `asn1:"optional"`
}

func Test_SM2Pkcs12(t *testing.T) {
    ber, err := base64.StdEncoding.DecodeString(sm2Pkcs12)
    if err != nil {
        t.Errorf("err: %v", err)
    }

    pfx := new(pfxPdu)
    if _, err = Unmarshal(ber, pfx); err != nil {
        t.Errorf("Unmarshal err: %v", err)
    }

    if pfx.Version != 3 {
        t.Errorf("Version err: %d", pfx.Version)
    }

    if _, err = Unmarshal(pfx.AuthSafe.Content.Bytes, &pfx.AuthSafe.Content); err != nil {
        t.Errorf("Unmarshal2 err: %v", err)
    }

    data := pfx.AuthSafe.Content.Bytes
    // data = bytes.TrimRight(data, string([]byte{0}))

    var authenticatedSafes = make([]RawValue, 0)

    for {
        var authenticatedSafe RawValue
        data, err = Unmarshal(data, &authenticatedSafe)
        if err != nil {
            t.Errorf("Unmarshal octet err: %v", err)
        }

        authenticatedSafes = append(authenticatedSafes, authenticatedSafe)

        if len(data) == 0 {
            break
        }
    }

    password := "12345678"
    newPassword, err := testBmpStringZeroTerminated(password)
    if err != nil {
        t.Errorf("password err: %v", err)
    }

    checked := pfx.MacData.Verify(data, newPassword)
    if !checked {
        // t.Errorf("password is error")
    }

    for _, as := range authenticatedSafes {
        // t.Errorf("%x", as.Bytes)

        asBuf := bytes.NewReader(as.Bytes)

        _, err := readUint8(asBuf)
        if err != nil {
            t.Errorf("readUint8 err: %v", err)
        }

    }

    // t.Errorf("authenticatedSafes data: %#v", authenticatedSafes)

}

// bmpStringZeroTerminated returns s encoded in UCS-2 with a zero terminator.
func testBmpStringZeroTerminated(s string) ([]byte, error) {
    // References:
    // https://tools.ietf.org/html/rfc7292#appendix-B.1
    // The above RFC provides the info that BMPStrings are NULL terminated.

    ret, err := testBmpString(s)
    if err != nil {
        return nil, err
    }

    return append(ret, 0, 0), nil
}

// bmpString returns s encoded in UCS-2
func testBmpString(s string) ([]byte, error) {
    // References:
    // https://tools.ietf.org/html/rfc7292#appendix-B.1
    // https://en.wikipedia.org/wiki/Plane_(Unicode)#Basic_Multilingual_Plane
    //  - non-BMP characters are encoded in UTF 16 by using a surrogate pair of 16-bit codes
    //    EncodeRune returns 0xfffd if the rune does not need special encoding

    ret := make([]byte, 0, 2*len(s)+2)

    for _, r := range s {
        if t, _ := utf16.EncodeRune(r); t != 0xfffd {
            return nil, errors.New("pkcs12: string contains characters that cannot be encoded in UCS-2")
        }
        ret = append(ret, byte(r/256), byte(r%256))
    }

    return ret, nil
}

func readUint8(r io.Reader) (uint8, error) {
    var v uint8
    err := binary.Read(r, binary.BigEndian, &v)

    return v, err
}

func readUint16(r io.Reader) (uint16, error) {
    var v uint16
    err := binary.Read(r, binary.BigEndian, &v)

    return v, err
}

func readInt32(r io.Reader) (int32, error) {
    var v int32
    err := binary.Read(r, binary.BigEndian, &v)

    return v, err
}

func readUTF(r io.Reader) (string, error) {
    length, err := readUint16(r)
    if err != nil {
        return "", err
    }

    buf := make([]byte, length)

    _, err = io.ReadFull(r, buf)
    if err != nil {
        return "", err
    }

    return string(buf), nil
}

func readBytes(r io.Reader) ([]byte, error) {
    length, err := readInt32(r)
    if err != nil {
        return nil, err
    }

    buf := make([]byte, length)
    _, err = io.ReadFull(r, buf)
    if err != nil {
        return nil, err
    }

    return buf, nil
}
