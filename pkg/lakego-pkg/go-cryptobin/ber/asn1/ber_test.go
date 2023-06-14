package asn1

import (
    "math"
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
    {[]byte{0x30, 0x80, 0x31, 0x80, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02, 0x02, 0x01, 0x03, 0x00, 0x00, 0x00, 0x00}, &TestSet{Ints: []int{1, 2, 3}}},
    {[]byte{0x30, 0x80, 0x13, 0x03, 0x66, 0x6f, 0x6f, 0x02, 0x01, 0x22, 0x02, 0x01, 0x33, 0x00, 0x00}, &TestElementsAfterString{"foo", 0x22, 0x33}},
    {[]byte{0x30, 0x80, 0xa2, 0x80, 0x31, 0x08, 0xa1, 0x03, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02, 0x00, 0x00,
        0x60, 0x80, 0x30, 0x80, 0x02, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
        &TestExplicitIndefinite{TestContextSpecificTags2{1, 2}, []int{2}}},
}
