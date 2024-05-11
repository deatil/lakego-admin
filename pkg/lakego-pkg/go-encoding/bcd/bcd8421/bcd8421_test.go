package bcd8421

import (
    "reflect"
    "testing"
)

func TestStringNumberToBytes(t *testing.T) {
    should := []byte{0x00, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9}
    b, err := stringNumberToBytes("0123456789")
    if err != nil {
        panic(err)
    }

    if !reflect.DeepEqual(b, should) {
        t.Errorf("should be %#v", should)
    }
}

var encodeTestcases = []struct {
    number      string
    bytes       []byte
    bytesLength int
}{
    {
        number:      "907865438",
        bytes:       []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x09, 0x07, 0x86, 0x54, 0x38},
        bytesLength: 10,
    },
    {
        number:      "9007865438",
        bytes:       []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x90, 0x07, 0x86, 0x54, 0x38},
        bytesLength: 10,
    },
    {
        number:      "90007865438",
        bytes:       []byte{0x00, 0x00, 0x00, 0x00, 0x09, 0x00, 0x07, 0x86, 0x54, 0x38},
        bytesLength: 10,
    },
    {
        number:      "900007865438",
        bytes:       []byte{0x00, 0x00, 0x00, 0x00, 0x90, 0x00, 0x07, 0x86, 0x54, 0x38},
        bytesLength: 10,
    },
    {
        number:      "9000007865438",
        bytes:       []byte{0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x07, 0x86, 0x54, 0x38},
        bytesLength: 10,
    },
    {
        number:      "3830",
        bytes:       []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x38, 0x30},
        bytesLength: 10,
    },
    {
        number:      "38300",
        bytes:       []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x83, 0x00},
        bytesLength: 10,
    },
    {
        number:      "383000",
        bytes:       []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x38, 0x30, 0x00},
        bytesLength: 10,
    },
    {
        number:      "3830000",
        bytes:       []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x83, 0x00, 0x00},
        bytesLength: 10,
    },
}

var decodeTestcases = []struct {
    number   string
    bytes    []byte
    skipzero bool
}{
    {
        number: "060101150304",
        bytes:  []byte{0x06, 0x01, 0x01, 0x15, 0x03, 0x04},
    },
    {
        number: "00060101150304",
        bytes:  []byte{0x00, 0x06, 0x01, 0x01, 0x15, 0x03, 0x04},
    },
    {
        number:   "60101150304",
        bytes:    []byte{0x06, 0x01, 0x01, 0x15, 0x03, 0x04},
        skipzero: true,
    },
    {
        number:   "60101150304",
        bytes:    []byte{0x00, 0x06, 0x01, 0x01, 0x15, 0x03, 0x04},
        skipzero: true,
    },
}

func TestEncodeFromString(t *testing.T) {
    for _, tt := range encodeTestcases {
        ret, err := EncodeFromString(tt.number, tt.bytesLength)
        if err != nil {
            panic(err)
        }
        if !reflect.DeepEqual(ret, tt.bytes) {
            t.Errorf("EncodeFromString(%#v) = %#v; should be %#v", tt.number, ret, tt.bytes)
        }
    }
}

func TestDecodeToString(t *testing.T) {
    for _, tt := range decodeTestcases {
        n, err := DecodeToString(tt.bytes, tt.skipzero)
        if err != nil {
            panic(err)
        }
        if n != tt.number {
            t.Errorf("DecodeToString(%#v) = %s; should be %s", tt.bytes, n, tt.number)
        }
    }
}
