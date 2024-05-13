package sha0

import (
    "fmt"
    "bytes"
    "testing"
    "encoding/hex"
)

func fromHex(s string) []byte {
    h, _ := hex.DecodeString(s)
    return h
}

func fromString(s string) []byte {
    return []byte(s)
}

type testData struct {
    msg []byte
    md []byte
}

func Test_MillionA_Check(t *testing.T) {
    msg := make([]byte, 1000)
    for i := 0; i < 1000; i++ {
        msg[i] = 'a'
    }

    check := "3232affa48628a26653b5aaa44541fd90d690603"

    h := New()
    for i := 0; i < 1000; i++ {
        h.Write(msg)
    }

    got := fmt.Sprintf("%x", h.Sum(nil))
    if got != check {
        t.Errorf("fail, got %s, want %s", got, check)
    }
}

func Test_Hash_Check(t *testing.T) {
   tests := []testData{
        {
           fromString("abc"),
           fromHex("0164b8a914cd2a5e74c4f7ff082c4d97f1edf880"),
        },
        {
           fromString("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
           fromHex("d2516ee1acfa5baf33dfc1c471e438449ef134c8"),
        },
    }

    h := New()

    for i, test := range tests {
        h.Reset()
        h.Write(test.msg)
        sum := h.Sum(nil)

        if !bytes.Equal(sum, test.md) {
            t.Errorf("[%d] New fail, got %x, want %x", i, sum, test.md)
        }

        // =====

        sum2 := Sum(test.msg)

        if !bytes.Equal(sum2[:], test.md) {
            t.Errorf("[%d] Sum fail, got %x, want %x", i, sum2, test.md)
        }
    }
}
