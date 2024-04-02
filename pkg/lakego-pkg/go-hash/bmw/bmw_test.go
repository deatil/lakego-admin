package bmw

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

func Test_Hash(t *testing.T) {
    msg := []byte("test-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-data")

    h := New()
    h.Write(msg)
    dst := h.Sum(nil)

    if len(dst) == 0 {
        t.Error("Hash make error")
    }
}

type testData struct {
    msg []byte
    md []byte
}

func Test_Hash_Check(t *testing.T) {
   tests := []testData{
        {
           fromHex("1F877C"),
           fromHex("afc964b8ec55fc0bf5880008e484c85cc08f85f10bc9dea42249412c376eba0d"),
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

func Test_bmw256(t *testing.T) {
    msg := "78AECC1F4DBF27AC146780EEA8DCC56B"
    check := "73092167d7f56feffc58dded2b30b281d170ccd54042dd1f1991189aac1ae5f3"

    dst := Sum([]byte(msg))

    if fmt.Sprintf("%x", dst) != check {
        t.Errorf("fail, got %x, want %s", dst, check)
    }

}
