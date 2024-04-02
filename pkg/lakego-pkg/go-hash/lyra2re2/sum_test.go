package lyra2re2

import (
    "bytes"
    "testing"
    "encoding/hex"
)

func Test_SumV2(t *testing.T) {
    correct, err := hex.DecodeString("5f21d7763b1ae8fc87db7dc993ddc50468765729411ba6b24906de15851a4abf")
    if err != nil {
        t.Fatal(err)
    }

    data := make([]byte, 80)
    copy(data, []byte("test"))
    result, err := Sum(data)
    if err != nil {
        t.Fatal(err)
    }
    if !bytes.Equal(correct, result) {
        t.Errorf("not match, got %x, want %x", result, correct)
    }
}
