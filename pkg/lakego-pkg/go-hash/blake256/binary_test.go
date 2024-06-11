package blake256

import (
    "fmt"
    "bytes"
    "testing"
    "encoding"
)

func Test_MarshalBinary(t *testing.T) {
    msg := []byte("The quick brown fox jumps over the lazy dog")
    check := "7576698ee9cad30173080678e5965916adbb11cb5245d386bf1ffda1cb26c9d7"

    h := New()
    h.Write(msg)
    dst := h.Sum(nil)
    if len(dst) == 0 {
        t.Error("Hash make error")
    }

    bs, _ := h.(encoding.BinaryMarshaler).MarshalBinary()

    h2 := New()
    err := h2.(encoding.BinaryUnmarshaler).UnmarshalBinary(bs)
    if err != nil {
        t.Fatal(err)
    }

    newdst := h2.Sum(nil)
    if len(newdst) == 0 {
        t.Error("newHash make error")
    }

    if !bytes.Equal(newdst, dst) {
        t.Errorf("Hash MarshalBinary error, got %x, want %x", newdst, dst)
    }

    // ===========

    sum1 := fmt.Sprintf("%x", dst)
    if sum1 != check {
        t.Errorf("Sum error, got %s, want %s", sum1, check)
    }

    sum2 := fmt.Sprintf("%x", newdst)
    if sum2 != check {
        t.Errorf("ReSum error, got %s, want %s", sum2, check)
    }
}
