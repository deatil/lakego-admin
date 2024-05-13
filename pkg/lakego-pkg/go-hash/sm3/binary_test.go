package sm3

import (
    "fmt"
    "bytes"
    "testing"
)

func Test_MarshalBinary(t *testing.T) {
    msg := []byte("abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd")
    check := "90d52a2e85631a8d6035262626941fa11b85ce570cec1e3e991e2dd7ed258148"

    h := newDigest()
    h.Write(msg)
    dst := h.Sum(nil)
    if len(dst) == 0 {
        t.Error("Hash make error")
    }

    bs, _ := h.MarshalBinary()

    h2 := newDigest()
    err := h2.UnmarshalBinary(bs)
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
