package sm3

import (
    "bytes"
    "testing"
)

func Test_MarshalBinary(t *testing.T) {
    msg := []byte("test-dd1111111dddddddatatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-data")

    h := new(digest)
    h.Reset()

    h.Write(msg)
    dst := h.Sum(nil)
    if len(dst) == 0 {
        t.Error("Hash make error")
    }

    bs, _ := h.MarshalBinary()

    h.Reset()
    err := h.UnmarshalBinary(bs)
    if err != nil {
        t.Fatal(err)
    }

    newdst := h.Sum(nil)
    if len(newdst) == 0 {
        t.Error("newHash make error")
    }

    if !bytes.Equal(newdst, dst) {
        t.Errorf("Hash MarshalBinary error, got %x, want %x", newdst, dst)
    }
}
