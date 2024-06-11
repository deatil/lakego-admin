package blake512

import (
    "fmt"
    "bytes"
    "testing"
    "encoding"
)

func Test_MarshalBinary(t *testing.T) {
    msg := fromHex("eed7422227613b6f53c9")
    check := "c5633a1b9e45cef38647603cbd9710e1aca4f2fb84f8d56a0d729fd6d480ef05f8a46f1dc0e771ec114aea2f9ad534b70bf03046118a5f2fbdd371442d9d8895"

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
