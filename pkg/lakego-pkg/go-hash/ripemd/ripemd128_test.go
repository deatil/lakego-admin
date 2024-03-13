package ripemd

import (
    "fmt"
    "io"
    "testing"
)

func Test128Vectors(t *testing.T) {
    var vectors = [...]mdTest{
        {"d6d56cab46e0f3af2c756289f2b447e0", "123456"},
        {"86be7afa339d0fc7cfc785e72f578d33", "a"},
    }
    for i := 0; i < len(vectors); i++ {
        tv := vectors[i]
        md := New128()
        io.WriteString(md, tv.in)
        s := fmt.Sprintf("%x", md.Sum(nil))
        if s != tv.out {
            t.Fatalf("RIPEMD-128(%s) = %s, expected %s", tv.in, s, tv.out)
        }
        md.Reset()
    }

    for i := 0; i < len(vectors); i++ {
        tv := vectors[i]
        s := fmt.Sprintf("%x", Sum128([]byte(tv.in)))
        if s != tv.out {
            t.Fatalf("RIPEMD-128-sum(%s) = %s, expected %s", tv.in, s, tv.out)
        }
    }
}
