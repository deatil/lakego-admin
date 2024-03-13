package ripemd

import (
    "fmt"
    "io"
    "testing"
)

func Test320Vectors(t *testing.T) {
    var vectors = [...]mdTest{
        {"a2ee4b6b9e3144c7db61b1ffc748bf2c728b65819e3f69a021f515acb044995b90f03d60974b6b4a", "123456"},
        {"bfa11b73ad4e6421a8ba5a1223d9c9f58a5ad456be98bee5bfcd19a3ecdc6140ce4c700be860fda9", "123"},
        {"ce78850638f92658a5a585097579926dda667a5716562cfcf6fbe77f63542f99b04705d6970dff5d", "a"},
    }
    for i := 0; i < len(vectors); i++ {
        tv := vectors[i]
        md := New320()
        for j := 0; j < 3; j++ {
            if j < 2 {
                io.WriteString(md, tv.in)
            } else {
                io.WriteString(md, tv.in[0:len(tv.in)/2])
                md.Sum(nil)
                io.WriteString(md, tv.in[len(tv.in)/2:])
            }
            s := fmt.Sprintf("%x", md.Sum(nil))
            if s != tv.out {
                t.Fatalf("RIPEMD-320(%s) = %s, expected %s", tv.in, s, tv.out)
            }
            md.Reset()
        }
    }

    for i := 0; i < len(vectors); i++ {
        tv := vectors[i]
        s := fmt.Sprintf("%x", Sum320([]byte(tv.in)))
        if s != tv.out {
            t.Fatalf("RIPEMD-320-sum(%s) = %s, expected %s", tv.in, s, tv.out)
        }
    }
}
