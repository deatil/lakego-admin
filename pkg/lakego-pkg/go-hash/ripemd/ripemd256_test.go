package ripemd

import (
    "fmt"
    "io"
    "testing"
)

func Test256Vectors(t *testing.T) {
    var vectors = [...]mdTest{
        {"afbd6e228b9d8cbbcef5ca2d03e6dba10ac0bc7dcbe4680e1e42d2e975459b65", "abc"},
        {"8536753ad7bface2dba89fb318c95b1b42890016057d4c3a2f351cec3acbb28b", "123"},
        {"77093b1266befed58d512e67b3a8a15398c3ce5c1333d66a190becc9baa329e9", "123456"},
    }
    for i := 0; i < len(vectors); i++ {
        tv := vectors[i]
        md := New256()
        io.WriteString(md, tv.in)

        s := fmt.Sprintf("%x", md.Sum(nil))
        if s != tv.out {
            t.Fatalf("RIPEMD-256(%s) = %s, expected %s", tv.in, s, tv.out)
        }
        md.Reset()
    }

    for i := 0; i < len(vectors); i++ {
        tv := vectors[i]
        s := fmt.Sprintf("%x", Sum256([]byte(tv.in)))
        if s != tv.out {
            t.Fatalf("RIPEMD-256-sum(%s) = %s, expected %s", tv.in, s, tv.out)
        }
    }
}
