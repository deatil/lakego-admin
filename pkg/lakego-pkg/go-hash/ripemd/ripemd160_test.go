package ripemd

import (
    "fmt"
    "io"
    "testing"
)

type mdTest struct {
    out string
    in  string
}

func Test160Vectors(t *testing.T) {
    var vectors = [...]mdTest{
        {"9c1185a5c5e9fc54612808977ee8f548b2258d31", ""},
        {"0bdc9d2d256b3ee9daae347be6f4dc835a467ffe", "a"},
        {"8eb208f7e05d987a9b044a8e98c6b087f15a0bfc", "abc"},
        {"5d0689ef49d2fae572b881b123a85ffa21595f36", "message digest"},
        {"f71c27109c692c1b56bbdceb5b9d2865b3708dbc", "abcdefghijklmnopqrstuvwxyz"},
        {"12a053384a9c0c88e405a06c27dcf49ada62eb2b", "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"},
        {"b0e20b6e3116640286ed3a87a5713079b21f5189", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"},
        {"9b752e45573d4b39f4dbd3323cab82bf63326bfb", "12345678901234567890123456789012345678901234567890123456789012345678901234567890"},
    }

    for i := 0; i < len(vectors); i++ {
        tv := vectors[i]
        md := New160()
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
                t.Fatalf("RIPEMD-160[%d](%s) = %s, expected %s", j, tv.in, s, tv.out)
            }
            md.Reset()
        }
    }

    for i := 0; i < len(vectors); i++ {
        tv := vectors[i]
        s := fmt.Sprintf("%x", Sum160([]byte(tv.in)))
        if s != tv.out {
            t.Fatalf("RIPEMD-160-sum(%s) = %s, expected %s", tv.in, s, tv.out)
        }
    }
}

func millionA() string {
    md := New160()
    for i := 0; i < 100000; i++ {
        io.WriteString(md, "aaaaaaaaaa")
    }
    return fmt.Sprintf("%x", md.Sum(nil))
}

func TestMillionA(t *testing.T) {
    const out = "52783243c1697bdbe16d37f97f68f08325dc1528"
    if s := millionA(); s != out {
        t.Fatalf("RIPEMD-160 (1 million 'a') = %s, expected %s", s, out)
    }
}

func BenchmarkMillionA(b *testing.B) {
    for i := 0; i < b.N; i++ {
        millionA()
    }
}
