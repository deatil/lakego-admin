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

func Test_Hash128_Check(t *testing.T) {
    var vectors = [...]mdTest{
        {"d6d56cab46e0f3af2c756289f2b447e0", "123456"},
        {"86be7afa339d0fc7cfc785e72f578d33", "a"},
    }

    md := New128()
    for i := 0; i < len(vectors); i++ {
        tv := vectors[i]
        md.Reset()
        io.WriteString(md, tv.in)

        s := fmt.Sprintf("%x", md.Sum(nil))
        if s != tv.out {
            t.Fatalf("RIPEMD-128(%s) = %s, expected %s", tv.in, s, tv.out)
        }
    }

    for i := 0; i < len(vectors); i++ {
        tv := vectors[i]
        s := fmt.Sprintf("%x", Sum128([]byte(tv.in)))
        if s != tv.out {
            t.Fatalf("RIPEMD-128-sum(%s) = %s, expected %s", tv.in, s, tv.out)
        }
    }
}

func Test_Hash160_Check(t *testing.T) {
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

func Test_Hash256_Check(t *testing.T) {
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

func Test_Hash320_Check(t *testing.T) {
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

// =====

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

