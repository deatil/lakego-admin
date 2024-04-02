package tiger

import (
    "io"
    "fmt"
    "strings"
    "testing"
)

type Test struct {
    out string
    in  string
}

var golden = []Test{
    {"3293ac630c13f0245f92bbb1766e16167a4e58492dde73f3", ""},
    {"77befbef2e7ef8ab2ec8f93bf587a7fc613e247f5f247809", "a"},
    {"2aab1484e8c158f2bfb8c5ff41b57a525129131c957b5f93", "abc"},
    {"d981f8cb78201a950dcf3048751e441c517fca1aa55a29f6", "message digest"},
    {"1714a472eee57d30040412bfcc55032a0b11602ff37beee9", "abcdefghijklmnopqrstuvwxyz"},
    {"0f7bf9a19b9c58f2b7610df7e84f0ac3a71c631e7b53f78e", "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"},
    {"8dcea680a17583ee502ba38a3c368651890ffbccdc49a8cc", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"},
    {"1c14795529fd9f207a958f84c52f11e887fa0cabdfd91bfd", "12345678901234567890123456789012345678901234567890123456789012345678901234567890"},
    {"cdf0990c5c6b6b0bddd63a75ed20e2d448bf44e15fde0df4", strings.Repeat("A", 1024)},
    {"6db0e2729cbead93d715c6a7d36302e9b3cee0d2bc314b41", strings.Repeat("a", 1000000)},
}

func Test_Golden(t *testing.T) {
    for i := 0; i < len(golden); i++ {
        g := golden[i]
        c := New()
        buf := make([]byte, len(g.in)+4)
        for j := 0; j < 7; j++ {
            if j < 2 {
                io.WriteString(c, g.in)
            } else if j == 2 {
                io.WriteString(c, g.in[0:len(g.in)/2])
                c.Sum(nil)
                io.WriteString(c, g.in[len(g.in)/2:])
            } else if j > 2 {
                // test unaligned write
                buf = buf[1:]
                copy(buf, g.in)
                c.Write(buf[:len(g.in)])
            }

            s := fmt.Sprintf("%x", c.Sum(nil))
            if s != g.out {
                t.Fatalf("tiger[%d](%s) = %s want %s", j, g.in, s, g.out)
            }

            c.Reset()
        }
    }
}

func Test_Golden128(t *testing.T) {
    for i := 0; i < len(golden); i++ {
        g := golden[i]
        c := New128()
        buf := make([]byte, len(g.in)+4)
        for j := 0; j < 7; j++ {
            if j < 2 {
                io.WriteString(c, g.in)
            } else if j == 2 {
                io.WriteString(c, g.in[0:len(g.in)/2])
                c.Sum(nil)
                io.WriteString(c, g.in[len(g.in)/2:])
            } else if j > 2 {
                // test unaligned write
                buf = buf[1:]
                copy(buf, g.in)
                c.Write(buf[:len(g.in)])
            }

            s := fmt.Sprintf("%x", c.Sum(nil))
            if s != g.out[:32] {
                t.Fatalf("tiger[%d](%s) = %s want %s", j, g.in, s, g.out[:32])
            }

            c.Reset()
        }
    }
}

func Test_Golden160(t *testing.T) {
    for i := 0; i < len(golden); i++ {
        g := golden[i]
        c := New160()
        buf := make([]byte, len(g.in)+4)
        for j := 0; j < 7; j++ {
            if j < 2 {
                io.WriteString(c, g.in)
            } else if j == 2 {
                io.WriteString(c, g.in[0:len(g.in)/2])
                c.Sum(nil)
                io.WriteString(c, g.in[len(g.in)/2:])
            } else if j > 2 {
                // test unaligned write
                buf = buf[1:]
                copy(buf, g.in)
                c.Write(buf[:len(g.in)])
            }

            s := fmt.Sprintf("%x", c.Sum(nil))
            if s != g.out[:40] {
                t.Fatalf("tiger[%d](%s) = %s want %s", j, g.in, s, g.out[:40])
            }

            c.Reset()
        }
    }
}

var goldenV2 = []Test{
    {"4441be75f6018773c206c22745374b924aa8313fef919f41", ""},
    {"67e6ae8e9e968999f70a23e72aeaa9251cbc7c78a7916636", "a"},
    {"f68d7bc5af4b43a06e048d7829560d4a9415658bb0b1f3bf", "abc"},
    {"e29419a1b5fa259de8005e7de75078ea81a542ef2552462d", "message digest"},
    {"f5b6b6a78c405c8547e91cd8624cb8be83fc804a474488fd", "abcdefghijklmnopqrstuvwxyz"},
    {"a6737f3997e8fbb63d20d2df88f86376b5fe2d5ce36646a9", "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"},
    {"ea9ab6228cee7b51b77544fca6066c8cbb5bbae6319505cd", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"},
    {"d85278115329ebaa0eec85ecdc5396fda8aa3a5820942fff", "12345678901234567890123456789012345678901234567890123456789012345678901234567890"},
    {"e068281f060f551628cc5715b9d0226796914d45f7717cf4", strings.Repeat("a", 1000000)},
}

func Test_GoldenV2(t *testing.T) {
    for i := 0; i < len(goldenV2); i++ {
        g := goldenV2[i]
        c := New2()
        buf := make([]byte, len(g.in)+4)
        for j := 0; j < 7; j++ {
            if j < 2 {
                io.WriteString(c, g.in)
            } else if j == 2 {
                io.WriteString(c, g.in[0:len(g.in)/2])
                c.Sum(nil)
                io.WriteString(c, g.in[len(g.in)/2:])
            } else if j > 2 {
                // test unaligned write
                buf = buf[1:]
                copy(buf, g.in)
                c.Write(buf[:len(g.in)])
            }

            s := fmt.Sprintf("%x", c.Sum(nil))
            if s != g.out {
                t.Errorf("tiger[%d](%s) = %s want %s", j, g.in, s, g.out)
            }

            c.Reset()
        }
    }
}

func Test_GoldenV2_128(t *testing.T) {
    for i := 0; i < len(goldenV2); i++ {
        g := goldenV2[i]
        c := New2_128()
        buf := make([]byte, len(g.in)+4)
        for j := 0; j < 7; j++ {
            if j < 2 {
                io.WriteString(c, g.in)
            } else if j == 2 {
                io.WriteString(c, g.in[0:len(g.in)/2])
                c.Sum(nil)
                io.WriteString(c, g.in[len(g.in)/2:])
            } else if j > 2 {
                // test unaligned write
                buf = buf[1:]
                copy(buf, g.in)
                c.Write(buf[:len(g.in)])
            }

            s := fmt.Sprintf("%x", c.Sum(nil))
            if s != g.out[:32] {
                t.Errorf("tiger[%d](%s) = %s want %s", j, g.in, s, g.out[:32])
            }

            c.Reset()
        }
    }
}

func Test_GoldenV2_160(t *testing.T) {
    for i := 0; i < len(goldenV2); i++ {
        g := goldenV2[i]
        c := New2_160()
        buf := make([]byte, len(g.in)+4)
        for j := 0; j < 7; j++ {
            if j < 2 {
                io.WriteString(c, g.in)
            } else if j == 2 {
                io.WriteString(c, g.in[0:len(g.in)/2])
                c.Sum(nil)
                io.WriteString(c, g.in[len(g.in)/2:])
            } else if j > 2 {
                // test unaligned write
                buf = buf[1:]
                copy(buf, g.in)
                c.Write(buf[:len(g.in)])
            }

            s := fmt.Sprintf("%x", c.Sum(nil))
            if s != g.out[:40] {
                t.Errorf("tiger[%d](%s) = %s want %s", j, g.in, s, g.out[:40])
            }

            c.Reset()
        }
    }
}
