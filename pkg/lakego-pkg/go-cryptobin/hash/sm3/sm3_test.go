package sm3

import (
    "io"
    "fmt"
    "testing"
    "crypto/hmac"
)

type sm3Test struct {
    out string
    in  string
}

var golden = []sm3Test{
    {"66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0", "abc"},
    {"debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732", "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd"},
    {"952eb84cacee9c10bde4d6882d29d63140ba72af6fe485085095dccd5b872453", "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabc"},
    {"90d52a2e85631a8d6035262626941fa11b85ce570cec1e3e991e2dd7ed258148", "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd"},
    {"e1c53f367a9c5d19ab6ddd30248a7dafcc607e74e6bcfa52b00e0ba35e470421", "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabc"},
    {"520472cafdaf21d994c5849492ba802459472b5206503389fc81ff73adbec1b4", "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabc"},
}

func Test_Check(t *testing.T) {
    for i := 0; i < len(golden); i++ {
        g := golden[i]
        h := Sum([]byte(g.in))
        sum := fmt.Sprintf("%x", h)

        if sum != g.out {
            t.Fatalf("Sum: got %s, want %s", sum, g.out)
        }

        c := New()
        for j := 0; j < 3; j++ {
            if j < 2 {
                io.WriteString(c, g.in)
            } else {
                io.WriteString(c, g.in[0:len(g.in)/2])
                c.Sum(nil)
                io.WriteString(c, g.in[len(g.in)/2:])
            }

            sum := fmt.Sprintf("%x", c.Sum(nil))
            if sum != g.out {
                t.Fatalf("New: got %s, want %s", sum, g.out)
            }

            c.Reset()
        }
    }
}

func Test_HmacSM3(t *testing.T) {
    key := []byte("1234567812345678")
    msg := []byte("abc")

    check := "0a69401a75c5d471f5166465eec89e6a65198ae885c1fdc061556254d91c1080"

    hash := hmac.New(New, key)
    hash.Write(msg)

    s := fmt.Sprintf("%x", hash.Sum(nil))
    if s != check {
        t.Errorf("error, got %s want %s", s, check)
    }
}
