package panama

import (
    "fmt"
    "hash"
    "testing"
)

func Test_Interfaces(t *testing.T) {
    var _ hash.Hash = (*digest)(nil)
}

func Test_Hash(t *testing.T) {
    msg := []byte("T")
    check := "049d698307d8541f22870dfa0a551099d3d02bc6d57c610a06a4585ed8d35ff8"

    h := New()
    h.Write(msg)

    got := fmt.Sprintf("%x", h.Sum(nil))
    if got != check {
        t.Errorf("fail, got %s, want %s", got, check)
    }
}

func Test_KatMillionA_Hash(t *testing.T) {
    msg := make([]byte, 1000)
    for i := 0; i < 1000; i++ {
        msg[i] = 'a'
    }

    check := "af9c66fb6058e2232a5dfba063ee14b0f86f0e334e165812559435464dd9bb60"

    h := New()
    for i := 0; i < 1000; i++ {
        h.Write(msg)
    }

    got := fmt.Sprintf("%x", h.Sum(nil))
    if got != check {
        t.Errorf("fail, got %s, want %s", got, check)
    }
}

func Test_Sum(t *testing.T) {
    table := []struct {
        in   string
        want string
    }{
        {
            "",
            "aa0cc954d757d7ac7779ca3342334ca471abd47d5952ac91ed837ecd5b16922b",
        },
        {
            "T",
            "049d698307d8541f22870dfa0a551099d3d02bc6d57c610a06a4585ed8d35ff8",
        },
        {
            "The quick brown fox jumps over the lazy dog",
            "5f5ca355b90ac622b0aa7e654ef5f27e9e75111415b48b8afe3add1c6b89cba1",
        },
    }

    c := New()

    for _, r := range table {
        c.Reset()
        c.Write([]byte(r.in))
        got := fmt.Sprintf("%x", c.Sum(nil))
        if got != r.want {
            t.Errorf("New.Sum(%#v), got %#v, want %#v", r.in, got, r.want)
        }

        // =====

        sum2 := Sum([]byte(r.in))

        got = fmt.Sprintf("%x", sum2)
        if got != r.want {
            t.Errorf("Sum(%#v), got %#v, want %#v", r.in, got, r.want)
        }
    }

    for _, r := range table {
        c := New()
        for _, b := range []byte(r.in) {
            // byte at at time test
            c.Write([]byte{b})
        }

        got := fmt.Sprintf("%x", c.Sum(nil))
        if got != r.want {
            t.Errorf("Sum(%#v)b, got %#v, want %#v", r.in, got, r.want)
        }

        got2 := fmt.Sprintf("%x", c.Sum(nil))
        if got != got2 {
            t.Errorf("repeat Sum(), got %#v, want %#v", got2, got)
        }
    }
}
