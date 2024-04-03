package cubehash

import (
    "fmt"
    "hash"
    "bytes"
    "encoding"
    "testing"
)

func Test_Interfaces(t *testing.T) {
    var _ hash.Hash = (*digest)(nil)
    var _ encoding.BinaryMarshaler = (*digest)(nil)
    var _ encoding.BinaryUnmarshaler = (*digest)(nil)
}

func Test_Sum(t *testing.T) {
    table := []struct {
        in   string
        want string
    }{
        {
            "",
            "37045cca405ee6fbdf815ed8b57c971b" +
                "b78dafb58f3ef676c977a716f66dbd8f" +
                "376fef59d2e0687cf5608c5dad53ba42" +
                "c8456269f3f3bcfb27d9b75caaa26e11",
        },
        {
            "Hello",
            "a3c2b3d38c940b46b51c286b0159bceb" +
                "34fa7ae4d307234f48a2ca4662a21ddc" +
                "5875fda2c2a5994bb4d45dbbb3218381" +
                "174d5dd5f0aae87db87d086dff46e3ae",
        },
        {
            "The quick brown fox jumped over the lazy dog.",
            "8be880e82d924eaa4c569758429c9edf" +
                "93f178b8ad078650c56fa02afd7d8213" +
                "fa3b0da03f75f866c82c24a206ef0709" +
                "775d1a11813b56075b1aaa29480e1060",
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

func Test_Marshal(t *testing.T) {
    a := New()
    a.Write([]byte{1, 2, 3})
    save, _ := a.(encoding.BinaryMarshaler).MarshalBinary()

    b := New()
    b.(encoding.BinaryUnmarshaler).UnmarshalBinary(save)

    asum := a.Sum(nil)
    bsum := b.Sum(nil)
    if !bytes.Equal(asum, bsum) {
        t.Errorf("UnmarshalBinary(...), got %x, want %x", bsum, asum)
    }
}

func Test_EmptyMessage(t *testing.T) {
    msg := ""

    {
        check := "44c6de3ac6c73c391bf0906cb7482600ec06b216c7c54a2a8688a6a42676577d"

        c := NewCubehash(256, 32, 16, 160, 160)
        c.Reset()
        c.Write([]byte(msg))
        dst := c.Sum(nil)

        if fmt.Sprintf("%x", dst) != check {
            t.Errorf("fail, got %x, want %s", dst, check)
        }
    }

    {
        check := "4a1d00bbcfcb5a9562fb981e7f7db3350fe2658639d948b9d57452c22328bb32f468b072208450bad5ee178271408be0b16e5633ac8a1e3cf9864cfbfc8e043a"

        c := NewCubehash(512, 32, 16, 160, 160)
        c.Reset()
        c.Write([]byte(msg))
        dst := c.Sum(nil)

        if fmt.Sprintf("%x", dst) != check {
            t.Errorf("fail, got %x, want %s", dst, check)
        }
    }

}

func Test_ShortMessage(t *testing.T) {
    msg := "Hello"

    {
        check := "e712139e3b892f2f5fe52d0f30d78a0cb16b51b217da0e4acb103dd0856f2db0"

        c := NewCubehash(256, 32, 16, 160, 160)
        c.Reset()
        c.Write([]byte(msg))
        dst := c.Sum(nil)

        if fmt.Sprintf("%x", dst) != check {
            t.Errorf("fail, got %x, want %s", dst, check)
        }
    }

    {
        check := "dcc0503aae279a3c8c95fa1181d37c418783204e2e3048a081392fd61bace883a1f7c4c96b16b4060c42104f1ce45a622f1a9abaeb994beb107fed53a78f588c"

        c := NewCubehash(512, 32, 16, 160, 160)
        c.Reset()
        c.Write([]byte(msg))
        dst := c.Sum(nil)

        if fmt.Sprintf("%x", dst) != check {
            t.Errorf("fail, got %x, want %s", dst, check)
        }
    }

}

func Test_LongerMessage(t *testing.T) {
    msg := "The quick brown fox jumps over the lazy dog"

    {
        check := "5151e251e348cbbfee46538651c06b138b10eeb71cf6ea6054d7ca5fec82eb79"

        c := NewCubehash(256, 32, 16, 160, 160)
        c.Reset()
        c.Write([]byte(msg))
        dst := c.Sum(nil)

        if fmt.Sprintf("%x", dst) != check {
            t.Errorf("fail, got %x, want %s", dst, check)
        }
    }

    {
        check := "bdba44a28cd16b774bdf3c9511def1a2baf39d4ef98b92c27cf5e37beb8990b7cdb6575dae1a548330780810618b8a5c351c1368904db7ebdf8857d596083a86"

        c := NewCubehash(512, 32, 16, 160, 160)
        c.Reset()
        c.Write([]byte(msg))
        dst := c.Sum(nil)

        if fmt.Sprintf("%x", dst) != check {
            t.Errorf("fail, got %x, want %s", dst, check)
        }
    }

}

func BenchmarkSum(b *testing.B) {
    var buf [1 << 20]byte
    c := New()
    for i := 0; i < b.N; i++ {
        c.Reset()
        c.Write(buf[:])
        c.Sum(nil)
    }
}
