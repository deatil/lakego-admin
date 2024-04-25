package xxh3

import (
    "fmt"
    "testing"
    "io/ioutil"
)

func testMustReadFile(tb testing.TB, filename string) []byte {
    tb.Helper()

    b, err := ioutil.ReadFile(filename)
    if err != nil {
        tb.Fatal(err)
    }

    return b
}

func fillTestBuffer(l int) []byte {
    const PRIME32 = 2654435761
    const PRIME64 = 11400714785074694797

    var byteGen uint64 = uint64(PRIME32)

    buffer := make([]byte, l)
    for i := 0; i < l; i++ {
        buffer[i] = byte(byteGen>>56)
        byteGen *= uint64(PRIME64)
    }

    return buffer
}

var vecs128 = [...]string{
    "e651ca75082952cc14bf9dd9043e9ff9",
    "165555094b7cbe4dc53d643361dd6cd0",
    "19eafccc1f1170e843bbe8f6e5ad911c",
}

func Test_XXH3_128(t *testing.T) {
    var data []byte

    for i, want := range vecs128 {
        data = append(data, byte(i))
        got := Sum128WithSeed(data[:i], 0x0102030405060708)
        if fmt.Sprintf("%x", got) != want {
            t.Errorf("[%d] got %x, want %s", i, got, want)
        }
    }
}

func Test_Hash64(t *testing.T) {
    in := []byte("nonce-asdfg56d6dd148d3df5947b54f0a0fb5e5b0234680cd7b4614bf3005c86fffb45257419b3133c39e551347cd3ad26850bd9513877ee2b708829f3f8f902377720655f56d6dd148d3df5947b54f0a0fb5e5b0234680cd7b4614bf3005c86fffb45257419b3133c39e551347cd3ad26850bd9513877ee2b708829f3f8f902377720655f")
    check := "3ddf6d234465a3df"

    {
        out := Sum64(in)

        if fmt.Sprintf("%x", out) != check {
            t.Errorf("Check error. got %x, want %s", out, check)
        }
    }

    // ==========

    {
        out := Hash_64bits(in)

        if fmt.Sprintf("%x", out) != check {
            t.Errorf("Check error. got %x, want %s", out, check)
        }
    }
}

func Test_Hash128(t *testing.T) {
    in := []byte("nonce-asdfg56d6dd148d3df5947b54f0a0fb5e5b0234680cd7b4614bf3005c86fffb45257419b3133c39e551347cd3ad26850bd9513877ee2b708829f3f8f902377720655f56d6dd148d3df5947b54f0a0fb5e5b0234680cd7b4614bf3005c86fffb45257419b3133c39e551347cd3ad26850bd9513877ee2b708829f3f8f902377720655f")
    check := "4559a89aaeab6e363ddf6d234465a3df"

    {
        out := Sum128(in)

        if fmt.Sprintf("%x", out) != check {
            t.Errorf("Check error. got %x, want %s", out, check)
        }
    }

    // ===========

    {
        out := Hash_128bits(in).Bytes()

        if fmt.Sprintf("%x", out) != check {
            t.Errorf("Check error. got %x, want %s", out, check)
        }
    }
}

type testHash128Data struct {
    msg []byte
    md  string
}

func Test_Hash128_Check(t *testing.T) {
    tests := []testHash128Data{
        {
            msg: []byte("Hello World !"),
            md: "8c52e3056b8541c2780aae38ba5d77fa",
        },
        {
            msg: []byte("The quick brown fox jumps over the lazy dog"),
            md: "ddd650205ca3e7fa24a1cc2e3a8a7651",
        },
        {
            msg: testMustReadFile(t, "testdata/Square Polano.txt"),
            md: "eb22f44e32ac3f14c437688e07426857",
        },
        {
            msg: testMustReadFile(t, "testdata/The Three-Cornered World.txt"),
            md: "9ca1941dfdfd1dd72f81241fcb240c15",
        },
    }

    md := New128()

    for i, td := range tests {
        {
            out := Sum128(td.msg)
            if fmt.Sprintf("%x", out) != td.md {
                t.Errorf("[%d] Check error. got %x, want %s", i, out, td.md)
            }
        }

        // new use
        {
            md.Reset()
            md.Write(td.msg)
            out := md.Sum(nil)

            if fmt.Sprintf("%x", out) != td.md {
                t.Errorf("[%d] New128 Check error. got %x, want %s", i, out, td.md)
            }
        }

    }
}
