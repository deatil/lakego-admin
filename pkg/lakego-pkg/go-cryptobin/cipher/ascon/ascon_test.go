package ascon

import (
    "bufio"
    "bytes"
    "crypto/cipher"
    "encoding/hex"
    "fmt"
    "math/rand"
    "os"
    "path/filepath"
    "reflect"
    "strings"
    "testing"
    "testing/quick"
)

var stateType = reflect.TypeOf([5]uint64{})

func randState(rng *rand.Rand) state {
    v, ok := quick.Value(stateType, rng)
    if !ok {
        panic("got false")
    }
    x := v.Interface().([5]uint64)
    return state{
        x0: x[0],
        x1: x[1],
        x2: x[2],
        x3: x[3],
        x4: x[4],
    }
}

func TestRound(t *testing.T) {
    rng := rand.New(rand.NewSource(0xDEADBEEF))
    for i := 0; i < 1000; i++ {
        s := randState(rng)
        want, got := s, s
        C := uint64(i)
        roundGeneric(&want, C)
        round(&got, C)
        if want != got {
            t.Fatalf("expected %v, got %v", want, got)
        }
    }
}

func TestPermute(t *testing.T) {
    for _, tc := range []struct {
        name      string
        fn        func(*state)
        fnGeneric func(*state)
    }{
        {"p12", p12, p12Generic},
        {"p8", p8, p8Generic},
        {"p6", p6, p6Generic},
    } {
        rng := rand.New(rand.NewSource(0xDEADBEEF))
        t.Run(tc.name, func(t *testing.T) {
            for i := 0; i < 1000; i++ {
                s := randState(rng)
                want, got := s, s
                tc.fnGeneric(&want)
                tc.fn(&got)
                if want != got {
                    t.Fatalf("#%d: expected %v, got %v", i, want, got)
                }
            }
        })
    }
}

func TestVectors128(t *testing.T) {
    testVectors(t, New128, filepath.Join("testdata", "vectors_128.txt"))
}

func TestVectors128a(t *testing.T) {
    testVectors(t, New128a, filepath.Join("testdata", "vectors_128a.txt"))
}

func testVectors(t *testing.T, fn func([]byte) (cipher.AEAD, error), path string) {
    vecs, err := readVecs(path)
    if err != nil {
        t.Fatal(err)
    }
    for i, v := range vecs {
        c, err := fn(v.key)
        if err != nil {
            t.Fatalf("#%d: %v", i+1, err)
        }
        ciphertext := c.Seal(nil, v.nonce, v.pt, v.ad)
        if !bytes.Equal(ciphertext, v.ct) {
            t.Fatalf("#%d: expected %#x, got %#x", i+1, v.ct, ciphertext)
        }
        plaintext, err := c.Open(nil, v.nonce, v.ct, v.ad)
        if err != nil {
            t.Fatalf("#%d: %v", i+1, err)
        }
        if !bytes.Equal(plaintext, v.pt) {
            t.Fatalf("#%d: expected %#x, got %#x", i+1, v.pt, plaintext)
        }
    }
}

func BenchmarkSeal1K_128a(b *testing.B) {
    benchmarkSeal(b, New128a, make([]byte, 1024))
}

func BenchmarkOpen1K_128a(b *testing.B) {
    benchmarkOpen(b, New128a, make([]byte, 1024))
}

func BenchmarkSeal8K_128a(b *testing.B) {
    benchmarkSeal(b, New128a, make([]byte, 8*1024))
}

func BenchmarkOpen8K_128a(b *testing.B) {
    benchmarkOpen(b, New128a, make([]byte, 8*1024))
}

func BenchmarkSeal1K_128(b *testing.B) {
    benchmarkSeal(b, New128, make([]byte, 1024))
}

func BenchmarkOpen1K_128(b *testing.B) {
    benchmarkOpen(b, New128, make([]byte, 1024))
}

func BenchmarkSeal8K_128(b *testing.B) {
    benchmarkSeal(b, New128, make([]byte, 8*1024))
}

func BenchmarkOpen8K_128(b *testing.B) {
    benchmarkOpen(b, New128, make([]byte, 8*1024))
}

func benchmarkSeal(b *testing.B, fn func([]byte) (cipher.AEAD, error), buf []byte) {
    b.SetBytes(int64(len(buf)))

    key := make([]byte, KeySize)
    nonce := make([]byte, NonceSize)
    ad := make([]byte, 13)
    aead, err := fn(key)
    if err != nil {
        b.Fatal(err)
    }
    var out []byte

    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        out = aead.Seal(out[:0], nonce, buf, ad)
    }
}

func benchmarkOpen(b *testing.B, fn func([]byte) (cipher.AEAD, error), buf []byte) {
    b.SetBytes(int64(len(buf)))

    key := make([]byte, KeySize)
    nonce := make([]byte, NonceSize)
    ad := make([]byte, 13)
    aead, err := fn(key)
    if err != nil {
        b.Fatal(err)
    }
    var out []byte
    out = aead.Seal(out[:0], nonce, buf, ad)

    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        _, err := aead.Open(buf[:0], nonce, out, ad)
        if err != nil {
            b.Errorf("Open: %v", err)
        }
    }
}

type vector struct {
    key   []byte
    nonce []byte
    pt    []byte
    ad    []byte
    ct    []byte
}

func (v *vector) set(field string, p []byte) bool {
    switch field {
    case "Key":
        v.key = p
    case "Nonce":
        v.nonce = p
    case "PT":
        v.pt = p
    case "AD":
        v.ad = p
    case "CT":
        v.ct = p
    default:
        return false
    }
    return true
}

func readVecs(path string) ([]vector, error) {
    f, err := os.Open(path)
    if err != nil {
        return nil, err
    }
    defer f.Close()

    var vecs []vector

    s := bufio.NewScanner(f)
    for i := 0; s.Scan(); i++ {
        t := s.Text()
        if t == "" {
            continue
        }
        if strings.HasPrefix(t, "Count = ") {
            vecs = append(vecs, vector{})
            continue
        }
        i := strings.IndexByte(t, '=')
        if i < 0 {
            return nil, fmt.Errorf("malformed line %d: %q", i+1, t)
        }
        data := strings.TrimSpace(t[i+1:])
        buf, err := hex.DecodeString(data)
        if err != nil {
            return nil, fmt.Errorf("malformed line %d: %v", i+1, err)
        }
        field := strings.TrimSpace(t[:i])
        if !vecs[len(vecs)-1].set(field, buf) {
            return nil, fmt.Errorf("malformed line %d: %q", i+1, t)
        }
    }
    return vecs, nil
}
