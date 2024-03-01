package rabin

import (
    "fmt"
    "math/rand"
    "testing"
)

var testPolys = []uint64{
    0x11d,              // Degree 8 (smallest supported)
    0xbfe6b8a5bf378d83, // Degree 63 (largest supported)
}

func TestRabin(t *testing.T) {
    nTests := 100
    if testing.Short() {
        nTests = 5
    }

    for _, poly := range testPolys {
        tab := NewTable(poly, 0)
        t.Run("poly="+newPolyGF2(poly).String(), func(t *testing.T) {
            rg := rand.New(rand.NewSource(42))
            data := make([]byte, 64)
            for i := 0; i < nTests; i++ {
                rg.Read(data)
                h1 := rabinSlow(poly, data)
                h2 := New(tab)
                h2.Write(data)
                if h1 != h2.Sum64() {
                    t.Errorf("want hash %#x (%s), got %#x (%s) for %x", h1, newPolyGF2(h1), h2.Sum64(), newPolyGF2(h2.Sum64()), data)
                }
            }
        })
    }
}

// rabinSlow is a slow, very literal implementation of Rabin
// fingerprinting that doesn't support streaming.
func rabinSlow(poly uint64, data []byte) uint64 {
    var mpoly polyGF2
    mpoly.coeff.SetBytes(data)
    return mpoly.Mod(&mpoly, newPolyGF2(poly)).coeff.Uint64()
}

func TestWindow(t *testing.T) {
    rg := rand.New(rand.NewSource(42))
    data := make([]byte, 1024)
    rg.Read(data)

    for _, poly := range testPolys {
        hNoWin := New(NewTable(poly, 0))
        for _, window := range []int{1, 4, 64, 65} {
            hWin := New(NewTable(poly, window))
            t.Run(fmt.Sprintf("poly=%s/window=%d", newPolyGF2(poly), window), func(t *testing.T) {
                for _, blockSize := range []int{1, 2, 5, 100} {
                    hWin.Reset()
                    for i := 0; i < len(data); i += blockSize {
                        block := data[i:]
                        if len(block) > blockSize {
                            block = block[:blockSize]
                        }

                        hWin.Write(block)

                        dataWin := data[:i+len(block)]
                        if len(dataWin) > window {
                            dataWin = dataWin[len(dataWin)-window:]
                        }
                        hNoWin.Reset()
                        hNoWin.Write(dataWin)

                        // Check the hash.
                        if hNoWin.Sum64() != hWin.Sum64() {
                            t.Errorf("want hash %#x, got %#x at byte %d with %d byte blocks", hNoWin.Sum64(), hWin.Sum64(), i, blockSize)
                        }
                    }
                }
            })
        }
    }
}

func BenchmarkRabin(b *testing.B) {
    rg := rand.New(rand.NewSource(42))
    data := make([]byte, 1<<20)
    rg.Read(data)
    b.SetBytes(int64(len(data)))
    h := New(NewTable(Poly64, 0))
    b.ResetTimer()

    for i := 0; i < b.N; i++ {
        h.Reset()
        h.Write(data)
    }
}

func BenchmarkRabinWindowed64(b *testing.B) {
    const window = 64
    rg := rand.New(rand.NewSource(42))
    data := make([]byte, 1<<20)
    rg.Read(data)
    b.SetBytes(int64(len(data)))
    h := New(NewTable(Poly64, window))
    b.ResetTimer()

    for i := 0; i < b.N; i++ {
        h.Reset()
        // Feed it smaller blocks or it will just reset and
        // hash the end.
        for j := 0; j < len(data); j += window / 2 {
            h.Write(data[j : j+window/2])
        }
    }
}
