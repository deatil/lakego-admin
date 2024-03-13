package rabbitio_test

import (
    "fmt"
    "testing"

    "github.com/deatil/go-cryptobin/cipher/rabbitio"
)

func TestNewCipher(t *testing.T) {
    key, ivt := []byte("12345678abcdefgh"), []byte("1234qwer")
    txt := "test NewReadercipher text dummy tx"
    cph, err := rabbitio.NewCipher(key, ivt)
    if err != nil {
        t.Fatal(err)
    }
    dst := make([]byte, len(txt))
    cph.XORKeyStream(dst, []byte(txt))

    cph, err = rabbitio.NewCipher(key, ivt)
    if err != nil {
        t.Fatal(err)
    }

    nds := make([]byte, len(dst))
    cph.XORKeyStream(nds, dst)
    if string(nds) != txt {
        t.Error("error: nds is not equal to txt")
    }

}

func BenchmarkNewCipher(b *testing.B) {
    b.Run(fmt.Sprintf("bench %v", b.N), func(b *testing.B) {
        for i := 0; i < b.N; i++ {
            key, ivt := []byte("12345678abcdefgh"), []byte("1234qwer")
            txt := "test NewReadercipher text dummy tx"
            cph, err := rabbitio.NewCipher(key, ivt)
            if err != nil {
                b.Fatal(err)
            }
            dst := make([]byte, len(txt))
            cph.XORKeyStream(dst, []byte(txt))

            cph, err = rabbitio.NewCipher(key, ivt)
            if err != nil {
                b.Fatal(err)
            }

            nds := make([]byte, len(dst))
            cph.XORKeyStream(nds, dst)
            if string(nds) != txt {
                b.Error("error: nds is not equal to txt")
            }
        }
    })

}
