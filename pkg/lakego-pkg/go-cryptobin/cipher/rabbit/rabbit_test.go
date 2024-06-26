package rabbit_test

import (
    "fmt"
    "bytes"
    "testing"
    "encoding/hex"

    "github.com/deatil/go-cryptobin/cipher/rabbit"
)

func Test_NewCipher(t *testing.T) {
    key, ivt := []byte("12345678abcdefgh"), []byte("1234qwer")
    txt := "test NewReadercipher text dummy tx"
    cph, err := rabbit.NewCipher(key, ivt)
    if err != nil {
        t.Fatal(err)
    }
    dst := make([]byte, len(txt))
    cph.XORKeyStream(dst, []byte(txt))

    cph, err = rabbit.NewCipher(key, ivt)
    if err != nil {
        t.Fatal(err)
    }

    nds := make([]byte, len(dst))
    cph.XORKeyStream(nds, dst)
    if string(nds) != txt {
        t.Error("error: nds is not equal to txt")
    }

}

var testDatas = []struct {
    key string
    iv string
    plain string
    cipher string
} {
    {
        "12345678901234561234567890123456",
        "",
        "0000000000000000",
        "d55293bba40cadf0",
    },
    {
        "12345678901234561234567890123456",
        "1234567812345678",
        "0000000000000000",
        "da7671fb2e61c40a",
    },
    {
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
        "1234567812345678",
        "0000000000000000",
        "22e8c9583f950d46",
    },
}

func Test_Check(t *testing.T) {
    for _, v := range testDatas {
        keyBytes, _ := hex.DecodeString(v.key)
        ivBytes, _ := hex.DecodeString(v.iv)
        plainBytes, _ := hex.DecodeString(v.plain)
        cipherBytes, _ := hex.DecodeString(v.cipher)

        c, err := rabbit.NewCipher(keyBytes, ivBytes)
        if err != nil {
            t.Fatal(err.Error())
        }

        var encrypted []byte = make([]byte, len(plainBytes))
        c.XORKeyStream(encrypted[:], plainBytes)

        if !bytes.Equal(encrypted, cipherBytes) {
            t.Errorf("encryption/decryption failed: got %x, want %x", encrypted, cipherBytes)
        }

        // =================

        c2, err := rabbit.NewCipher(keyBytes, ivBytes)
        if err != nil {
            t.Fatal(err.Error())
        }

        var decrypted []byte = make([]byte, len(cipherBytes))
        c2.XORKeyStream(decrypted[:], cipherBytes)

        if !bytes.Equal(decrypted, plainBytes) {
            t.Errorf("encryption/decryption failed: got %x, want %x", decrypted, plainBytes)
        }
    }
}

func Benchmark_NewCipher(b *testing.B) {
    b.Run(fmt.Sprintf("bench %v", b.N), func(b *testing.B) {
        for i := 0; i < b.N; i++ {
            key, ivt := []byte("12345678abcdefgh"), []byte("1234qwer")
            txt := "test NewReadercipher text dummy tx"
            cph, err := rabbit.NewCipher(key, ivt)
            if err != nil {
                b.Fatal(err)
            }
            dst := make([]byte, len(txt))
            cph.XORKeyStream(dst, []byte(txt))

            cph, err = rabbit.NewCipher(key, ivt)
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
