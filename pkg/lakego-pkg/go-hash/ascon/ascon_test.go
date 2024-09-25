package ascon

import (
    "fmt"
    "hash"
    "bytes"
    "testing"
    "crypto/cipher"
    "encoding/hex"
)

func fromHex(s string) []byte {
    b, err := hex.DecodeString(s)
    if err != nil {
        panic(err)
    }

    return b
}

func Test_Interface(t *testing.T) {
    var _ hash.Hash = (*Hash)(nil)
    var _ cipher.AEAD = (*AEAD)(nil)
}

func Test_Hashs(t *testing.T) {
    // Test that the hardcoded initial state equals the computed values
    h := NewHash()
    g := new(Hash)
    g.initHash(64, 12, 12, 256)
    got := h.s
    want := g.s
    for i := range got {
        if got[i] != want[i] {
            t.Errorf("Hash: s[%d] = %016x, want %016x", i, got[i], want[i])
        }
    }

    h = NewHasha()
    got = h.s
    g.initHash(64, 12, 8, 256)
    want = g.s
    for i := range got {
        if got[i] != want[i] {
            t.Errorf("Hasha: s[%d] = %016x, want %016x", i, got[i], want[i])
        }
    }
}

func hashBytes(b []byte) []byte {
    h := NewHash()
    h.Write(b)
    return h.Sum(nil)
}

func Test_Hash_Check(t *testing.T) {
    want := "7346BC14F036E87AE03D0997913088F5F68411434B3CF8B54FA796A80D251F91"
    got := fmt.Sprintf("%X", hashBytes(nil))
    if got != want {
        t.Errorf("got %s, want %s", got, want)
    }
}

func Test_Hasha_Check(t *testing.T) {
    h := NewHasha()
    want := "AECD027026D0675F9DE7A8AD8CCF512DB64B1EDCF0B20C388A0C7CC617AAA2C4"
    got := fmt.Sprintf("%X", h.Sum(nil))
    if got != want {
        t.Errorf("got %s, want %s", got, want)
    }

    // check that Sum is idempotent
    got = fmt.Sprintf("%X", h.Sum(nil))
    if got != want {
        t.Errorf("got %s, want %s", got, want)
    }
}

func Test_XofChunks(t *testing.T) {
    init := NewXof()
    init.Write([]byte("abc"))

    const N = 2016

    expected := make([]byte, N)
    d := init.Clone()
    d.readAll(expected)

    for chunkSize := 1; chunkSize < N; chunkSize++ {
        output := make([]byte, N)
        d := init.Clone()
        for i := 0; i < len(output); i += chunkSize {
            end := i + chunkSize
            if end > len(output) {
                end = len(output)
            }
            nread, err := d.Read(output[i:end])
            if len := end - i; nread != len || err != nil {
                t.Errorf("Read(%d) returned n=%v, err=%v expected n=%v, err=nil", len, nread, err, len)
            }
        }
        if !bytes.Equal(output, expected) {
            t.Errorf("Chunked read of %d bytes: got %X, want %X", chunkSize, output, expected)
        }
    }

    output := make([]byte, N)
    d = init.Clone()
    for i, j := 0, 0; i < len(output); i, j = i+j, j+1 {
        end := i + j
        if end > len(output) {
            end = len(output)
        }
        d.Read(output[i:end])
        if !bytes.Equal(output[i:end], expected[i:end]) {
            t.Errorf("Read of %d bytes after %d: got %X, want %X", j, i, output[i:end], expected[i:end])
        }
    }
    if !bytes.Equal(output, expected) {
        t.Error("Chunked reads differ from expected")
    }
}

func Test_AEAD(t *testing.T) {
    for _, td := range testAEADs {
        var (
            key   = td.key
            nonce = td.nonce
            text  = td.text
            ad    = td.ad
            want  = td.want
        )

        a := new(AEAD)
        copy(a.key[:], key)
        c := a.Seal(nil, nonce, text, ad)

        if !bytes.Equal(c, want) {
            t.Errorf("got %x, want %x", c, want)
        }
    }
}

type testAEAD struct {
    key []byte
    nonce []byte
    text []byte
    ad []byte
    want []byte
}

var testAEADs = []testAEAD{
    // Count = 514
    {
        key:   fromHex("000102030405060708090A0B0C0D0E0F"),
        nonce: fromHex("000102030405060708090A0B0C0D0E0F"),
        text:  fromHex("000102030405060708090A0B0C0D0E"),
        ad:    fromHex("000102030405060708090A0B0C0D0E0F1011"),
        want:  fromHex("77AA511159627C4B855E67F95B3ABFA1FA8B51439743E4C8B41E4E76B40460"),
    },
    // Count = 496
    {
        key:   fromHex("000102030405060708090A0B0C0D0E0F"),
        nonce: fromHex("000102030405060708090A0B0C0D0E0F"),
        text:  fromHex("000102030405060708090A0B0C0D0E"),
        ad:    fromHex(""),
        want:  fromHex("BC820DBDF7A4631C5B29884AD6917516D420A5BC2E5357D010818F0B5F7859"),
    },
}

func newAEAD(key []byte) *AEAD {
    a := new(AEAD)
    copy(a.key[:], key)
    return a
}

func FuzzAEAD(f *testing.F) {
    key := []byte("my special key..")
    nonce := []byte("my special nonce")

    f.Add(byte(0x00), byte(0x00), 8, 0, byte(0x00), 0)
    f.Fuzz(func(t *testing.T,
        msgByte, adByte byte,
        msgLen, adLen int,
        noise byte, noiseIndex int,
    ) {
        a := newAEAD(key)
        if msgLen < 0 || msgLen > 0x4000 {
            return
        }
        if adLen < 0 || adLen > 0x100 {
            return
        }
        msg := bytes.Repeat([]byte{msgByte}, msgLen)
        ad := bytes.Repeat([]byte{adByte}, adLen)
        ciphertext := a.Seal(nil, nonce, msg, ad)
        decrypted, err := a.Open(nil, nonce, ciphertext, ad)
        if err != nil {
            t.Error(err)
        } else if !bytes.Equal(decrypted, msg) {
            t.Error("plaintext mismatch")
        }

        doNoise := func(name string, thing []byte) {
            if len(thing) > 0 {
                i := noiseIndex % len(thing)
                thing[i] ^= noise
                _, err := a.Open(nil, nonce, ciphertext, ad)
                thing[i] ^= noise
                if err == nil {
                    t.Error("Open succeeded with a modified ", name)
                }
            }
        }
        if noise != 0 && noiseIndex >= 0 {
            doNoise("nonce", nonce)
            doNoise("ciphertext", ciphertext)
            doNoise("additional data", ad)
        }
    })

}

