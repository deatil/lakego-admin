package lion

import (
    "hash"
    "bytes"
    "testing"
    "math/rand"
    "crypto/md5"
    "crypto/rc4"
    "crypto/sha1"
    "crypto/cipher"
    "encoding/hex"
)

func fromHex(s string) []byte {
    h, _ := hex.DecodeString(s)
    return h
}

var newRc4Cipher = func(key []byte) (cipher.Stream, error) {
    return rc4.NewCipher(key)
}

func Test_Cipher(t *testing.T) {
    random := rand.New(rand.NewSource(99))
    max := 100

    var encrypted [36]byte
    var decrypted [36]byte

    for i := 0; i < max; i++ {
        key := make([]byte, 16)
        random.Read(key)
        value := make([]byte, 36)
        random.Read(value)

        cipher1, err := NewCipher(md5.New(), newRc4Cipher, 36, key)
        if err != nil {
            t.Fatal(err.Error())
        }

        cipher1.Encrypt(encrypted[:], value)

        if bytes.Equal(encrypted[:], value[:]) {
            t.Errorf("fail: encrypted equal plaintext \n")
        }

        cipher2, err := NewCipher(md5.New(), newRc4Cipher, 36, key)
        if err != nil {
            t.Fatal(err.Error())
        }

        cipher2.Decrypt(decrypted[:], encrypted[:])

        if !bytes.Equal(decrypted[:], value[:]) {
            t.Errorf("encryption/decryption failed: % 02x != % 02x\n", decrypted, value)
        }
    }
}

var cipTests = []struct {
    hash   hash.Hash
    cip    Streamer
    bs     int
    key    []byte
    plain  []byte
    cipher []byte
}{
    // [Lion(SHA-1,RC4,64)]
    {
        sha1.New(),
        newRc4Cipher,
        64,
        fromHex("00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF"),
        fromHex("1112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F3031323334353637382015B3DB2DC49529C2D26B1F1E86C65EC7B946AB2D2E2F30"),
        fromHex("BCE3BE866EF63AF5AD4CBA8C3CAA2AA9CF9BB3CC2A3D77FF7C05D0EC7E684AD6134ABFD7DF6842B7292071064C9F4DFE4B9D34EAE89201136B7CE70ED4A190DB"),
    },

}

func Test_Check(t *testing.T) {
    for _, tt := range cipTests {
        c, err := NewCipher(tt.hash, tt.cip, tt.bs, tt.key)
        if err != nil {
            t.Fatal(err)
        }

        b := make([]byte, len(tt.plain))
        c.Encrypt(b[:], tt.plain)
        if !bytes.Equal(b[:], tt.cipher) {
            t.Errorf("encrypt failed: got %x, want %x", b, tt.cipher)
        }

        c.Decrypt(b[:], tt.cipher)
        if !bytes.Equal(b[:], tt.plain) {
            t.Errorf("decrypt failed: got %x, want %x", b, tt.plain)
        }
    }
}

