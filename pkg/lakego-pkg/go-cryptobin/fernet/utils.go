package fernet

import (
    "crypto/aes"
    "crypto/hmac"
    "crypto/sha256"
    "encoding/binary"

    "github.com/deatil/go-cryptobin/padding"
)

func getu64(ptr []byte) uint64 {
    return binary.BigEndian.Uint64(ptr)
}

func putu64(ptr []byte, a uint64) {
    binary.BigEndian.PutUint64(ptr, a)
}

var usePadding = padding.NewPKCS7()

// Pads p to a multiple of k using PKCS #7 standard block padding.
func pad(q, p []byte, k int) int {
    pad := usePadding.Padding(p, k)
    copy(q, pad)

    return len(pad)
}

// Removes PKCS #7 standard block padding from p.
func unpad(p []byte) []byte {
    unpad, err := usePadding.UnPadding(p)
    if err != nil {
        return nil
    }

    return unpad
}

func hmacHash(p, k []byte) (q []byte) {
    h := hmac.New(sha256.New, k)
    h.Write(p)
    hashed := h.Sum(q)

    return hashed
}

// token length for input msg of length n, not including base64
func encodedLen(n int) int {
    const k = aes.BlockSize
    return n/k*k + k + overhead
}

// max msg length for tok of length n, for binary token (no base64)
// upper bound; not exact
func decodedLen(n int) int {
    return n - overhead
}
