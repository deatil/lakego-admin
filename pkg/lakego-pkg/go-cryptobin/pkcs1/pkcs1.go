package pkcs1

// RFC 1423 describes the encryption of PEM blocks. The algorithm used to
// generate a key from the password was derived by looking at the OpenSSL
// implementation.

import (
    "io"
    "errors"
    "strings"
    "encoding/hex"
    "encoding/pem"
)

// IsEncryptedPEMBlock returns whether the PEM block is password encrypted
// according to RFC 1423.
//
// Deprecated: Legacy PEM encryption as specified in RFC 1423 is insecure by
// design. Since it does not authenticate the ciphertext, it is vulnerable to
// padding oracle attacks that can let an attacker recover the plaintext.
func IsEncryptedPEMBlock(b *pem.Block) bool {
    _, ok := b.Headers["DEK-Info"]
    return ok
}

// IncorrectPasswordError is returned when an incorrect password is detected.
var IncorrectPasswordError = errors.New("go-cryptobin/pkcs1: decryption password incorrect")

// DecryptPEMBlock takes a PEM block encrypted according to RFC 1423 and the
// password used to encrypt it and returns a slice of decrypted DER encoded
// bytes. It inspects the DEK-Info header to determine the algorithm used for
// decryption. If no DEK-Info header is present, an error is returned. If an
// incorrect password is detected an IncorrectPasswordError is returned. Because
// of deficiencies in the format, it's not always possible to detect an
// incorrect password. In these cases no error will be returned but the
// decrypted DER bytes will be random noise.
//
// Deprecated: Legacy PEM encryption as specified in RFC 1423 is insecure by
// design. Since it does not authenticate the ciphertext, it is vulnerable to
// padding oracle attacks that can let an attacker recover the plaintext.
func DecryptPEMBlock(b *pem.Block, password []byte) ([]byte, error) {
    dek, ok := b.Headers["DEK-Info"]
    if !ok {
        return nil, errors.New("go-cryptobin/pkcs1: no DEK-Info header in block")
    }

    mode, hexIV, ok := strings.Cut(dek, ",")
    if !ok {
        return nil, errors.New("go-cryptobin/pkcs1: malformed DEK-Info header")
    }

    ciph, err := cipherByName(mode)
    if err != nil {
        return nil, errors.New("go-cryptobin/pkcs1: unknown encryption mode")
    }

    iv, err := hex.DecodeString(hexIV)
    if err != nil {
        return nil, err
    }

    if len(iv) != ciph.BlockSize() {
        return nil, errors.New("go-cryptobin/pkcs1: incorrect IV size")
    }

    plaintext, err := ciph.Decrypt(password, iv, b.Bytes)
    if err != nil {
        return nil, err
    }

    return plaintext, nil
}

// EncryptPEMBlock returns a PEM block of the specified type holding the
// given DER encoded data encrypted with the specified algorithm and
// password according to RFC 1423.
//
// Deprecated: Legacy PEM encryption as specified in RFC 1423 is insecure by
// design. Since it does not authenticate the ciphertext, it is vulnerable to
// padding oracle attacks that can let an attacker recover the plaintext.
func EncryptPEMBlock(rand io.Reader, blockType string, data, password []byte, cipher Cipher) (*pem.Block, error) {
    if cipher == nil {
        return nil, errors.New("go-cryptobin/pkcs1: incorrect cipher")
    }

    // encrypt data
    encrypted, iv, err := cipher.Encrypt(rand, password, data)
    if err != nil {
        return nil, err
    }

    return &pem.Block{
        Type: blockType,
        Headers: map[string]string{
            "Proc-Type": "4,ENCRYPTED",
            "DEK-Info":  cipher.Name() + "," + hex.EncodeToString(iv),
        },
        Bytes: encrypted,
    }, nil
}

func cipherByName(name string) (Cipher, error) {
    newCipher, err := GetCipher(name)
    if err != nil {
        return nil, err
    }

    return newCipher, nil
}
