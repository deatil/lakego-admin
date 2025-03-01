package pkcs12

import "errors"

var (
    // ErrDecryption represents a failure to decrypt the input.
    ErrDecryption = errors.New("go-cryptobin/pkcs12: decryption error, incorrect padding")

    // ErrIncorrectPassword is returned when an incorrect password is detected.
    // Usually, P12/PFX data is signed to be able to verify the password.
    ErrIncorrectPassword = errors.New("go-cryptobin/pkcs12: decryption password incorrect")
)

// NotImplementedError indicates that the input is not currently supported.
type NotImplementedError string

func (e NotImplementedError) Error() string {
    return "go-cryptobin/pkcs12: " + string(e)
}
