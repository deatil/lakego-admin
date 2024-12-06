package mac

import (
    "crypto/cipher"
)

// Reference: GB/T 15821.1-2020 Security techniques
// Message authentication codes - Part 1: Mechanisms using block ciphers

// BlockCipherMAC is the interface that wraps the basic MAC method.
type BlockCipherMAC interface {
    // Size returns the MAC value's number of bytes.
    Size() int

    // MAC calculates the MAC of the given data.
    // The MAC value's number of bytes is returned by Size.
    // Intercept message authentication code as needed.
    MAC(src []byte) []byte
}

// BlockCipherFunc is creator func type
type BlockCipherFunc = func(key []byte) (cipher.Block, error)
