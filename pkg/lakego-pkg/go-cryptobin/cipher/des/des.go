package des

import (
    "strconv"
    "crypto/des"
    "crypto/cipher"
)

// The DES block size in bytes.
const BlockSize = des.BlockSize

type KeySizeError int

func (k KeySizeError) Error() string {
    return "crypto/des: invalid key size " + strconv.Itoa(int(k))
}

type twoDESCipher struct {
    key1 []byte
    key2 []byte
}

// NewTwoDESCipher creates and returns a new cipher.Block.
func NewTwoDESCipher(key []byte) (cipher.Block, error) {
    if len(key) != 16 {
        return nil, KeySizeError(len(key))
    }

    c := new(twoDESCipher)
    c.key1 = key[:8]
    c.key2 = key[8:]

    return c, nil
}

func (c *twoDESCipher) BlockSize() int {
    return des.BlockSize
}

func (c *twoDESCipher) Encrypt(dst, src []byte) {
    encoded, err := desEncrypt(c.key1, src)
    if err != nil {
        panic(err.Error())
    }

    encoded, err = desEncrypt(c.key2, encoded)
    if err != nil {
        panic(err.Error())
    }

    copy(dst, encoded)
}

func (c *twoDESCipher) Decrypt(dst, src []byte) {
    decoded, err := desDecrypt(c.key2, src)
    if err != nil {
        panic(err.Error())
    }

    decoded, err = desDecrypt(c.key1, decoded)
    if err != nil {
        panic(err.Error())
    }

    copy(dst, decoded)
}

// Encrypt data
func desEncrypt(key []byte, data []byte) ([]byte, error) {
    block, err := des.NewCipher(key)
    if err != nil {
        return nil, err
    }

    dst := make([]byte, len(data))
    block.Encrypt(dst, data)

    return dst, nil
}

// Decrypt data
func desDecrypt(key []byte, data []byte) ([]byte, error) {
    block, err := des.NewCipher(key)
    if err != nil {
        return nil, err
    }

    dst := make([]byte, len(data))
    block.Decrypt(dst, data)

    return dst, nil
}
