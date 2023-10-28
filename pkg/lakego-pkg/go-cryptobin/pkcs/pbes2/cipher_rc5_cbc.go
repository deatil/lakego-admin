package pbes2

import (
    "errors"
    "crypto/rand"
    "crypto/cipher"
    "encoding/asn1"
)

// cbc 模式加密参数
type rc5CBCParams struct {
    WordSize int
    Rounds   int
    IV       []byte
}

// cbc 模式加密
type CipherRC5CBC struct {
    cipherFunc func(key []byte, wordSize, r uint) (cipher.Block, error)
    wordSize   uint
    rounds     uint
    keySize    int
    identifier asn1.ObjectIdentifier
}

// 值大小
func (this CipherRC5CBC) KeySize() int {
    return this.keySize
}

// oid
func (this CipherRC5CBC) OID() asn1.ObjectIdentifier {
    return this.identifier
}

// 加密
func (this CipherRC5CBC) Encrypt(key, plaintext []byte) ([]byte, []byte, error) {
    block, err := this.cipherFunc(key, this.wordSize, this.rounds)
    if err != nil {
        return nil, nil, errors.New("pkcs/cipher: failed to create cipher: " + err.Error())
    }

    blockSize := block.BlockSize()

    // 随机生成 iv
    iv := make(cbcParams, blockSize)
    if _, err := rand.Read(iv); err != nil {
        return nil, nil, errors.New("pkcs/cipher: failed to generate IV: " + err.Error())
    }

    // 加密数据补码
    plaintext = pkcs7Padding(plaintext, blockSize)

    // 需要保存的加密数据
    encrypted := make([]byte, len(plaintext))

    enc := cipher.NewCBCEncrypter(block, iv)
    enc.CryptBlocks(encrypted, plaintext)

    // 需要编码的参数
    paramSeq := rc5CBCParams{
        WordSize: int(this.wordSize),
        Rounds:   int(this.rounds),
        IV:       iv,
    }

    // 编码
    paramBytes, err := asn1.Marshal(paramSeq)
    if err != nil {
        return nil, nil, err
    }

    return encrypted, paramBytes, nil
}

// 解密
func (this CipherRC5CBC) Decrypt(key, params, ciphertext []byte) ([]byte, error) {
    // 解析参数
    var param rc5CBCParams
    if _, err := asn1.Unmarshal(params, &param); err != nil {
        return nil, errors.New("pkcs/cipher: invalid parameters")
    }

    block, err := this.cipherFunc(key, uint(param.WordSize), uint(param.Rounds))
    if err != nil {
        return nil, err
    }

    blockSize := block.BlockSize()

    if len(param.IV) != blockSize {
        return nil, errors.New("pkcs/cipher: incorrect IV size")
    }

    if len(ciphertext)%blockSize != 0 {
        return nil, errors.New("pkcs/cipher: encrypted PEM data is not a multiple of the block size")
    }

    plaintext := make([]byte, len(ciphertext))

    mode := cipher.NewCBCDecrypter(block, param.IV)
    mode.CryptBlocks(plaintext, ciphertext)

    // 判断数据是否为填充数据
    dlen := len(plaintext)
    if dlen == 0 || dlen%blockSize != 0 {
        return nil, errors.New("pkcs/cipher: invalid padding")
    }

    // 解析加密数据
    plaintext, err = pkcs7UnPadding(plaintext)
    if err != nil {
        return nil, err
    }

    return plaintext, nil
}

// 设置 WordSize
func (this CipherRC5CBC) WithWordSize(wordSize uint) CipherRC5CBC {
    this.wordSize = wordSize

    return this
}

// 设置 Rounds
func (this CipherRC5CBC) WithRounds(rounds uint) CipherRC5CBC {
    this.rounds = rounds

    return this
}

// 设置 keySize
func (this CipherRC5CBC) WithKeySize(keySize int) CipherRC5CBC {
    this.keySize = keySize

    return this
}
