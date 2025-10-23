package pbes1

import (
    "io"
    "hash"
    "errors"
    "crypto/cipher"
    "encoding/asn1"
)

// pbe 数据
type pbeCBCParams struct {
    Salt           []byte
    IterationCount int
}

// cbc 模式加密
type CipherBlockCBC struct {
    // 对称加密
    cipherFunc     func(key []byte) (cipher.Block, error)
    // hash 摘要
    hashFunc       func() hash.Hash
    // 密钥生成
    derivedKeyFunc DerivedKeyFunc
    // salt 长度
    saltSize       int
    // 与 key 长度相关
    keySize        int
    // 与 iv 长度相关
    blockSize      int
    // 迭代次数
    iterationCount int
    // oid
    oid            asn1.ObjectIdentifier
    // 是否有 KeyLength
    hasKeyLength   bool
    // 密码是否需要 Bmp 处理
    needBmpPass    bool
}

// 值大小
func (this CipherBlockCBC) KeySize() int {
    return this.keySize
}

// oid
func (this CipherBlockCBC) OID() asn1.ObjectIdentifier {
    return this.oid
}

// 是否有 KeyLength
func (this CipherBlockCBC) HasKeyLength() bool {
    return this.hasKeyLength
}

// 密码是否需要 Bmp 处理
func (this CipherBlockCBC) NeedBmpPassword() bool {
    return this.needBmpPass
}

// 加密
func (this CipherBlockCBC) Encrypt(rand io.Reader, password, plaintext []byte) ([]byte, []byte, error) {
    salt := make([]byte, this.saltSize)
    if _, err := io.ReadFull(rand, salt); err != nil {
        return nil, nil, errors.New("pkcs1: failed to generate salt: " + err.Error())
    }

    key, iv := this.derivedKeyFunc(string(password), string(salt), this.iterationCount, this.keySize, this.blockSize, this.hashFunc)

    block, err := this.cipherFunc(key)
    if err != nil {
        return nil, nil, errors.New("go-cryptobin/pkcs:" + err.Error() + " failed to create cipher")
    }

    // 加密数据补码
    plaintext = pkcs7Padding(plaintext, this.blockSize)

    // 需要保存的加密数据
    encrypted := make([]byte, len(plaintext))

    enc := cipher.NewCBCEncrypter(block, iv)
    enc.CryptBlocks(encrypted, plaintext)

    // 返回数据
    paramBytes, err := asn1.Marshal(pbeCBCParams{
        Salt:           salt,
        IterationCount: this.iterationCount,
    })
    if err != nil {
        return nil, nil, err
    }

    return encrypted, paramBytes, nil
}

// 解密
func (this CipherBlockCBC) Decrypt(password, params, ciphertext []byte) ([]byte, error) {
    var param pbeCBCParams
    if _, err := asn1.Unmarshal(params, &param); err != nil {
        return nil, errors.New("go-cryptobin/pkcs: invalid PBES2 parameters")
    }

    key, iv := this.derivedKeyFunc(string(password), string(param.Salt), param.IterationCount, this.keySize, this.blockSize, this.hashFunc)

    block, err := this.cipherFunc(key)
    if err != nil {
        return nil, err
    }

    blockSize := block.BlockSize()

    if len(ciphertext)%blockSize != 0 {
        return nil, errors.New("go-cryptobin/pkcs: encrypted PEM data is not a multiple of the block size")
    }

    plaintext := make([]byte, len(ciphertext))

    mode := cipher.NewCBCDecrypter(block, iv)
    mode.CryptBlocks(plaintext, ciphertext)

    // 判断数据是否为填充数据
    dlen := len(plaintext)
    if dlen == 0 || dlen%blockSize != 0 {
        return nil, errors.New("go-cryptobin/pkcs: invalid padding")
    }

    // 解析加密数据
    pt, err := pkcs7UnPadding(plaintext)
    if err != nil {
        return plaintext, nil
    }

    return pt, nil
}

// 设置 saltSize
func (this CipherBlockCBC) WithSaltSize(saltSize int) CipherBlockCBC {
    this.saltSize = saltSize

    return this
}

// 设置 saltSize
func (this CipherBlockCBC) WithKeySize(keySize int) CipherBlockCBC {
    this.keySize = keySize

    return this
}

// 设置 derivedKeyFunc
func (this CipherBlockCBC) WithDerivedKeyFunc(derivedKeyFunc DerivedKeyFunc) CipherBlockCBC {
    this.derivedKeyFunc = derivedKeyFunc

    return this
}

func (this CipherBlockCBC) WithHasKeyLength(hasKeyLength bool) CipherBlockCBC {
    this.hasKeyLength = hasKeyLength

    return this
}

func (this CipherBlockCBC) WithNeedBmpPassword(needBmpPass bool) CipherBlockCBC {
    this.needBmpPass = needBmpPass

    return this
}
