package pbes2

import (
    "io"
    "sync"
    "errors"
    "crypto/cipher"
    "encoding/asn1"

    "github.com/deatil/go-cryptobin/cipher/gost"
)

var (
    oidGostTc26CipherZ = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 2, 5, 1, 1}
)

var gostMu sync.RWMutex

type GostSbox struct {
    OID  asn1.ObjectIdentifier
    Sbox [][]byte
}

var gostSboxs = make(map[string]GostSbox)

func AddGostSbox(name string, sbox GostSbox) {
    gostMu.Lock()
    defer gostMu.Unlock()

    gostSboxs[name] = sbox
}

func GetGostSbox(name string) (GostSbox, bool) {
    gostMu.RLock()
    defer gostMu.RUnlock()

    if sbox, ok := gostSboxs[name]; ok {
        return sbox, true
    }

    return GostSbox{}, false
}

func GetGostSboxByOID(oid asn1.ObjectIdentifier) ([][]byte, bool) {
    gostMu.RLock()
    defer gostMu.RUnlock()

    for _, sbox := range gostSboxs {
        if sbox.OID.Equal(oid) {
            return sbox.Sbox, true
        }
    }

    return nil, false
}

func init() {
    AddGostSbox("tc26CipherZ", GostSbox{
        OID:  oidGostTc26CipherZ,
        Sbox: gost.SboxTC26gost28147paramZ,
    })
}

// Gost CFB 模式加密参数
type gostCfbParams struct {
    IV      []byte
    SboxOid asn1.ObjectIdentifier
}

// Gost CFB 模式加密
type CipherGostCFB struct {
    cipherFunc   func(key []byte, sbox [][]byte) (cipher.Block, error)
    keySize      int
    blockSize    int
    identifier   asn1.ObjectIdentifier
    sboxOid      asn1.ObjectIdentifier
    hasKeyLength bool
    needPassBmp  bool
}

// 值大小
func (this CipherGostCFB) KeySize() int {
    return this.keySize
}

// oid
func (this CipherGostCFB) OID() asn1.ObjectIdentifier {
    return this.identifier
}

// 是否有 KeyLength
func (this CipherGostCFB) HasKeyLength() bool {
    return this.hasKeyLength
}

// 密码是否需要 Bmp 处理
func (this CipherGostCFB) NeedPasswordBmpString() bool {
    return this.needPassBmp
}

// 加密
func (this CipherGostCFB) Encrypt(rand io.Reader, key, plaintext []byte) ([]byte, []byte, error) {
    sbox, ok := GetGostSboxByOID(this.sboxOid)
    if !ok {
        return nil, nil, errors.New("pkcs/cipher: failed to get cipher sbox")
    }

    block, err := this.cipherFunc(key, sbox)
    if err != nil {
        return nil, nil, errors.New("pkcs/cipher: failed to create cipher: " + err.Error())
    }

    // 随机生成 iv
    iv := make(cfbParams, this.blockSize)
    if _, err := io.ReadFull(rand, iv); err != nil {
        return nil, nil, errors.New("pkcs/cipher: failed to generate IV: " + err.Error())
    }

    // 需要保存的加密数据
    encrypted := make([]byte, len(plaintext))

    enc := cipher.NewCFBEncrypter(block, iv)
    enc.XORKeyStream(encrypted, plaintext)

    // 编码 iv
    paramBytes, err := asn1.Marshal(gostCfbParams{
        IV:      iv,
        SboxOid: this.sboxOid,
    })
    if err != nil {
        return nil, nil, err
    }

    return encrypted, paramBytes, nil
}

// 解密
func (this CipherGostCFB) Decrypt(key, params, ciphertext []byte) ([]byte, error) {
    // 解析出 iv
    var param gostCfbParams
    if _, err := asn1.Unmarshal(params, &param); err != nil {
        return nil, errors.New("pkcs/cipher: invalid parameters")
    }

    sbox, ok := GetGostSboxByOID(param.SboxOid)
    if !ok {
        return nil, errors.New("pkcs/cipher: invalid parameters sbox")
    }

    block, err := this.cipherFunc(key, sbox)
    if err != nil {
        return nil, err
    }

    iv := param.IV

    if len(iv) != block.BlockSize() {
        return nil, errors.New("pkcs/cipher: incorrect IV size")
    }

    plaintext := make([]byte, len(ciphertext))

    mode := cipher.NewCFBDecrypter(block, iv)
    mode.XORKeyStream(plaintext, ciphertext)

    return plaintext, nil
}

func (this CipherGostCFB) WithHasKeyLength(hasKeyLength bool) CipherGostCFB {
    this.hasKeyLength = hasKeyLength

    return this
}

func (this CipherGostCFB) WithNeedPasswordBmpString(needPassBmp bool) CipherGostCFB {
    this.needPassBmp = needPassBmp

    return this
}

func (this CipherGostCFB) WithSbox(name string) CipherGostCFB {
    sbox, ok := GetGostSbox(name)
    if ok {
        this.sboxOid = sbox.OID
    }

    return this
}
