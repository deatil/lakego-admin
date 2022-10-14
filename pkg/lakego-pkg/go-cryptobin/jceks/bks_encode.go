package jceks

import (
    "io"
    "fmt"
    "time"
    "bytes"
    "errors"
    "crypto"
    "crypto/sha1"
    "crypto/hmac"
)

// 添加
func (this *BKS) AddCert(alias string, certData []byte, certChain [][]byte) error {
    entry := &bksTrustedCertEntry{}
    entry.cert = certData
    entry.certType = "X509"

    entry.WithData(alias, time.Now(), certChain)

    this.entries[alias] = entry

    return nil
}

// 添加私钥
func (this *BKS) AddKeyPrivate(
    alias string,
    privateKey crypto.PrivateKey,
    certChain [][]byte,
) error {
    priKey, err := MarshalPKCS8PrivateKey(privateKey)
    if err != nil {
        return err
    }

    algorithm, err := GetPKCS8PrivateKeyAlgorithm(privateKey)
    if err != nil {
        return err
    }

    entry := &bksKeyEntry{}
    entry.keyType = bksKeyTypePrivate
    entry.format = "PKCS8" // PKCS8 | PKCS#8
    entry.algorithm = algorithm
    entry.encoded = priKey

    entry.WithData(alias, time.Now(), certChain)

    this.entries[alias] = entry

    return nil
}

// 添加私钥
func (this *BKS) AddKeyPrivateWithPassword(
    alias string,
    privateKey crypto.PrivateKey,
    password string,
    certChain [][]byte,
) error {
    priKey, err := MarshalPKCS8PrivateKey(privateKey)
    if err != nil {
        return err
    }

    algorithm, err := GetPKCS8PrivateKeyAlgorithm(privateKey)
    if err != nil {
        return err
    }

    entry := &bksKeyEntry{}
    entry.keyType = bksKeyTypePrivate
    entry.format = "PKCS8" // PKCS8 | PKCS#8
    entry.algorithm = algorithm
    entry.encoded = priKey

    sealedEntry := &bksSealedKeyEntry{
        nested:   entry,
        password: password,
    }
    sealedEntry.WithData(alias, time.Now(), certChain)

    this.entries[alias] = sealedEntry

    return nil
}

// 添加公钥
func (this *BKS) AddKeyPublic(
    alias string,
    publicKey crypto.PublicKey,
    certChain [][]byte,
) error {
    pubKey, err := MarshalPKCS8PublicKey(publicKey)
    if err != nil {
        return err
    }

    algorithm, err := GetPKCS8PublicKeyAlgorithm(publicKey)
    if err != nil {
        return err
    }

    entry := &bksKeyEntry{}
    entry.keyType = bksKeyTypePublic
    entry.format = "X509" // X.509 | X509
    entry.algorithm = algorithm
    entry.encoded = pubKey

    entry.WithData(alias, time.Now(), certChain)

    this.entries[alias] = entry

    return nil
}

// 添加公钥
func (this *BKS) AddKeyPublicWithPassword(
    alias string,
    publicKey crypto.PublicKey,
    password string,
    certChain [][]byte,
) error {
    pubKey, err := MarshalPKCS8PublicKey(publicKey)
    if err != nil {
        return err
    }

    algorithm, err := GetPKCS8PublicKeyAlgorithm(publicKey)
    if err != nil {
        return err
    }

    entry := &bksKeyEntry{}
    entry.keyType = bksKeyTypePublic
    entry.format = "X509" // X.509 | X509
    entry.algorithm = algorithm
    entry.encoded = pubKey

    sealedEntry := &bksSealedKeyEntry{
        nested:   entry,
        password: password,
    }
    sealedEntry.WithData(alias, time.Now(), certChain)

    this.entries[alias] = sealedEntry

    return nil
}

// 添加密钥
// algorithm = "AES"
func (this *BKS) AddKeySecret(
    alias string,
    secret []byte,
    algorithm string,
    certChain [][]byte,
) error {
    entry := &bksKeyEntry{}
    entry.keyType = bksKeyTypeSecret
    entry.format = "RAW"
    entry.algorithm = algorithm
    entry.encoded = secret

    entry.WithData(alias, time.Now(), certChain)

    this.entries[alias] = entry

    return nil
}

// 添加密钥
// algorithm = "AES"
func (this *BKS) AddKeySecretWithPassword(
    alias string,
    secret []byte,
    password string,
    algorithm string,
    certChain [][]byte,
) error {
    entry := &bksKeyEntry{}
    entry.keyType = bksKeyTypeSecret
    entry.format = "RAW"
    entry.algorithm = algorithm
    entry.encoded = secret

    sealedEntry := &bksSealedKeyEntry{
        nested:   entry,
        password: password,
    }
    sealedEntry.WithData(alias, time.Now(), certChain)

    this.entries[alias] = sealedEntry

    return nil
}

// 添加证书
func (this *BKS) AddSecret(
    alias string,
    secretData []byte,
    certChain [][]byte,
) error {
    entry := &bksSecretKeyEntry{}
    entry.secret = secretData

    entry.WithData(alias, time.Now(), certChain)

    this.entries[alias] = entry

    return nil
}

func (this *BKS) marshalCert(w io.Writer, data *bksTrustedCertEntry) error {
    var err error

    err = writeUTF(w, data.certType)
    if err != nil {
        return err
    }

    err = writeBytes(w, data.cert)
    if err != nil {
        return err
    }

    return nil
}

func (this *BKS) marshalKey(w io.Writer, data *bksKeyEntry) error {
    var err error

    err = writeUint8(w, uint8(data.keyType))
    if err != nil {
        return err
    }

    err = writeUTF(w, data.format)
    if err != nil {
        return err
    }

    err = writeUTF(w, data.algorithm)
    if err != nil {
        return err
    }

    err = writeBytes(w, data.encoded)
    if err != nil {
        return err
    }

    return nil
}

func (this *BKS) marshalSecret(w io.Writer, data *bksSecretKeyEntry) error {
    var err error

    err = writeBytes(w, data.secret)
    if err != nil {
        return err
    }

    return nil
}

func (this *BKS) marshalSealed(w io.Writer, data *bksSealedKeyEntry) error {
    var err error

    encrypted, err := data.Encrypt()
    if err != nil {
        return err
    }

    err = writeBytes(w, encrypted)
    if err != nil {
        return err
    }

    return nil
}

// 包装
func (this *BKS) marshalEntryData(
    w io.Writer,
    tag int,
    entry BksEntry,
) error {
    var err error

    alias, date, certChain := entry.GetData()

    err = writeUint8(w, uint8(tag))
    if err != nil {
        return err
    }

    err = writeUTF(w, alias)
    if err != nil {
        return err
    }

    err = writeDate(w, date)
    if err != nil {
        return err
    }

    chainLength := len(certChain)

    err = writeInt32(w, int32(chainLength))
    if err != nil {
        return err
    }

    for i := 0; i < chainLength; i++ {
        err := this.marshalCert(w, &bksTrustedCertEntry{
            cert: certChain[i],
            certType: "X509",
        })
        if err != nil {
            return err
        }
    }

    return nil
}

// 包装
func (this *BKS) marshalEntries(w io.Writer) error {
    var err error

    for _, entry := range this.entries {
        switch e := entry.(type) {
            case *bksTrustedCertEntry:
                err = this.marshalEntryData(w, bksEntryTypeCert, e)
                if err != nil {
                    return err
                }

                err = this.marshalCert(w, e)
            case *bksKeyEntry:
                err = this.marshalEntryData(w, bksEntryTypeKey, e)
                if err != nil {
                    return err
                }

                err = this.marshalKey(w, e)
            case *bksSecretKeyEntry:
                err = this.marshalEntryData(w, bksEntryTypeSecret, e)
                if err != nil {
                    return err
                }

                err = this.marshalSecret(w, e)
            case *bksSealedKeyEntry:
                err = this.marshalEntryData(w, bksEntryTypeSealed, e)
                if err != nil {
                    return err
                }

                err = this.marshalSealed(w, e)
        }
    }

    if err != nil {
        return err
    }

    // 添加间隔
    err = writeUint8(w, uint8(0))

    return err
}

// 配置
type BKSOpts struct {
    Version        int
    SaltSize       int
    IterationCount int
}

// 默认配置
var BKSDefaultOpts = BKSOpts{
    Version:        1,
    SaltSize:       20,
    IterationCount: 10000,
}

func (this *BKS) Marshal(password string, opts ...BKSOpts) ([]byte, error) {
    opt := BKSDefaultOpts
    if len(opts) > 0 {
        opt = opts[0]
    }

    buf := bytes.NewBuffer(nil)

    var err error

    version := opt.Version
    iterationCount := opt.IterationCount

    if version != BksVersionV1 && version != BksVersionV2 {
        return nil, fmt.Errorf("Unsupported BKS keystore version; only V1 and V2 supported, use v%d", version)
    }

    err = writeUint32(buf, uint32(version))
    if err != nil {
        return nil, err
    }

    salt, err := genRandom(opt.SaltSize)
    if err != nil {
        return nil, errors.New("failed to generate salt")
    }

    err = writeBytes(buf, salt)
    if err != nil {
        return nil, err
    }

    err = writeInt32(buf, int32(iterationCount))
    if err != nil {
        return nil, err
    }

    entryBuf := bytes.NewBuffer(nil)

    // 编码数据
    err = this.marshalEntries(entryBuf)
    if err != nil {
        return nil, err
    }

    // 生成签名
    hmacFn := sha1.New
    hmacDigestSize := hmacFn().Size()
    hmacKeySize := hmacDigestSize*8
    if version == 1 {
        hmacKeySize = hmacDigestSize
    }

    hmacKey := derivedHmacKey(password, string(salt), iterationCount, hmacKeySize/8, hmacFn)

    hmac := hmac.New(sha1.New, hmacKey)
    hmac.Write(entryBuf.Bytes())
    computed := hmac.Sum([]byte{})

    _, err = io.Copy(buf, entryBuf)
    if err != nil {
        return nil, err
    }

    err = writeOnly(buf, computed)
    if err != nil {
        return nil, err
    }

    bufBytes := buf.Bytes()

    return bufBytes, nil
}
