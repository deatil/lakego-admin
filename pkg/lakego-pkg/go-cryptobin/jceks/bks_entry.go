package jceks

import (
    "fmt"
    "time"
    "bytes"
    "errors"
    "crypto"
    "encoding/asn1"
)

type BksDataEntry interface {
    GetAlias() string
    GetDate() time.Time
    GetCertChain() [][]byte
}

type BksEntry interface {
    WithData(alias string, date time.Time, certChain [][]byte)
    GetData() (alias string, date time.Time, certChain [][]byte)

    IsDecrypted() bool
    Decrypt(password string) error
}

type abstractBksEntry struct {
    alias     string
    date      time.Time
    certChain [][]byte
}

func (this *abstractBksEntry) WithData(alias string, date time.Time, certChain [][]byte) {
    this.alias = alias
    this.date = date
    this.certChain = certChain
}

func (this *abstractBksEntry) GetData() (alias string, date time.Time, certChain [][]byte) {
    return this.alias, this.date, this.certChain
}

func (this *abstractBksEntry) GetAlias() string {
    return this.alias
}

func (this *abstractBksEntry) GetDate() time.Time {
    return this.date
}

func (this *abstractBksEntry) GetCertChain() [][]byte {
    return this.certChain
}

type bksKeyEntry struct {
    abstractBksEntry

    keyType   int
    format    string
    algorithm string
    encoded   []byte
}

func (this *bksKeyEntry) String() string {
    return fmt.Sprintf("plain-key: %s", this.date)
}

func (this *bksKeyEntry) IsDecrypted() bool {
    return true
}

// 解密
func (this *bksKeyEntry) Decrypt(password string) error {
    return nil
}

func (this *bksKeyEntry) TypeString() string {
    switch this.keyType {
        case bksKeyTypePrivate:
            return "PRIVATE"
        case bksKeyTypePublic:
            return "PUBLIC"
        case bksKeyTypeSecret:
            return "SECRET"
    }

    return ""
}

func (this *bksKeyEntry) Recover() (
    private crypto.PrivateKey,
    public crypto.PublicKey,
    secret []byte,
    err error,
) {
    keyType := this.keyType

    switch keyType {
        case bksKeyTypePrivate:
            if this.format != "PKCS8" && this.format != "PKCS#8" {
                err = fmt.Errorf("Unexpected encoding for private key entry: '%s'", this.format)
                return
            }

            private, err = ParsePKCS8PrivateKey(this.encoded)
            return

        case bksKeyTypePublic:
            if this.format != "X.509" && this.format != "X509" {
                err = fmt.Errorf("Unexpected encoding for public key entry: '%s'", this.format)
                return
            }

            public, err = ParsePKCS8PublicKey(this.encoded)
            return

        case bksKeyTypeSecret:
            if this.format != "RAW" {
                err = fmt.Errorf("Unexpected encoding for raw key entry: '%s'", this.format)
                return
            }

            secret = this.encoded
            return
    }

    err = fmt.Errorf("Key format '%s' not recognized", keyType)
    return
}

// ===================

type bksTrustedCertEntry struct {
    abstractBksEntry

    cert     []byte
    certType string
}

func (this *bksTrustedCertEntry) String() string {
    return fmt.Sprintf("trusted-cert: %s", this.date)
}

func (this *bksTrustedCertEntry) IsDecrypted() bool {
    return true
}

// 解密
func (this *bksTrustedCertEntry) Decrypt(password string) error {
    return nil
}

// ===================

type bksSecretKeyEntry struct {
    abstractBksEntry

    secret []byte
}

func (this *bksSecretKeyEntry) String() string {
    return fmt.Sprintf("secret-key: %s", this.date)
}

func (this *bksSecretKeyEntry) IsDecrypted() bool {
    return true
}

// 解密
func (this *bksSecretKeyEntry) Decrypt(password string) error {
    return nil
}

// ===================

type bksSealedKeyEntry struct {
    abstractBksEntry

    encrypted []byte
    nested    *bksKeyEntry
    password  string
}

func (this *bksSealedKeyEntry) String() string {
    return fmt.Sprintf("sealed-key: %s", this.date)
}

func (this *bksSealedKeyEntry) IsDecrypted() bool {
    if len(this.encrypted) == 0 {
        return true
    }

    return false
}

// 解密
func (this *bksSealedKeyEntry) Decrypt(password string) error {
    if this.IsDecrypted() {
        return nil
    }

    sealedData := this.encrypted

    rr := bytes.NewReader(sealedData)

    salt, err := readBytes(rr)
    if err != nil {
        return errors.New("decrypt EOF")
    }

    iterationCount, err := readInt32(rr)
    if err != nil {
        return errors.New("decrypt EOF")
    }

    blobLen := len(sealedData) - (len(salt) + 4 + 4)

    encryptedBlob, err := readOnly(rr, int32(blobLen))
    if err != nil {
        return errors.New("decrypt EOF")
    }

    params, err := asn1.Marshal(pbeParam{
        Salt:           salt,
        IterationCount: int(iterationCount),
    })
    if err != nil {
        return errors.New("decrypt marshal error")
    }

    decrypted, err := CipherSHA1And3DESForBKS.Decrypt([]byte(password), params, encryptedBlob)
    if err != nil {
        return errors.New("decrypt EOF")
    }

    bks := &BKS{}

    keyEntry, err := bks.readKey(bytes.NewReader(decrypted))
    if err != nil {
        this.nested = &bksKeyEntry{}

        return errors.New("decrypt EOF")
    }

    this.nested = keyEntry
    this.encrypted = make([]byte, 0)

    return nil
}

// 加密
func (this *bksSealedKeyEntry) Encrypt() ([]byte, error) {
    var err error

    bksBuf := bytes.NewBuffer(nil)

    bks := &BKS{}

    err = bks.marshalKey(bksBuf, this.nested)
    if err != nil {
        return nil, err
    }

    plaintext := bksBuf.Bytes()

    encrypted, params, err := CipherSHA1And3DESForBKS.Encrypt([]byte(this.password), plaintext)
    if err != nil {
        return nil, err
    }

    var param pbeParam
    if _, err := asn1.Unmarshal(params, &param); err != nil {
        return nil, err
    }

    buf := bytes.NewBuffer(nil)

    err = writeBytes(buf, param.Salt)
    if err != nil {
        return nil, err
    }

    err = writeInt32(buf, int32(param.IterationCount))
    if err != nil {
        return nil, err
    }

    err = writeOnly(buf, encrypted)
    if err != nil {
        return nil, err
    }

    bufBytes := buf.Bytes()

    return bufBytes, nil
}
