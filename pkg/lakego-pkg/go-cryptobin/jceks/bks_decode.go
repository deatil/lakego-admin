package jceks

import (
    "io"
    "fmt"
    "time"
    "bytes"
    "errors"
    "crypto"
    "crypto/sha1"
    "crypto/x509"
    "crypto/hmac"
    "crypto/subtle"
)

func (this *BKS) readCert(r io.Reader) (*bksTrustedCertEntry, error) {
    certType, err := readUTF(r)
    if err != nil {
        return nil, errors.New("readCert EOF")
    }

    certData, err := readBytes(r)
    if err != nil {
        return nil, errors.New("readCert EOF")
    }

    entry := &bksTrustedCertEntry{}
    entry.cert = certData
    entry.certType = certType

    return entry, nil
}

func (this *BKS) readKey(r io.Reader) (*bksKeyEntry, error) {
    keyType, err := readUint8(r)
    if err != nil {
        return nil, errors.New("readKey EOF")
    }

    keyFormat, err := readUTF(r)
    if err != nil {
        return nil, errors.New("readKey EOF")
    }

    keyAlgorithm, err := readUTF(r)
    if err != nil {
        return nil, errors.New("readKey EOF")
    }

    keyEnc, err := readBytes(r)
    if err != nil {
        return nil, errors.New("readKey EOF")
    }

    entry := &bksKeyEntry{}
    entry.keyType = int(keyType)
    entry.format = keyFormat
    entry.algorithm = keyAlgorithm
    entry.encoded = keyEnc

    return entry, nil
}

func (this *BKS) readSecret(r io.Reader) (*bksSecretKeyEntry, error) {
    secretData, err := readBytes(r)
    if err != nil {
        return nil, errors.New("readSecret EOF")
    }

    entry := &bksSecretKeyEntry{}
    entry.secret = secretData

    return entry, nil
}

// 解密
func (this *BKS) readSealed(r io.Reader) (*bksSealedKeyEntry, error) {
    sealedData, err := readBytes(r)
    if err != nil {
        return nil, errors.New("readSealed EOF")
    }

    entry := &bksSealedKeyEntry{}
    entry.encrypted = sealedData

    return entry, nil
}

// 解析
func (this *BKS) loadEntries(r io.Reader, password string) error {
    for {
        tag, err := readUint8(r)
        if err != nil {
            return errors.New("load EOF")
        }

        if int(tag) == 0 {
            break
        }

        alias, err := readUTF(r)
        if err != nil {
            return errors.New("load EOF")
        }

        date, err := readDate(r)
        if err != nil {
            return errors.New("load EOF")
        }

        chainLength, err := readInt32(r)
        if err != nil {
            return errors.New("load EOF")
        }

        certChain := make([][]byte, 0)
        for i := 0; i < int(chainLength); i++ {
            entry, err := this.readCert(r)
            if err != nil {
                return errors.New("load EOF")
            }

            certChain = append(certChain, entry.cert)
        }

        var entry BksEntry
        switch int(tag) {
            case bksEntryTypeCert:
                entry, err = this.readCert(r)
            case bksEntryTypeKey:
                entry, err = this.readKey(r)
            case bksEntryTypeSecret:
                entry, err = this.readSecret(r)
            case bksEntryTypeSealed:
                entry, err = this.readSealed(r)
            default:
                return fmt.Errorf("Unsupported keystore type: %d", tag)
        }

        if err != nil {
            return fmt.Errorf("Keystore type: %d, err: %s", tag, err.Error())
        }

        entry.WithData(alias, date, certChain)

        if isInArray[any](alias, this.entries) {
            return fmt.Errorf("Found duplicate alias '%s'", alias)
        }

        this.entries[alias] = entry
    }

    return nil
}

// 解析
func (this *BKS) Parse(r io.Reader, password string) error {
    version, err := readUint32(r)
    if err != nil {
        return errors.New("parse EOF")
    }

    if version != BksVersionV1 && version != BksVersionV2 {
        return fmt.Errorf("Unsupported BKS keystore version; only V1 and V2 supported, found v%d", version)
    }

    this.version = version
    this.storeType = "bks"

    salt, err := readBytes(r)
    if err != nil {
        return errors.New("parse EOF")
    }

    iterationCount, err := readInt32(r)
    if err != nil {
        return errors.New("parse EOF")
    }

    hmacFn := sha1.New
    hmacDigestSize := hmacFn().Size()
    hmacKeySize := hmacDigestSize*8
    if version == 1 {
        hmacKeySize = hmacDigestSize
    }

    hmacKey := derivedHmacKey(password, string(salt), int(iterationCount), hmacKeySize/8, hmacFn)
    hmac := hmac.New(sha1.New, hmacKey)

    r = io.TeeReader(r, hmac)

    err = this.loadEntries(r, password)
    if err != nil {
        return err
    }

    computed := hmac.Sum([]byte{})
    computedLen := len(computed)

    actual, err := readOnly(r, int32(computedLen))
    if err != nil {
        return errors.New("parse EOF")
    }

    if subtle.ConstantTimeCompare(computed, actual) != 1 {
        return fmt.Errorf("keystore was tampered with or password was incorrect")
    }

    return nil
}

// GetKeyPrivate
func (this *BKS) GetKeyPrivate(alias string) (private crypto.PrivateKey, err error) {
    private, _, _, err = this.GetKey(alias)

    return
}

// GetKeyPrivateWithPassword
func (this *BKS) GetKeyPrivateWithPassword(alias string, password string) (private crypto.PrivateKey, err error) {
    private, _, _, err = this.GetSealedKey(alias, password)

    return
}

// GetKeyPublic
func (this *BKS) GetKeyPublic(alias string) (public crypto.PublicKey, err error) {
    _, public, _, err = this.GetKey(alias)

    return
}

// GetKeyPublicWithPassword
func (this *BKS) GetKeyPublicWithPassword(alias string, password string) (public crypto.PublicKey, err error) {
    _, public, _, err = this.GetSealedKey(alias, password)

    return
}

// GetKeySecret
func (this *BKS) GetKeySecret(alias string) (secret []byte, err error) {
    _, _, secret, err = this.GetKey(alias)

    return
}

// GetKeySecretWithPassword
func (this *BKS) GetKeySecretWithPassword(alias string, password string) (secret []byte, err error) {
    _, _, secret, err = this.GetSealedKey(alias, password)

    return
}

// GetKeyType
func (this *BKS) GetKeyType(alias string) (keyType string, err error) {
    entry, ok := this.entries[alias]
    if !ok {
        err = errors.New("no data")
        return
    }

    switch t := entry.(type) {
        case *bksKeyEntry:
            keyType = t.TypeString()
    }

    return
}

// GetKey
func (this *BKS) GetKey(alias string) (
    private crypto.PrivateKey,
    public crypto.PublicKey,
    secret []byte,
    err error,
) {
    entry, ok := this.entries[alias]
    if !ok {
        err = errors.New("no data")
        return
    }

    switch t := entry.(type) {
        case *bksKeyEntry:
            private, public, secret, err = t.Recover()
            if err != nil {
                return
            }
    }

    return
}

// GetCertType
func (this *BKS) GetCertType(alias string) (certType string, err error) {
    entry, ok := this.entries[alias]
    if !ok {
        err = errors.New("no data")
        return
    }

    switch t := entry.(type) {
        case *bksTrustedCertEntry:
            certType = t.certType
    }

    return
}

// GetCert
func (this *BKS) GetCert(alias string) (
    cert *x509.Certificate,
    err error,
) {
    entry, ok := this.entries[alias]
    if !ok {
        err = errors.New("no data")
        return
    }

    switch t := entry.(type) {
        case *bksTrustedCertEntry:
            cert, err = x509.ParseCertificate(t.cert)
    }

    return
}

// GetCertBytes
func (this *BKS) GetCertBytes(alias string) (
    cert []byte,
    err error,
) {
    entry, ok := this.entries[alias]
    if !ok {
        err = errors.New("no data")
        return
    }

    switch t := entry.(type) {
        case *bksTrustedCertEntry:
            cert = t.cert
    }

    return
}

// GetSecret
func (this *BKS) GetSecret(alias string) (
    secret []byte,
    err error,
) {
    entry, ok := this.entries[alias]
    if !ok {
        err = errors.New("no data")
        return
    }

    switch t := entry.(type) {
        case *bksSecretKeyEntry:
            secret = t.secret
    }

    return
}

// GetSealedKeyType
func (this *BKS) GetSealedKeyType(alias string, password string) (keyType string, err error) {
    entry, ok := this.entries[alias]
    if !ok {
        err = errors.New("no data")
        return
    }

    switch t := entry.(type) {
        case *bksSealedKeyEntry:
            err = t.Decrypt(password)
            if err != nil {
                return
            }

            keyType = t.nested.TypeString()
    }

    return
}

// GetSealedKey
func (this *BKS) GetSealedKey(alias string, password string) (
    private crypto.PrivateKey,
    public crypto.PublicKey,
    secret []byte,
    err error,
) {
    entry, ok := this.entries[alias]
    if !ok {
        err = errors.New("no data")
        return
    }

    switch t := entry.(type) {
        case *bksSealedKeyEntry:
            err = t.Decrypt(password)
            if err != nil {
                return
            }

            private, public, secret, err = t.nested.Recover()
    }

    return
}

// GetCertChain
func (this *BKS) GetCertChain(alias string) (certChain []*x509.Certificate, err error) {
    entry, ok := this.entries[alias]
    if !ok {
        err = errors.New("no data")
        return
    }

    switch t := entry.(type) {
        case BksDataEntry:
            certChain, err = parseCertChain(t.GetCertChain())
    }

    return
}

// GetCertChainBytes
func (this *BKS) GetCertChainBytes(alias string) (certChain [][]byte, err error) {
    entry, ok := this.entries[alias]
    if !ok {
        err = errors.New("no data")
        return
    }

    switch t := entry.(type) {
        case BksDataEntry:
            certChain = t.GetCertChain()
    }

    return
}

// GetCreateDate
func (this *BKS) GetCreateDate(alias string) (date time.Time, err error) {
    entry, ok := this.entries[alias]
    if !ok {
        err = errors.New("no data")
        return
    }

    switch t := entry.(type) {
        case BksDataEntry:
            date = t.GetDate()
    }

    return
}

// ListCerts
func (this *BKS) ListCerts() []string {
    var r []string

    for k, v := range this.entries {
        if _, ok := v.(*bksTrustedCertEntry); ok {
            r = append(r, k)
        }
    }

    return r
}

// ListSecrets lists the names of the SecretKey stored in the key store.
func (this *BKS) ListSecrets() []string {
    var r []string

    for k, v := range this.entries {
        if _, ok := v.(*bksSecretKeyEntry); ok {
            r = append(r, k)
        }
    }

    return r
}

// ListKeys
func (this *BKS) ListKeys() []string {
    var r []string
    for k, v := range this.entries {
        if _, ok := v.(*bksKeyEntry); ok {
            r = append(r, k)
        }
    }

    return r
}

// ListSealedKeys
func (this *BKS) ListSealedKeys() []string {
    var r []string
    for k, v := range this.entries {
        if _, ok := v.(*bksSealedKeyEntry); ok {
            r = append(r, k)
        }
    }

    return r
}

func (this *BKS) Version() uint32 {
    return this.version
}

func (this *BKS) StoreType() string {
    return this.storeType
}

func (this *BKS) String() string {
    var buf bytes.Buffer

    for k, v := range this.entries {
        fmt.Fprintf(&buf, "%s\n", k)
        fmt.Fprintf(&buf, "  %s\n", v)
    }

    return buf.String()
}
