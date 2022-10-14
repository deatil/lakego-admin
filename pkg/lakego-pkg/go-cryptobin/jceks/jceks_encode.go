package jceks

import (
    "io"
    "time"
    "bytes"
    "errors"
    "crypto"
)

// 添加私钥
func (this *JCEKS) AddPrivateKey(
    alias string,
    privateKey crypto.PrivateKey,
    password string,
    certs [][]byte,
    cipher ...Cipher,
) error {
    entry := privateKeyEntry{}
    encodedKey, err := entry.Encode(privateKey, password, cipher...)
    if err != nil {
        return err
    }

    entry.date = time.Now()
    entry.encodedKey = encodedKey
    entry.certs = certs

    this.entries[alias] = entry

    return nil
}

// 添加证书
func (this *JCEKS) AddTrustedCert(
    alias string,
    cert []byte,
) error {
    entry := trustedCertEntry{}
    entry.date = time.Now()
    entry.cert = cert

    this.entries[alias] = entry

    return nil
}

// 添加密钥
func (this *JCEKS) AddSecretKey(
    alias string,
    secretKey []byte,
    password string,
    cipher ...Cipher,
) error {
    entry := secretKeyEntry{}
    encodedKey, err := entry.Encode(secretKey, password, cipher...)
    if err != nil {
        return err
    }

    entry.date = time.Now()
    entry.encodedKey = encodedKey

    this.entries[alias] = entry

    return nil
}

func (this *JCEKS) marshalPrivateKey(w io.Writer, alias string, data privateKeyEntry) error {
    certLen := len(data.certs)
    if certLen == 0 {
        return errors.New("privateKey cert is empty.")
    }

    var err error

    err = writeInt32(w, int32(jceksPrivateKeyId))
    if err != nil {
        return err
    }

    err = writeUTF(w, alias)
    if err != nil {
        return err
    }

    err = writeDate(w, data.date)
    if err != nil {
        return err
    }

    err = writeBytes(w, data.encodedKey)
    if err != nil {
        return err
    }

    err = writeInt32(w, int32(certLen))
    if err != nil {
        return err
    }

    for _, cert := range data.certs {
        err = writeUTF(w, certType)
        if err != nil {
            return err
        }

        err = writeBytes(w, cert)
        if err != nil {
            return err
        }
    }

    return nil
}

func (this *JCEKS) marshalTrustedCert(w io.Writer, alias string, data trustedCertEntry) error {
    var err error

    err = writeInt32(w, int32(jceksTrustedCertId))
    if err != nil {
        return err
    }

    err = writeUTF(w, alias)
    if err != nil {
        return err
    }

    err = writeDate(w, data.date)
    if err != nil {
        return err
    }

    err = writeUTF(w, certType)
    if err != nil {
        return err
    }

    err = writeBytes(w, data.cert)
    if err != nil {
        return err
    }

    return nil
}

func (this *JCEKS) marshalSecretKey(w io.Writer, alias string, data secretKeyEntry) error {
    var err error

    err = writeInt32(w, int32(jceksSecretKeyId))
    if err != nil {
        return err
    }

    err = writeUTF(w, alias)
    if err != nil {
        return err
    }

    err = writeDate(w, data.date)
    if err != nil {
        return err
    }

    err = writeBytes(w, data.encodedKey)
    if err != nil {
        return err
    }

    return nil
}

func (this *JCEKS) Marshal(password string) ([]byte, error) {
    buf := bytes.NewBuffer(nil)

    var err error

    err = writeHeader(buf)
    if err != nil {
        return nil, err
    }

    count := len(this.entries)
    err = writeInt32(buf, int32(count))
    if err != nil {
        return nil, err
    }

    for alias, entry := range this.entries {
        switch e := entry.(type) {
            case privateKeyEntry:
                err = this.marshalPrivateKey(buf, alias, e)
            case trustedCertEntry:
                err = this.marshalTrustedCert(buf, alias, e)
            case secretKeyEntry:
                err = this.marshalSecretKey(buf, alias, e)
        }
    }

    if err != nil {
        return nil, err
    }

    if password != "" {
        md := getPreKeyedHash([]byte(password))
        md.Write(buf.Bytes())
        computed := md.Sum([]byte{})

        err = writeOnly(buf, computed)
        if err != nil {
            return nil, err
        }
    }

    bufBytes := buf.Bytes()

    return bufBytes, nil
}
