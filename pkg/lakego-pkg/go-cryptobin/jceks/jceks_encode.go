package jceks

import (
    "io"
    "time"
    "bytes"
    "errors"
    "crypto"
)

type privateKeyEntryData struct {
    date       time.Time
    encodedKey []byte
    certs      [][]byte
}

type trustedCertEntryData struct {
    date time.Time
    cert []byte
}

type secretKeyEntryData struct {
    date       time.Time
    encodedKey []byte
}

// 编码
type JceksEncode struct {
    // 私钥加证书
    privateKeys  map[string]privateKeyEntryData

    // 证书
    trustedCerts map[string]trustedCertEntryData

    // 密钥
    secretKeys   map[string]secretKeyEntryData

    // 数量统计
    count        int
}

// 添加私钥
func (this *JceksEncode) AddPrivateKey(
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

    data := privateKeyEntryData{}
    data.date = time.Now()
    data.encodedKey = encodedKey
    data.certs = certs

    this.privateKeys[alias] = data
    this.count++

    return nil
}

// 添加证书
func (this *JceksEncode) AddTrustedCert(
    alias string,
    cert []byte,
    cipher ...Cipher,
) error {
    data := trustedCertEntryData{}
    data.date = time.Now()
    data.cert = cert

    this.trustedCerts[alias] = data
    this.count++

    return nil
}

// 添加密钥
func (this *JceksEncode) AddSecretKey(
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

    data := secretKeyEntryData{}
    data.date = time.Now()
    data.encodedKey = encodedKey

    this.secretKeys[alias] = data
    this.count++

    return nil
}

func (this *JceksEncode) marshalPrivateKey(w io.Writer) error {
    for alias, data := range this.privateKeys {
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

    }

    return nil
}

func (this *JceksEncode) marshalTrustedCert(w io.Writer) error {
    for alias, data := range this.trustedCerts {
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
    }

    return nil
}

func (this *JceksEncode) marshalSecretKey(w io.Writer) error {
    for alias, data := range this.secretKeys {
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
    }

    return nil
}

func (this *JceksEncode) Marshal(password string) ([]byte, error) {
    buf := bytes.NewBuffer(nil)

    var err error

    err = writeHeader(buf)
    if err != nil {
        return nil, err
    }

    err = writeInt32(buf, int32(this.count))
    if err != nil {
        return nil, err
    }

    err = this.marshalPrivateKey(buf)
    if err != nil {
        return nil, err
    }

    err = this.marshalTrustedCert(buf)
    if err != nil {
        return nil, err
    }

    err = this.marshalSecretKey(buf)
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
