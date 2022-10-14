package jceks

import (
    "time"
    "bytes"
    "errors"
    "crypto"
)

// 添加私钥
func (this *JKS) AddPrivateKey(
    alias string,
    privateKey crypto.PrivateKey,
    password string,
    certChain [][]byte,
) error {
    if isInArray[[]byte](alias, this.trustedCerts) {
        return errors.New("\"" + alias + " is a trusted certificate entry")
    }

    var err error
    var marshaledPrivateKey []byte

    marshaledPrivateKey, err = MarshalPKCS8PrivateKey(privateKey)
    if err != nil {
        return err
    }

    this.privateKeys[alias], err = jksEncryptKey(marshaledPrivateKey, []byte(password))
    if err != nil {
        return err
    }

    if certChain != nil && len(certChain) != 0 {
        this.certChains[alias] = certChain
    } else {
        this.certChains[alias] = make([][]byte, 0)
    }

    if !isInSlice(alias, this.aliases) {
        this.dates[alias] = time.Now()
        this.aliases = append(this.aliases, alias)
    }

    return nil
}

// 添加私钥
func (this *JKS) AddEncodedPrivateKey(
    alias string,
    encodedKey []byte,
    certChain [][]byte,
) error {
    if isInArray[[]byte](alias, this.trustedCerts) {
        return errors.New("\"" + alias + " is a trusted certificate entry")
    }

    this.privateKeys[alias] = encodedKey

    if certChain != nil && len(certChain) != 0 {
        this.certChains[alias] = certChain
    } else {
        this.certChains[alias] = make([][]byte, 0)
    }

    if !isInSlice(alias, this.aliases) {
        this.dates[alias] = time.Now()
        this.aliases = append(this.aliases, alias)
    }

    return nil
}

// 添加密钥
func (this *JKS) AddTrustedCert(
    alias string,
    cert []byte,
) error {
    if isInArray[[]byte](alias, this.privateKeys) {
        return errors.New("\"" + alias + "\" is a private key entry")
    }

    if cert == nil || len(cert) == 0 {
        return errors.New("cert is empty")
    }

    this.trustedCerts[alias] = cert

    if !isInSlice(alias, this.aliases) {
        this.dates[alias] = time.Now()
        this.aliases = append(this.aliases, alias)
    }

    return nil
}

func (this *JKS) Marshal(password string) ([]byte, error) {
    buf := bytes.NewBuffer(nil)

    var err error

    err = writeUint32(buf, jksMagic)
    if err != nil {
        return nil, err
    }

    err = writeUint32(buf, jksVersion)
    if err != nil {
        return nil, err
    }

    err = writeInt32(buf, int32(len(this.aliases)))
    if err != nil {
        return nil, err
    }

    for _, alias := range this.aliases {
        if isInArray[[]byte](alias, this.trustedCerts) {
            err = writeInt32(buf, int32(jksTrustedCertId))
            if err != nil {
                return nil, err
            }

            err = writeUTF(buf, alias)
            if err != nil {
                return nil, err
            }

            err = writeDate(buf, this.dates[alias])
            if err != nil {
                return nil, err
            }

            err = writeUTF(buf, certType)
            if err != nil {
                return nil, err
            }

            err = writeBytes(buf, this.trustedCerts[alias])
            if err != nil {
                return nil, err
            }
        } else {
            err = writeInt32(buf, int32(jksPrivateKeyId))
            if err != nil {
                return nil, err
            }

            err = writeUTF(buf, alias)
            if err != nil {
                return nil, err
            }

            err = writeDate(buf, this.dates[alias])
            if err != nil {
                return nil, err
            }

            err = writeBytes(buf, this.privateKeys[alias])
            if err != nil {
                return nil, err
            }

            chain := this.certChains[alias]

            err = writeInt32(buf, int32(len(chain)))
            if err != nil {
                return nil, err
            }

            for _, item := range chain {
                err = writeUTF(buf, certType)
                if err != nil {
                    return nil, err
                }

                err = writeBytes(buf, item)
                if err != nil {
                    return nil, err
                }
            }

        }
    }

    md := getJksPreKeyedHash([]byte(password))
    md.Write(buf.Bytes())
    computed := md.Sum([]byte{})

    err = writeOnly(buf, computed)
    if err != nil {
        return nil, err
    }

    bufBytes := buf.Bytes()

    return bufBytes, nil
}
