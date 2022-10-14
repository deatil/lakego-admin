package jceks

import (
    "io"
    "fmt"
    "hash"
    "bytes"
    "errors"
    "crypto"
    "crypto/subtle"
    "crypto/x509"
)

func (this *JCEKS) parsePrivateKey(r io.Reader) error {
    alias, err := readUTF(r)
    if err != nil {
        return err
    }

    entry := &privateKeyEntry{
        certs: make([][]byte, 0),
    }

    entry.date, err = readDate(r)
    if err != nil {
        return err
    }

    entry.encodedKey, err = readBytes(r)
    if err != nil {
        return err
    }

    nCerts, err := readInt32(r)
    if err != nil {
        return err
    }

    for j := 0; j < int(nCerts); j++ {
        readCertType, err := readUTF(r)
        if err != nil {
            return err
        }

        if readCertType != certType {
            return fmt.Errorf("unable to handle certificate type: %s", certType)
        }

        cert, err := readBytes(r)
        if err != nil {
            return err
        }

        entry.certs = append(entry.certs, cert)
    }

    this.entries[alias] = entry
    return nil
}

func (this *JCEKS) parseTrustedCert(r io.Reader) error {
    alias, err := readUTF(r)
    if err != nil {
        return err
    }

    entry := &trustedCertEntry{}

    entry.date, err = readDate(r)
    if err != nil {
        return err
    }

    readCertType, err := readUTF(r)
    if err != nil {
        return err
    }

    if readCertType != certType {
        return fmt.Errorf("unable to handle certificate type: %s", certType)
    }

    cert, err := readBytes(r)
    if err != nil {
        return err
    }

    entry.cert = cert

    this.entries[alias] = entry
    return nil
}

func (this *JCEKS) parseSecretKey(r io.Reader) error {
    alias, err := readUTF(r)
    if err != nil {
        return err
    }

    entry := &secretKeyEntry{}

    entry.date, err = readDate(r)
    if err != nil {
        return err
    }

    entry.encodedKey, err = readBytes(r)
    if err != nil {
        return err
    }

    this.entries[alias] = entry
    return nil
}

// 解析
func (this *JCEKS) Parse(r io.Reader, password string) error {
    var md hash.Hash
    if password != "" {
        md = getPreKeyedHash([]byte(password))
        r = io.TeeReader(r, md)
    }

    version, err := parseHeader(r)
    if err != nil {
        return err
    }

    if version != jceksVersion {
        return fmt.Errorf("unexpected version: %d != %d", version, jceksVersion)
    }

    count, err := readInt32(r)
    if err != nil {
        return err
    }

    for i := 0; i < int(count); i++ {
        tag, err := readInt32(r)
        if err != nil {
            return err
        }

        switch tag {
            case jceksPrivateKeyId:
                // Private-key entry
                err := this.parsePrivateKey(r)
                if err != nil {
                    return err
                }
            case jceksTrustedCertId:
                // Trusted-cert entry
                err := this.parseTrustedCert(r)
                if err != nil {
                    return err
                }
            case jceksSecretKeyId:
                // Secret-key entry
                err := this.parseSecretKey(r)
                if err != nil {
                    return err
                }
            default:
                return fmt.Errorf("unimplemented tag: %d", tag)
        }
    }

    if md != nil {
        computed := md.Sum([]byte{})
        actual := make([]byte, len(computed))
        _, err := io.ReadFull(r, actual)
        if err != nil {
            return err
        }

        if subtle.ConstantTimeCompare(computed, actual) != 1 {
            return fmt.Errorf("keystore was tampered with or password was incorrect")
        }
    }

    return nil
}

// GetPrivateKeyAndCerts
func (this *JCEKS) GetPrivateKeyAndCerts(alias string, password string) (
    key crypto.PrivateKey,
    certs []*x509.Certificate,
    err error,
) {
    entry, ok := this.entries[alias]
    if !ok {
        err = errors.New("no data")
        return
    }

    switch t := entry.(type) {
        case *privateKeyEntry:
            if len(t.certs) < 1 {
                return nil, nil, fmt.Errorf("key has no certificates")
            }

            key, err = t.Recover([]byte(password))
            if err == nil {
                for _, cert := range t.certs {
                    var parsedCert *x509.Certificate
                    parsedCert, err = x509.ParseCertificate(cert)
                    if err != nil {
                        return
                    }

                    certs = append(certs, parsedCert)
                }

                return
            }
    }

    return
}

// GetPrivateKeyAndCertsBytes
func (this *JCEKS) GetPrivateKeyAndCertsBytes(alias string, password string) (
    key crypto.PrivateKey,
    certs [][]byte,
    err error,
) {
    entry, ok := this.entries[alias]
    if !ok {
        err = errors.New("no data")
        return
    }

    switch t := entry.(type) {
        case *privateKeyEntry:
            if len(t.certs) < 1 {
                return nil, nil, fmt.Errorf("key has no certificates")
            }

            key, err = t.Recover([]byte(password))
            if err == nil {
                certs = t.certs

                return
            }
    }

    return
}

// GetCert
func (this *JCEKS) GetCert(alias string) (*x509.Certificate, error) {
    entry, ok := this.entries[alias]
    if !ok {
        return nil, errors.New("no data")
    }

    switch t := entry.(type) {
        case *trustedCertEntry:
            parsedCert, err := x509.ParseCertificate(t.cert)
            if err != nil {
                return nil, err
            }

            return parsedCert, nil
    }

    return nil, nil
}

// GetCertBytes
func (this *JCEKS) GetCertBytes(alias string) ([]byte, error) {
    entry, ok := this.entries[alias]
    if !ok {
        return nil, errors.New("no data")
    }

    switch t := entry.(type) {
        case *trustedCertEntry:
            return t.cert, nil
    }

    return nil, nil
}

// GetSecretKey
func (this *JCEKS) GetSecretKey(alias string, password string) (key []byte, err error) {
    entry, ok := this.entries[alias]
    if !ok {
        err = errors.New("no data")
        return
    }

    switch t := entry.(type) {
        case *secretKeyEntry:
            key, err = t.Recover([]byte(password))
            return
    }

    return
}

// ListPrivateKeys
func (this *JCEKS) ListPrivateKeys() []string {
    var r []string
    for k, v := range this.entries {
        if _, ok := v.(*privateKeyEntry); ok {
            r = append(r, k)
        }
    }
    return r
}

// ListCerts
func (this *JCEKS) ListCerts() []string {
    var r []string

    for k, v := range this.entries {
        if _, ok := v.(*trustedCertEntry); ok {
            r = append(r, k)
        }
    }

    return r
}

// ListSecretKeys lists the names of the SecretKey stored in the key store.
func (this *JCEKS) ListSecretKeys() []string {
    var r []string

    for k, v := range this.entries {
        if _, ok := v.(*secretKeyEntry); ok {
            r = append(r, k)
        }
    }

    return r
}

func (this *JCEKS) String() string {
    var buf bytes.Buffer

    for k, v := range this.entries {
        fmt.Fprintf(&buf, "%s\n", k)
        fmt.Fprintf(&buf, "  %s\n", v)
    }

    return buf.String()
}
