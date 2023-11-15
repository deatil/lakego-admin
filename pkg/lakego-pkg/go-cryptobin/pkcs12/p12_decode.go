package pkcs12

import (
    "errors"
    "crypto"
    "crypto/x509"
    "encoding/pem"

    gmsm_x509 "github.com/tjfoc/gmsm/x509"

    pkcs8_pbes2 "github.com/deatil/go-cryptobin/pkcs8/pbes2"
)

func (this *PKCS12) getSafeContents(p12Data, password []byte) (bags []SafeBag, updatedPassword []byte, err error) {
    pfx := new(PfxPdu)
    if err := unmarshal(p12Data, pfx); err != nil {
        return nil, nil, errors.New("pkcs12: error reading P12 data: " + err.Error())
    }

    if pfx.Version != PKCS12Version {
        return nil, nil, NotImplementedError("can only decode v3 PFX PDU's")
    }

    if !pfx.AuthSafe.ContentType.Equal(oidDataContentType) {
        return nil, nil, NotImplementedError("only password-protected PFX is implemented")
    }

    // unmarshal the explicit bytes in the content for type 'data'
    if err := unmarshal(pfx.AuthSafe.Content.Bytes, &pfx.AuthSafe.Content); err != nil {
        return nil, nil, err
    }

    if len(pfx.MacData.Mac.Algorithm.Algorithm) == 0 {
        if !(len(password) == 2 && password[0] == 0 && password[1] == 0) {
            return nil, nil, errors.New("pkcs12: no MAC in data")
        }
    } else {
        if err := pfx.MacData.Verify(pfx.AuthSafe.Content.Bytes, password); err != nil {
            if err == ErrIncorrectPassword && len(password) == 2 && password[0] == 0 && password[1] == 0 {
                // some implementations use an empty byte array
                // for the empty string password try one more
                // time with empty-empty password
                password = nil
                err = pfx.MacData.Verify(pfx.AuthSafe.Content.Bytes, password)
            }

            if err != nil {
                return nil, nil, err
            }
        }
    }

    var authenticatedSafe []ContentInfo
    if err := unmarshal(pfx.AuthSafe.Content.Bytes, &authenticatedSafe); err != nil {
        return nil, nil, err
    }

    for _, ci := range authenticatedSafe {
        var data []byte

        switch {
            case ci.ContentType.Equal(oidDataContentType):
                if err := unmarshal(ci.Content.Bytes, &data); err != nil {
                    return nil, nil, err
                }

            case ci.ContentType.Equal(oidEncryptedDataContentType):
                var encryptedData EncryptedData
                if err := unmarshal(ci.Content.Bytes, &encryptedData); err != nil {
                    return nil, nil, err
                }

                if encryptedData.Version != 0 {
                    return nil, nil, NotImplementedError("only version 0 of EncryptedData is supported")
                }

                encryptedContentInfo := encryptedData.EncryptedContentInfo
                encryptedContent := encryptedContentInfo.EncryptedContent
                contentEncryptionAlgorithm := encryptedContentInfo.ContentEncryptionAlgorithm

                // pbes2
                if pkcs8_pbes2.IsPBES2(contentEncryptionAlgorithm.Algorithm) {
                    // change type to utf-8
                    passwordString, err := decodeBMPString(password)
                    if err != nil {
                        return nil, nil, err
                    }

                    password = []byte(passwordString)

                    data, err = pkcs8_pbes2.PBES2Decrypt(encryptedContent, contentEncryptionAlgorithm, password)
                    if err != nil {
                        return nil, nil, errors.New("pkcs12: " + err.Error())
                    }
                } else {
                    newCipher, enParams, err := parseContentEncryptionAlgorithm(contentEncryptionAlgorithm)
                    if err != nil {
                        return nil, nil, err
                    }

                    data, err = newCipher.Decrypt(password, enParams, encryptedContent)
                    if err != nil {
                        return nil, nil, err
                    }
                }

            default:
                return nil, nil, NotImplementedError("only data and encryptedData content types are supported in authenticated safe")
        }

        var safeContents []SafeBag
        if err := unmarshal(data, &safeContents); err != nil {
            return nil, nil, err
        }

        bags = append(bags, safeContents...)
    }

    return bags, password, nil
}

func (this *PKCS12) parseKeyBag(bag *SafeBag) error {
    privateKey, err := ParsePKCS8PrivateKey(bag.Value.Bytes)
    if err != nil {
        return err
    }

    bagData := NewSafeBagDataWithAttrs(privateKey, bag.Attributes)
    this.parsedData["privateKey"] = append(this.parsedData["privateKey"], bagData)

    return nil
}

func (this *PKCS12) parseShroundedKeyBag(bag *SafeBag, password []byte) error {
    privateKey, err := decodePkcs8ShroudedKeyBag(bag.Value.Bytes, password)
    if err != nil {
        return err
    }

    bagData := NewSafeBagDataWithAttrs(privateKey, bag.Attributes)
    this.parsedData["privateKey"] = append(this.parsedData["privateKey"], bagData)

    return nil
}

func (this *PKCS12) parseCertBag(bag *SafeBag) error {
    certsData, err := decodeCertBag(bag.Value.Bytes)
    if err != nil {
        return err
    }

    parsedCerts, err := x509.ParseCertificates(certsData)
    if err != nil {
        gmsmCerts, err := gmsm_x509.ParseCertificates(certsData)
        if err != nil {
            err = errors.New("pkcs12: x509 error: " + err.Error())
            return err
        }

        for _, cert := range gmsmCerts {
            parsedCerts = append(parsedCerts, cert.ToX509Certificate())
        }
    }

    if len(parsedCerts) != 1 {
        err = errors.New("pkcs12: expected exactly one certificate in the certBag")
        return err
    }

    switch {
        case bag.hasAttribute(oidJavaTrustStore):
            bagData := NewSafeBagDataWithAttrs(parsedCerts[0], bag.Attributes)

            this.parsedData["trustStore"] = append(this.parsedData["trustStore"], bagData)

        case bag.hasAttribute(oidLocalKeyID):
            bagData := NewSafeBagDataWithAttrs(parsedCerts[0], bag.Attributes)

            this.parsedData["cert"] = append(this.parsedData["cert"], bagData)

        default:
            bagData := NewSafeBagDataWithAttrs(parsedCerts[0], bag.Attributes)

            this.parsedData["caCert"] = append(this.parsedData["caCert"], bagData)

    }

    return nil
}

func (this *PKCS12) parseSecretBag(bag *SafeBag, password []byte) error {
    bagData := &SafeBagData{}

    data, err := decodeSecretBag(bag.Value.Bytes, password)
    if err != nil {
        return err
    }

    bagData.data = data
    bagData.attrs = NewPKCS12Attributes(bag.Attributes)

    this.parsedData["secretKey"] = append(this.parsedData["secretKey"], bagData)

    return nil
}

// 解析
func (this *PKCS12) Parse(pfxData []byte, password string) (*PKCS12, error) {
    encodedPassword, err := bmpStringZeroTerminated(password)
    if err != nil {
        return nil, err
    }

    bags, encodedPassword, err := this.getSafeContents(pfxData, encodedPassword)
    if err != nil {
        return nil, err
    }

    for _, bag := range bags {
        switch {
            case bag.Id.Equal(oidKeyBag):
                this.parseKeyBag(&bag)

            case bag.Id.Equal(oidPKCS8ShroundedKeyBag):
                this.parseShroundedKeyBag(&bag, encodedPassword)

            case bag.Id.Equal(oidCertBag):
                this.parseCertBag(&bag)

            case bag.Id.Equal(oidSecretBag):
                this.parseSecretBag(&bag, encodedPassword)
        }
    }

    return this, nil
}

//===============

func (this *PKCS12) GetPrivateKey() (crypto.PrivateKey, PKCS12Attributes) {
    privateKeys, ok := this.parsedData["privateKey"]
    if !ok {
        return nil, PKCS12Attributes{}
    }

    if len(privateKeys) == 0 {
        return nil, PKCS12Attributes{}
    }

    privateKey, ok := privateKeys[0].Data().(crypto.PrivateKey)
    if !ok {
        return nil, PKCS12Attributes{}
    }

    return privateKey, privateKeys[0].Attrs()
}

func (this *PKCS12) GetCert() (*x509.Certificate, PKCS12Attributes) {
    certs, ok := this.parsedData["cert"]
    if !ok {
        return nil, PKCS12Attributes{}
    }

    if len(certs) == 0 {
        return nil, PKCS12Attributes{}
    }

    cert, ok := certs[0].Data().(*x509.Certificate)
    if !ok {
        return nil, PKCS12Attributes{}
    }

    return cert, certs[0].Attrs()
}

func (this *PKCS12) GetCaCerts() []*x509.Certificate {
    certs, ok := this.parsedData["caCert"]
    if !ok {
        return nil
    }

    if len(certs) == 0 {
        return nil
    }

    caCerts := make([]*x509.Certificate, 0)

    for _, cert := range certs {
        c, ok := cert.Data().(*x509.Certificate)
        if ok {
            caCerts = append(caCerts, c)
        }
    }

    return caCerts
}

func (this *PKCS12) GetTrustStores() []*x509.Certificate {
    certs, ok := this.parsedData["trustStore"]
    if !ok {
        return nil
    }

    if len(certs) == 0 {
        return nil
    }

    caCerts := make([]*x509.Certificate, 0)

    for _, cert := range certs {
        c, ok := cert.Data().(*x509.Certificate)
        if ok {
            caCerts = append(caCerts, c)
        }
    }

    return caCerts
}

type trustStoreKeyData struct {
    Attrs PKCS12Attributes
    Cert  *x509.Certificate
}

func (this *PKCS12) GetTrustStoreEntries() []trustStoreKeyData {
    certs, ok := this.parsedData["trustStore"]
    if !ok {
        return nil
    }

    if len(certs) == 0 {
        return nil
    }

    caCerts := make([]trustStoreKeyData, 0)

    for _, cert := range certs {
        c, ok := cert.Data().(*x509.Certificate)
        if ok {
            caCerts = append(caCerts, trustStoreKeyData{
                Attrs: cert.Attrs(),
                Cert:  c,
            })
        }
    }

    return caCerts
}

func (this *PKCS12) GetSecretKey() ([]byte, PKCS12Attributes) {
    keys, ok := this.parsedData["secretKey"]
    if !ok {
        return nil, PKCS12Attributes{}
    }

    if len(keys) == 0 {
        return nil, PKCS12Attributes{}
    }

    key, ok := keys[0].Data().([]byte)
    if !ok {
        return nil, PKCS12Attributes{}
    }

    return key, keys[0].Attrs()
}

//===============

func (this *PKCS12) hasData(name string) bool {
    datas, ok := this.parsedData[name]
    if !ok {
        return false
    }

    if len(datas) == 0 {
        return false
    }

    return true
}

func (this *PKCS12) HasPrivateKey() bool {
    return this.hasData("privateKey")
}

func (this *PKCS12) HasCert() bool {
    return this.hasData("cert")
}

func (this *PKCS12) HasCaCert() bool {
    return this.hasData("caCert")
}

func (this *PKCS12) HasTrustStore() bool {
    return this.hasData("trustStore")
}

func (this *PKCS12) HasSecretKey() bool {
    return this.hasData("secretKey")
}

//===============

func (this *PKCS12) convertBag(typ string, data []byte, attrs PKCS12Attributes) *pem.Block {
    block := &pem.Block{
        Headers: make(map[string]string),
    }

    block.Headers = attrs.ToArray()
    block.Type = typ
    block.Bytes = data

    return block
}

func (this *PKCS12) ToPEM() ([]*pem.Block, error) {
    blocks := make([]*pem.Block, 0)

    // 私钥
    prikey, attrs := this.GetPrivateKey()
    if prikey != nil {
        priBytes, err := MarshalPrivateKey(prikey)
        if err != nil {
            return nil, errors.New("found unknown private key type in PKCS#8 wrapping: " + err.Error())
        }

        priBlock := this.convertBag(PrivateKeyType, priBytes, attrs)

        blocks = append(blocks, priBlock)
    }

    // 证书
    cert, attrs := this.GetCert()
    if cert != nil {
        certBlock := this.convertBag(CertificateType, cert.Raw, attrs)

        blocks = append(blocks, certBlock)
    }

    // 证书链
    caCerts := this.GetCaCerts()
    for _, caCert := range caCerts {
        caCertBlock := this.convertBag(CertificateType, caCert.Raw, EmptyPKCS12Attributes())

        blocks = append(blocks, caCertBlock)
    }

    // JAVA 证书链
    trustStores := this.GetTrustStoreEntries()
    for _, entry := range trustStores {
        entryBlock := this.convertBag(CertificateType, entry.Cert.Raw, entry.Attrs)

        blocks = append(blocks, entryBlock)
    }

    return blocks, nil
}
