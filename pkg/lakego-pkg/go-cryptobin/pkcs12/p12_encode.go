package pkcs12

import (
    "io"
    "errors"
    "crypto"
    "crypto/x509"
    "crypto/sha1"
    "encoding/pem"
    "encoding/asn1"

    pkcs8_pbes1 "github.com/deatil/go-cryptobin/pkcs8/pbes1"
    pkcs8_pbes2 "github.com/deatil/go-cryptobin/pkcs8/pbes2"
)

func (this *PKCS12) decodePKCS8ShroudedKeyBag(asn1Data, password []byte) (pkData []byte, err error) {
    pkData, err = pkcs8_pbes2.DecryptPKCS8PrivateKey(asn1Data, password)
    if err != nil {
        pkData, err = pkcs8_pbes1.DecryptPKCS8Privatekey(asn1Data, password)
        if err != nil {
            return nil, errors.New("pkcs12: error decrypting PKCS#8: " + err.Error())
        }
    }

    ret := new(asn1.RawValue)
    if err = unmarshal(pkData, ret); err != nil {
        return nil, errors.New("pkcs12: error unmarshaling decrypted private key: " + err.Error())
    }

    return pkData, nil
}

func (this *PKCS12) encodePKCS8ShroudedKeyBag(
    rand io.Reader,
    pkData []byte,
    password []byte,
    opt Opts,
) (asn1Data []byte, err error) {
    var keyBlock *pem.Block

    if opt.KeyKDFOpts != nil {
        // change type to utf-8
        passwordString, err := decodeBMPString(password)
        if err != nil {
            return nil, err
        }

        password = []byte(passwordString)

        keyBlock, err = pkcs8_pbes2.EncryptPKCS8PrivateKey(rand, "KEY", pkData, password, pkcs8_pbes2.Opts{
            opt.KeyCipher,
            opt.KeyKDFOpts,
        })
    } else {
        keyBlock, err = pkcs8_pbes1.EncryptPKCS8Privatekey(rand, "KEY", pkData, password, opt.KeyCipher)
    }

    if err != nil {
        return nil, err
    }

    asn1Data = keyBlock.Bytes

    return asn1Data, nil
}

// ===============

func (this *PKCS12) AddPrivateKey(privateKey crypto.PrivateKey) error {
    pkData, err := MarshalPKCS8PrivateKey(privateKey)
    if err != nil {
        return err
    }

    this.privateKey = pkData

    return nil
}

func (this *PKCS12) AddPrivateKeyBytes(privateKey []byte) {
    this.privateKey = privateKey
}

func (this *PKCS12) AddCert(cert *x509.Certificate) {
    this.cert = cert.Raw
}

func (this *PKCS12) AddCertBytes(cert []byte) {
    this.cert = cert
}

func (this *PKCS12) AddCaCert(ca *x509.Certificate) {
    this.caCerts = append(this.caCerts, ca.Raw)
}

func (this *PKCS12) AddCaCertBytes(ca []byte) {
    this.caCerts = append(this.caCerts, ca)
}

func (this *PKCS12) AddCaCerts(caCerts []*x509.Certificate) {
    for _, cert := range caCerts {
        this.caCerts = append(this.caCerts, cert.Raw)
    }
}

func (this *PKCS12) AddCaCertsBytes(caCerts [][]byte) {
    for _, cert := range caCerts {
        this.caCerts = append(this.caCerts, cert)
    }
}

func (this *PKCS12) AddTrustStore(cert *x509.Certificate) {
    this.trustStores = append(this.trustStores, TrustStoreData{
        Cert: cert.Raw,
        FriendlyName: cert.Subject.String(),
    })
}

func (this *PKCS12) AddTrustStores(certs []*x509.Certificate) {
    for _, cert := range certs {
        this.trustStores = append(this.trustStores, TrustStoreData{
            Cert: cert.Raw,
            FriendlyName: cert.Subject.String(),
        })
    }
}

func (this *PKCS12) AddTrustStoreEntry(cert *x509.Certificate, friendlyName string) {
    this.trustStores = append(this.trustStores, TrustStoreData{
        Cert: cert.Raw,
        FriendlyName: friendlyName,
    })
}

func (this *PKCS12) AddTrustStoreEntryBytes(cert []byte, friendlyName string) {
    this.trustStores = append(this.trustStores, TrustStoreData{
        Cert: cert,
        FriendlyName: friendlyName,
    })
}

func (this *PKCS12) AddTrustStoreEntries(entries []TrustStoreData) {
    this.trustStores = append(this.trustStores, entries...)
}

func (this *PKCS12) AddSecretKey(secretKey []byte) {
    this.secretKey = secretKey
}

//===============

// 获取证书签名
func (this *PKCS12) makeCertLocalKeyIdAttr(cert []byte) (PKCS12Attribute, error) {
    var certFingerprint = sha1.Sum(cert)

    sha1Data, err := asn1.Marshal(certFingerprint[:])
    if err != nil {
        return PKCS12Attribute{}, err
    }

    var localKeyIdAttr PKCS12Attribute
    localKeyIdAttr.Id = oidLocalKeyID
    localKeyIdAttr.Value.Class = 0
    localKeyIdAttr.Value.Tag = 17
    localKeyIdAttr.Value.IsCompound = true
    localKeyIdAttr.Value.Bytes = sha1Data

    return localKeyIdAttr, nil
}

func (this *PKCS12) marshalPrivateKey(rand io.Reader, password []byte, opt Opts) (ci ContentInfo, err error) {
    if this.cert == nil {
        err = errors.New("PKCS12: cert error")
        return
    }

    // 私钥
    privateKey := this.privateKey

    var keyBag SafeBag
    keyBag.Value.Class = 2
    keyBag.Value.Tag = 0
    keyBag.Value.IsCompound = true

    if opt.KeyCipher != nil {
        keyBag.Id = oidPKCS8ShroundedKeyBag

        if keyBag.Value.Bytes, err = this.encodePKCS8ShroudedKeyBag(rand, privateKey, password, opt); err != nil {
            return
        }
    } else {
        keyBag.Id = oidKeyBag
        keyBag.Value.Bytes = privateKey
    }

    // 额外数据
    localKeyIdAttr, err := this.makeCertLocalKeyIdAttr(this.cert)
    if err != nil {
        err = errors.New("PKCS12: " + err.Error())
        return
    }

    keyBag.Attributes = append(keyBag.Attributes, localKeyIdAttr)

    return makeSafeContents(rand, []SafeBag{keyBag}, nil, Opts{})
}

func (this *PKCS12) marshalCert(rand io.Reader, password []byte, opt Opts) (ci ContentInfo, err error) {
    // 证书
    certificate := this.cert

    // 额外数据
    localKeyIdAttr, err := this.makeCertLocalKeyIdAttr(certificate)
    if err != nil {
        err = errors.New("PKCS12: " + err.Error())
        return
    }

    var certBags []SafeBag

    // 证书
    var certBag *SafeBag
    if certBag, err = makeCertBag(certificate, []PKCS12Attribute{localKeyIdAttr}); err != nil {
        return
    }

    certBags = append(certBags, *certBag)

    // 证书链
    for _, cert := range this.caCerts {
        var certBag *SafeBag
        if certBag, err = makeCertBag(cert, []PKCS12Attribute{}); err != nil {
            return
        }

        certBags = append(certBags, *certBag)
    }

    return makeSafeContents(rand, certBags, password, opt)
}

func (this *PKCS12) marshalTrustStoreEntries(rand io.Reader, password []byte, opt Opts) (ci ContentInfo, err error) {
    var certAttributes []PKCS12Attribute

    extKeyUsageOidBytes, err := asn1.Marshal(oidAnyExtendedKeyUsage)
    if err != nil {
        return
    }

    // the oidJavaTrustStore attribute contains the EKUs for which
    // this trust anchor will be valid
    certAttributes = append(certAttributes, PKCS12Attribute{
        Id: oidJavaTrustStore,
        Value: asn1.RawValue{
            Class:      0,
            Tag:        17,
            IsCompound: true,
            Bytes:      extKeyUsageOidBytes,
        },
    })

    entries := this.trustStores

    var certBags []SafeBag
    for _, entry := range entries {

        bmpFriendlyName, err1 := bmpString(entry.FriendlyName)
        if err1 != nil {
            err = err1
            return
        }

        encodedFriendlyName, err1 := asn1.Marshal(asn1.RawValue{
            Class:      0,
            Tag:        30,
            IsCompound: false,
            Bytes:      bmpFriendlyName,
        })
        if err1 != nil {
            err = err1
            return
        }

        friendlyName := PKCS12Attribute{
            Id: oidFriendlyName,
            Value: asn1.RawValue{
                Class:      0,
                Tag:        17,
                IsCompound: true,
                Bytes:      encodedFriendlyName,
            },
        }

        certBag, err1 := makeCertBag(entry.Cert, append(certAttributes, friendlyName))
        if err1 != nil {
            err = err1
            return
        }

        certBags = append(certBags, *certBag)
    }

    return makeSafeContents(rand, certBags, password, opt)
}

func (this *PKCS12) marshalSecretKey(rand io.Reader, password []byte, opt Opts) (ci ContentInfo, err error) {
    secretKey := this.secretKey

    secretFingerprint := sha1.Sum(secretKey)

    var localKeyIdAttr PKCS12Attribute
    localKeyIdAttr.Id = oidLocalKeyID
    localKeyIdAttr.Value.Class = 0
    localKeyIdAttr.Value.Tag = 17
    localKeyIdAttr.Value.IsCompound = true
    if localKeyIdAttr.Value.Bytes, err = asn1.Marshal(secretFingerprint[:]); err != nil {
        return
    }

    var keyBag SafeBag
    keyBag.Id = oidSecretBag
    keyBag.Value.Class = 2
    keyBag.Value.Tag = 0
    keyBag.Value.IsCompound = true
    if keyBag.Value.Bytes, err = encodeSecretBag(rand, secretKey, password, opt); err != nil {
        return
    }
    keyBag.Attributes = append(keyBag.Attributes, localKeyIdAttr)

    return makeSafeContents(rand, []SafeBag{keyBag}, nil, Opts{})
}

func (this *PKCS12) Marshal(rand io.Reader, password string, opts ...Opts) (pfxData []byte, err error) {
    var opt = DefaultOpts
    if len(opts) > 0 {
        opt = opts[0]
    }

    encodedPassword, err := bmpStringZeroTerminated(password)
    if err != nil {
        return nil, err
    }

    var pfx PfxPdu
    pfx.Version = PKCS12Version

    authenticatedSafe := make([]ContentInfo, 0)

    // 私钥
    if this.privateKey != nil {
        ci, err := this.marshalPrivateKey(rand, encodedPassword, opt)
        if err != nil {
            return nil, err
        }

        authenticatedSafe = append(authenticatedSafe, ci)
    }

    // 证书
    if this.cert != nil {
        ci, err := this.marshalCert(rand, encodedPassword, opt)
        if err != nil {
            return nil, err
        }

        authenticatedSafe = append(authenticatedSafe, ci)
    }

    // JAVA 证书链
    if len(this.trustStores) > 0 {
        ci, err := this.marshalTrustStoreEntries(rand, encodedPassword, opt)
        if err != nil {
            return nil, err
        }

        authenticatedSafe = append(authenticatedSafe, ci)
    }

    // 密钥
    if this.secretKey != nil {
        ci, err := this.marshalSecretKey(rand, encodedPassword, opt)
        if err != nil {
            return nil, err
        }

        authenticatedSafe = append(authenticatedSafe, ci)
    }

    var authenticatedSafeBytes []byte
    if authenticatedSafeBytes, err = asn1.Marshal(authenticatedSafe[:]); err != nil {
        return nil, err
    }

    if opt.MacKDFOpts != nil {
        // compute the MAC
        var kdfMacData MacKDFParameters
        kdfMacData, err = opt.MacKDFOpts.Compute(authenticatedSafeBytes, encodedPassword)
        if err != nil {
            return nil, err
        }

        pfx.MacData = kdfMacData.(MacData)
    }

    pfx.AuthSafe.ContentType = oidDataContentType
    pfx.AuthSafe.Content.Class = 2
    pfx.AuthSafe.Content.Tag = 0
    pfx.AuthSafe.Content.IsCompound = true
    if pfx.AuthSafe.Content.Bytes, err = asn1.Marshal(authenticatedSafeBytes); err != nil {
        return nil, err
    }

    if pfxData, err = asn1.Marshal(pfx); err != nil {
        return nil, errors.New("pkcs12: error writing P12 data: " + err.Error())
    }

    return
}
