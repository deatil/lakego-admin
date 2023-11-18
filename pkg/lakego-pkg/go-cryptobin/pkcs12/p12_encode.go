package pkcs12

import (
    "io"
    "errors"
    "crypto"
    "crypto/sha1"
    "crypto/x509"
    "crypto/x509/pkix"
    "encoding/pem"
    "encoding/asn1"

    "github.com/deatil/go-cryptobin/pkcs12/enveloped"
    pkcs8_pbes1 "github.com/deatil/go-cryptobin/pkcs8/pbes1"
    pkcs8_pbes2 "github.com/deatil/go-cryptobin/pkcs8/pbes2"
)

func (this *PKCS12) makeSafeContents(rand io.Reader, bags []SafeBag, password []byte, opts Opts) (ci ContentInfo, err error) {
    var data []byte
    if data, err = asn1.Marshal(bags); err != nil {
        return
    }

    // enveloped 加密
    if this.envelopedOpts != nil {
        envelopedOpts := this.envelopedOpts

        var encodedData []byte

        encodedData, err = enveloped.
            NewEnveloped().
            Encrypt(rand, data, envelopedOpts.Recipients, enveloped.Opts{
                Cipher:     envelopedOpts.Cipher,
                KeyEncrypt: envelopedOpts.KeyEncrypt,
            })
        if err != nil {
            return
        }

        err = unmarshal(encodedData, &ci)

        return
    }

    if opts.CertCipher == nil {
        ci.ContentType = oidDataContentType
        ci.Content.Class = 2
        ci.Content.Tag = 0
        ci.Content.IsCompound = true
        if ci.Content.Bytes, err = asn1.Marshal(data); err != nil {
            return
        }
    } else {
        cipher := opts.CertCipher

        var algo pkix.AlgorithmIdentifier
        var encrypted []byte

        // when pbes2
        if pkcs8_pbes2.CheckCipher(cipher) {
            var passwordString string

            // change type to utf-8
            passwordString, err = decodeBMPString(password)
            if err != nil {
                return
            }

            password = []byte(passwordString)

            encrypted, algo, err = pkcs8_pbes2.PBES2Encrypt(rand, data, password, &pkcs8_pbes2.Opts{
                opts.CertCipher,
                opts.CertKDFOpts,
            })
            if err != nil {
                err = errors.New("pkcs12: " + err.Error())
                return
            }
        } else {
            var params []byte
            encrypted, params, err = cipher.Encrypt(rand, password, data)
            if err != nil {
                return
            }

            algo.Algorithm = cipher.OID()
            algo.Parameters.FullBytes = params
        }

        var encryptedData EncryptedData
        encryptedData.Version = 0
        encryptedData.EncryptedContentInfo.ContentType = oidDataContentType
        encryptedData.EncryptedContentInfo.ContentEncryptionAlgorithm = algo
        encryptedData.EncryptedContentInfo.EncryptedContent = encrypted

        ci.ContentType = oidEncryptedDataContentType
        ci.Content.Class = 2
        ci.Content.Tag = 0
        ci.Content.IsCompound = true
        if ci.Content.Bytes, err = asn1.Marshal(encryptedData); err != nil {
            return
        }
    }

    return
}

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

            case ci.ContentType.Equal(oidEnvelopedDataContentType):
                encodedData, err := asn1.Marshal(ci)
                if err != nil {
                    return nil, nil, err
                }

                if this.envelopedOpts == nil {
                    return nil, nil, errors.New("pkcs12: enveloped opts is error")
                }

                envelopedOpts := this.envelopedOpts

                data, err = enveloped.
                    NewEnveloped().
                    Decrypt(encodedData, envelopedOpts.Cert, envelopedOpts.PrivateKey)
                if err != nil {
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

func (this *PKCS12) AddSdsiCertBytes(cert []byte) {
    this.sdsiCert = cert
}

func (this *PKCS12) AddCRL(crl *pkix.CertificateList) error {
    crlBytes, err := asn1.Marshal(*crl)
    if err != nil {
        return err
    }

    this.crl = crlBytes

    return nil
}

func (this *PKCS12) AddCRLBytes(crl []byte) {
    this.crl = crl
}

func (this *PKCS12) AddSecretKey(secretKey []byte) {
    this.secretKey = secretKey
}

//===============

// 获取证书签名
func (this *PKCS12) makeLocalKeyIdAttr(data []byte) (PKCS12Attribute, error) {
    var fingerprint []byte

    if this.localKeyId != nil {
        fingerprint = this.localKeyId
    } else {
        sum := sha1.Sum(data)
        fingerprint = sum[:]
    }

    localKeyId, err := asn1.Marshal(fingerprint)
    if err != nil {
        return PKCS12Attribute{}, err
    }

    var localKeyIdAttr PKCS12Attribute
    localKeyIdAttr.Id = oidLocalKeyID
    localKeyIdAttr.Value.Class = 0
    localKeyIdAttr.Value.Tag = 17
    localKeyIdAttr.Value.IsCompound = true
    localKeyIdAttr.Value.Bytes = localKeyId

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
    localKeyIdAttr, err := this.makeLocalKeyIdAttr(this.cert)
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
    localKeyIdAttr, err := this.makeLocalKeyIdAttr(certificate)
    if err != nil {
        err = errors.New("PKCS12: " + err.Error())
        return
    }

    var certBags []SafeBag

    // 证书
    var certBag *SafeBag
    if certBag, err = NewCertBagEntry().MakeCertBag(certificate, []PKCS12Attribute{localKeyIdAttr}); err != nil {
        return
    }

    certBags = append(certBags, *certBag)

    // 证书链
    for _, cert := range this.caCerts {
        var certBag *SafeBag
        if certBag, err = NewCertBagEntry().MakeCertBag(cert, []PKCS12Attribute{}); err != nil {
            return
        }

        certBags = append(certBags, *certBag)
    }

    return this.makeSafeContents(rand, certBags, password, opt)
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

        certBag, err1 := NewCertBagEntry().MakeCertBag(entry.Cert, append(certAttributes, friendlyName))
        if err1 != nil {
            err = err1
            return
        }

        certBags = append(certBags, *certBag)
    }

    return makeSafeContents(rand, certBags, password, opt)
}

func (this *PKCS12) marshalSdsiCert(rand io.Reader, password []byte, opt Opts) (ci ContentInfo, err error) {
    sdsiCert := this.sdsiCert

    // ID
    localKeyIdAttr, err := this.makeLocalKeyIdAttr(sdsiCert)
    if err != nil {
        err = errors.New("PKCS12: " + err.Error())
        return
    }

    var certBags []SafeBag

    // sdsiCert
    var certBag *SafeBag
    if certBag, err = NewCertBagEntry().WithType(CertTypeSdsi).MakeCertBag(sdsiCert, []PKCS12Attribute{localKeyIdAttr}); err != nil {
        return
    }

    certBags = append(certBags, *certBag)

    return this.makeSafeContents(rand, certBags, password, opt)
}

func (this *PKCS12) marshalCRL(rand io.Reader, password []byte, opt Opts) (ci ContentInfo, err error) {
    crl := this.crl

    // ID
    localKeyIdAttr, err := this.makeLocalKeyIdAttr(crl)
    if err != nil {
        err = errors.New("PKCS12: " + err.Error())
        return
    }

    var certBags []SafeBag

    // CRL
    var certBag *SafeBag
    if certBag, err = NewCRLBagEntry().MakeCertBag(crl, []PKCS12Attribute{localKeyIdAttr}); err != nil {
        return
    }

    certBags = append(certBags, *certBag)

    return this.makeSafeContents(rand, certBags, password, opt)
}

func (this *PKCS12) marshalSecretKey(rand io.Reader, password []byte, opt Opts) (ci ContentInfo, err error) {
    secretKey := this.secretKey

    // 额外数据
    localKeyIdAttr, err := this.makeLocalKeyIdAttr(secretKey)
    if err != nil {
        err = errors.New("PKCS12: " + err.Error())
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

    // sdsiCert
    if this.sdsiCert != nil {
        ci, err := this.marshalSdsiCert(rand, encodedPassword, opt)
        if err != nil {
            return nil, err
        }

        authenticatedSafe = append(authenticatedSafe, ci)
    }

    // CRL
    if this.crl != nil {
        ci, err := this.marshalCRL(rand, encodedPassword, opt)
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
