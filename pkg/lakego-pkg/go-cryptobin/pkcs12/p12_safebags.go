package pkcs12

import (
    "io"
    "fmt"
    "errors"
    "encoding/pem"
    "encoding/asn1"
    "crypto/x509/pkix"

    "github.com/deatil/go-cryptobin/pkcs8/pbes1"
    "github.com/deatil/go-cryptobin/pkcs8/pbes2"
    "github.com/deatil/go-cryptobin/pkcs12/enveloped"
)

func (this *PKCS12) makeSafeContents(rand io.Reader, bags []SafeBag, password []byte, opts Opts) (ci ContentInfo, err error) {
    var data []byte
    if data, err = asn1.Marshal(bags); err != nil {
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
        // enveloped 加密
        if opts.CertCipher == EnvelopedCipher && this.envelopedOpts != nil {
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

        cipher := opts.CertCipher

        var algo pkix.AlgorithmIdentifier
        var encrypted []byte

        // when pbes2
        if pbes2.CheckCipher(cipher) {
            var passwordString string

            // change type to utf-8
            passwordString, err = decodeBMPString(password)
            if err != nil {
                return
            }

            password = []byte(passwordString)

            encrypted, algo, err = pbes2.PBES2Encrypt(rand, data, password, &pbes2.Opts{
                opts.CertCipher,
                opts.CertKDFOpts,
            })
            if err != nil {
                err = errors.New("go-cryptobin/pkcs12: " + err.Error())
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
        return nil, nil, errors.New("go-cryptobin/pkcs12: error reading P12 data: " + err.Error())
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
            return nil, nil, errors.New("go-cryptobin/pkcs12: no MAC in data")
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
                    return nil, nil, errors.New("go-cryptobin/pkcs12: enveloped opts is error")
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

                // if pbes2
                if pbes2.CheckPBES2(contentEncryptionAlgorithm.Algorithm) {
                    // change type to utf-8
                    passwordString, err := decodeBMPString(password)
                    if err != nil {
                        return nil, nil, err
                    }

                    password = []byte(passwordString)

                    data, err = pbes2.PBES2Decrypt(encryptedContent, contentEncryptionAlgorithm, password)
                    if err != nil {
                        return nil, nil, errors.New("go-cryptobin/pkcs12: " + err.Error())
                    }
                } else {
                    newCipher, enParams, err := this.parseContentEncryptionAlgorithm(contentEncryptionAlgorithm)
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

// ============

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

        keyBlock, err = pbes2.EncryptPKCS8PrivateKey(rand, "KEY", pkData, password, pbes2.Opts{
            opt.KeyCipher,
            opt.KeyKDFOpts,
        })
    } else {
        keyBlock, err = pbes1.EncryptPKCS8Privatekey(rand, "KEY", pkData, password, opt.KeyCipher)
    }

    if err != nil {
        return nil, err
    }

    asn1Data = keyBlock.Bytes

    return asn1Data, nil
}

func (this *PKCS12) decodePKCS8ShroudedKeyBag(asn1Data, password []byte) (pkData []byte, err error) {
    pkData, err = pbes2.DecryptPKCS8PrivateKey(asn1Data, password)
    if err != nil {
        pkData, err = pbes1.DecryptPKCS8Privatekey(asn1Data, password)
        if err != nil {
            return nil, errors.New("go-cryptobin/pkcs12: error decrypting PKCS#8: " + err.Error())
        }
    }

    ret := new(asn1.RawValue)
    if err = unmarshal(pkData, ret); err != nil {
        return nil, errors.New("go-cryptobin/pkcs12: error unmarshaling decrypted private key: " + err.Error())
    }

    return pkData, nil
}

// ============

func (this *PKCS12) decodeSecretBag(asn1Data []byte, password []byte) (secretKey []byte, err error) {
    bag := new(secretBag)
    if err := unmarshal(asn1Data, bag); err != nil {
        return nil, errors.New("go-cryptobin/pkcs12: error decoding secret bag: " + err.Error())
    }

    data := bag.SecretValue

    var decrypted []byte

    if bag.SecretTypeID.Equal(oidPKCS8ShroundedKeyBag) {
        decrypted, err = pbes1.DecryptPKCS8PrivateKey(data, password)
        if err != nil {
            decrypted, err = pbes2.DecryptPKCS8PrivateKey(data, password)
            if err != nil {
                return nil, errors.New("go-cryptobin/pkcs12: error decrypting PKCS#8: " + err.Error())
            }
        }
    } else if bag.SecretTypeID.Equal(oidKeyBag) {
        decrypted = data
    } else {
        return nil, NotImplementedError("only PKCS#8 shrouded key bag secretTypeID are supported")
    }

    s := new(pkcs8)
    if err = unmarshal(decrypted, s); err != nil {
        return nil, errors.New("go-cryptobin/pkcs12: error unmarshaling decrypted secret key: " + err.Error())
    }

    if s.Version != 0 {
        return nil, NotImplementedError("only secret key v0 are supported")
    }

    return s.PrivateKey, nil
}

func (this *PKCS12) encodeSecretBag(rand io.Reader, secretKey []byte, password []byte, opt Opts) (asn1Data []byte, err error) {
    var s pkcs8
    s.Version = 0
    s.Algo = pkix.AlgorithmIdentifier{
        Algorithm:  oidSecretBag,
        Parameters: asn1.RawValue{
            Tag: asn1.TagNull,
        },
    }
    s.PrivateKey = secretKey

    pkData, err := asn1.Marshal(s)
    if err != nil {
        return nil, errors.New("go-cryptobin/pkcs12: " + err.Error())
    }

    var bag secretBag

    if opt.KeyCipher != nil {
        var keyBlock *pem.Block

        if opt.KeyKDFOpts != nil {
            passwordString, err := decodeBMPString(password)
            if err != nil {
                return nil, err
            }

            password = []byte(passwordString)

            keyBlock, err = pbes2.EncryptPKCS8PrivateKey(rand, "KEY", pkData, password, pbes2.Opts{
                opt.KeyCipher,
                opt.KeyKDFOpts,
            })
        } else {
            keyBlock, err = pbes1.EncryptPKCS8PrivateKey(rand, "KEY", pkData, password, opt.KeyCipher)
        }

        if err != nil {
            return nil, errors.New("go-cryptobin/pkcs12: " + err.Error())
        }

        bag.SecretTypeID = oidPKCS8ShroundedKeyBag
        bag.SecretValue = keyBlock.Bytes
    } else {
        bag.SecretTypeID = oidKeyBag
        bag.SecretValue = pkData
    }

    if asn1Data, err = asn1.Marshal(bag); err != nil {
        return nil, errors.New("go-cryptobin/pkcs12: error encoding secret bag: " + err.Error())
    }

    return asn1Data, nil
}

// ============

// 解析加密数据
func (this *PKCS12) parseContentEncryptionAlgorithm(contentEncryptionAlgorithm pkix.AlgorithmIdentifier) (Cipher, []byte, error) {
    oid := contentEncryptionAlgorithm.Algorithm.String()

    newCipher, err := pbes1.GetCipher(oid)
    if err != nil {
        return nil, nil, fmt.Errorf("go-cryptobin/pkcs12: unsupported cipher (OID: %s)", oid)
    }

    params := contentEncryptionAlgorithm.Parameters.FullBytes

    return newCipher, params, nil
}
