package pkcs12

import (
    "io"
    "fmt"
    "errors"
    "crypto/sha1"
    "crypto/x509"
    "crypto/x509/pkix"
    "encoding/hex"
    "encoding/pem"
    "encoding/asn1"

    gmsm_x509 "github.com/tjfoc/gmsm/x509"

    "github.com/deatil/go-cryptobin/pkcs8/pbes1"
    "github.com/deatil/go-cryptobin/pkcs8/pbes2"
)

// ToPEM converts all "safe bags" contained in pfxData to PEM blocks.
//
// Deprecated: ToPEM creates invalid PEM blocks (private keys
// are encoded as raw RSA or EC private keys rather than PKCS#8 despite being
// labeled "PRIVATE KEY").  To decode a PKCS#12 file, use DecodeChain instead,
// and use the encoding/pem package to convert to PEM if necessary.
func ToPEM(pfxData []byte, password string) ([]*pem.Block, error) {
    encodedPassword, err := bmpStringZeroTerminated(password)
    if err != nil {
        return nil, ErrIncorrectPassword
    }

    bags, encodedPassword, err := getSafeContents(pfxData, encodedPassword, 2)
    if err != nil {
        return nil, err
    }

    blocks := make([]*pem.Block, 0, len(bags))
    for _, bag := range bags {
        block, err := convertBag(&bag, encodedPassword)
        if err != nil {
            return nil, err
        }

        blocks = append(blocks, block)
    }

    return blocks, nil
}

func convertBag(bag *SafeBag, password []byte) (*pem.Block, error) {
    block := &pem.Block{
        Headers: make(map[string]string),
    }

    for _, attribute := range bag.Attributes {
        k, v, err := convertAttribute(&attribute)
        if err == errUnknownAttributeOID {
            continue
        }

        if err != nil {
            return nil, err
        }

        block.Headers[k] = v
    }

    var err error

    switch {
        case bag.Id.Equal(oidCertBag):
            block.Type = CertificateType

            block.Bytes, err = decodeCertBag(bag.Value.Bytes)
            if err != nil {
                return nil, err
            }

        case bag.Id.Equal(oidKeyBag):
            block.Type = PrivateKeyType

            key, err := ParsePKCS8PrivateKey(bag.Value.Bytes)
            if err != nil {
                return nil, err
            }

            block.Bytes, err = MarshalPrivateKey(key)
            if err != nil {
                return nil, errors.New("found unknown private key type in PKCS#8 wrapping: " + err.Error())
            }

        case bag.Id.Equal(oidPKCS8ShroundedKeyBag):
            block.Type = PrivateKeyType

            key, err := decodePkcs8ShroudedKeyBag(bag.Value.Bytes, password)
            if err != nil {
                return nil, err
            }

            block.Bytes, err = MarshalPrivateKey(key)
            if err != nil {
                return nil, errors.New("found unknown private key type in PKCS#8 wrapping: " + err.Error())
            }

        default:
            return nil, errors.New("don't know how to convert a safe bag of type " + bag.Id.String())
    }

    return block, nil
}

func convertAttribute(attribute *PKCS12Attribute) (key, value string, err error) {
    isString := false

    switch {
        case attribute.Id.Equal(oidFriendlyName):
            key = "friendlyName"
            isString = true
        case attribute.Id.Equal(oidLocalKeyID):
            key = "localKeyId"
        case attribute.Id.Equal(oidMicrosoftCSPName):
            // This key is chosen to match OpenSSL.
            key = "Microsoft CSP Name"
            isString = true
        case attribute.Id.Equal(oidJavaTrustStore):
            key = "javaTrustStore"

            storeOID := new(asn1.ObjectIdentifier)
            if _, err := asn1.Unmarshal(attribute.Value.Bytes, storeOID); err != nil {
                return "", "", err
            }

            value = (*storeOID).String()

            return
        default:
            key = attribute.Id.String()
            value = hex.EncodeToString(attribute.Value.Bytes)
            err = errUnknownAttributeOID

            return
    }

    if isString {
        if err := unmarshal(attribute.Value.Bytes, &attribute.Value); err != nil {
            return "", "", err
        }
        if value, err = decodeBMPString(attribute.Value.Bytes); err != nil {
            return "", "", err
        }
    } else {
        var id []byte
        if err := unmarshal(attribute.Value.Bytes, &id); err != nil {
            return "", "", err
        }

        value = hex.EncodeToString(id)
    }

    return key, value, nil
}

// Decode extracts a certificate and private key from pfxData, which must be a DER-encoded PKCS#12 file. This function
// assumes that there is only one certificate and only one private key in the
// pfxData.  Since PKCS#12 files often contain more than one certificate, you
// probably want to use DecodeChain instead.
func Decode(pfxData []byte, password string) (
    privateKey any,
    certificate *x509.Certificate,
    err error,
) {
    var caCerts []*x509.Certificate

    privateKey, certificate, caCerts, err = DecodeChain(pfxData, password)
    if len(caCerts) != 0 {
        err = errors.New("pkcs12: expected exactly two safe bags in the PFX PDU")
    }

    return
}

// DecodeChain extracts a certificate, a CA certificate chain, and private key
// from pfxData, which must be a DER-encoded PKCS#12 file. This function assumes that there is at least one certificate
// and only one private key in the pfxData.  The first certificate is assumed to
// be the leaf certificate, and subsequent certificates, if any, are assumed to
// comprise the CA certificate chain.
func DecodeChain(pfxData []byte, password string) (
    privateKey any,
    certificate *x509.Certificate,
    caCerts []*x509.Certificate,
    err error,
) {
    encodedPassword, err := bmpStringZeroTerminated(password)
    if err != nil {
        return nil, nil, nil, err
    }

    bags, encodedPassword, err := getSafeContents(pfxData, encodedPassword, 2)
    if err != nil {
        return nil, nil, nil, err
    }

    for _, bag := range bags {
        switch {
            case bag.Id.Equal(oidCertBag):
                certsData, err := decodeCertBag(bag.Value.Bytes)
                if err != nil {
                    return nil, nil, nil, err
                }

                certs, err := x509.ParseCertificates(certsData)
                if err != nil {
                    gmsmCerts, err := gmsm_x509.ParseCertificates(certsData)
                    if err != nil {
                        err = errors.New("pkcs12: x509 error: " + err.Error())
                        return nil, nil, nil, err
                    }

                    for _, cert := range gmsmCerts {
                        certs = append(certs, cert.ToX509Certificate())
                    }
                }

                if len(certs) != 1 {
                    err = errors.New("pkcs12: expected exactly one certificate in the certBag")
                    return nil, nil, nil, err
                }

                if certificate == nil {
                    certificate = certs[0]
                } else {
                    caCerts = append(caCerts, certs[0])
                }

            case bag.Id.Equal(oidKeyBag):
                if privateKey != nil {
                    err = errors.New("pkcs12: expected exactly one key bag")
                    return nil, nil, nil, err
                }

                if privateKey, err = ParsePKCS8PrivateKey(bag.Value.Bytes); err != nil {
                    return nil, nil, nil, err
                }

            case bag.Id.Equal(oidPKCS8ShroundedKeyBag):
                if privateKey != nil {
                    err = errors.New("pkcs12: expected exactly one key bag")
                    return nil, nil, nil, err
                }

                if privateKey, err = decodePkcs8ShroudedKeyBag(bag.Value.Bytes, encodedPassword); err != nil {
                    return nil, nil, nil, err
                }
        }
    }

    if certificate == nil {
        return nil, nil, nil, errors.New("pkcs12: certificate missing")
    }

    if privateKey == nil {
        return nil, nil, nil, errors.New("pkcs12: private key missing")
    }

    return
}

// DecodeTrustStore extracts the certificates from pfxData, which must be a DER-encoded
// PKCS#12 file containing exclusively certificates with attribute 2.16.840.1.113894.746875.1.1,
// which is used by Java to designate a trust anchor.
func DecodeTrustStore(pfxData []byte, password string) (certs []*x509.Certificate, err error) {
    encodedPassword, err := bmpStringZeroTerminated(password)
    if err != nil {
        return nil, err
    }

    bags, encodedPassword, err := getSafeContents(pfxData, encodedPassword, 1)
    if err != nil {
        return nil, err
    }

    for _, bag := range bags {
        switch {
            case bag.Id.Equal(oidCertBag):
                if !bag.hasAttribute(oidJavaTrustStore) {
                    return nil, errors.New("pkcs12: trust store contains a certificate that is not marked as trusted")
                }

                certsData, err := decodeCertBag(bag.Value.Bytes)
                if err != nil {
                    return nil, err
                }

                parsedCerts, err := x509.ParseCertificates(certsData)
                if err != nil {
                    gmsmCerts, err := gmsm_x509.ParseCertificates(certsData)
                    if err != nil {
                        err = errors.New("pkcs12: x509 error: " + err.Error())
                        return nil, err
                    }

                    for _, cert := range gmsmCerts {
                        parsedCerts = append(parsedCerts, cert.ToX509Certificate())
                    }
                }

                if len(parsedCerts) != 1 {
                    err = errors.New("pkcs12: expected exactly one certificate in the certBag")
                    return nil, err
                }

                certs = append(certs, parsedCerts[0])

            default:
                return nil, errors.New("pkcs12: expected only certificate bags")
        }
    }

    return
}

// DecodeTrustStoreEntries extracts the certificates from pfxData, which must be a DER-encoded
func DecodeTrustStoreEntries(pfxData []byte, password string) (trustStoreKeys []TrustStoreKey, err error) {
    encodedPassword, err := bmpStringZeroTerminated(password)
    if err != nil {
        return nil, err
    }

    bags, encodedPassword, err := getSafeContents(pfxData, encodedPassword, 1)
    if err != nil {
        return nil, err
    }

    for _, bag := range bags {
        switch {
            case bag.Id.Equal(oidCertBag):
                trustkey := &trustStoreKey{
                    attrs: make(map[string]string),
                }

                for _, attr := range bag.Attributes {
                    attr := attr
                    k, v, err := convertAttribute(&attr)
                    if err != nil {
                        return nil, err
                    }

                    trustkey.attrs[k] = v
                }

                if !bag.hasAttribute(oidJavaTrustStore) {
                    return nil, errors.New("pkcs12: trust store contains a certificate that is not marked as trusted")
                }

                certsData, err := decodeCertBag(bag.Value.Bytes)
                if err != nil {
                    return nil, err
                }

                parsedCerts, err := x509.ParseCertificates(certsData)
                if err != nil {
                    gmsmCerts, err := gmsm_x509.ParseCertificates(certsData)
                    if err != nil {
                        err = errors.New("pkcs12: x509 error: " + err.Error())
                        return nil, err
                    }

                    for _, cert := range gmsmCerts {
                        parsedCerts = append(parsedCerts, cert.ToX509Certificate())
                    }
                }

                if len(parsedCerts) != 1 {
                    err = errors.New("pkcs12: expected exactly one certificate in the certBag")
                    return nil, err
                }

                trustkey.cert = parsedCerts[0]

                trustStoreKeys = append(trustStoreKeys, trustkey)

            default:
                return nil, errors.New("pkcs12: expected only certificate bags")
        }
    }

    return
}

// DecodeSecret extracts the Secret key from pfxData, which must be a DER-encoded
func DecodeSecret(pfxData []byte, password string) (secretKeys []SecretKey, err error) {
    pkcs12, err := LoadPKCS12FromBytes(pfxData, password)
    if err != nil {
        return nil, err
    }

    secretKey, attrs, err := pkcs12.GetSecretKey()
    if err != nil {
        return nil, err
    }

    seckey := new(secretkey)
    seckey.key = secretKey
    seckey.attrs = attrs.ToArray()

    secretKeys = append(secretKeys, seckey)

    return
}

func getSafeContents(p12Data, password []byte, expectedItems int) (bags []SafeBag, updatedPassword []byte, err error) {
    pfx := new(PfxPdu)
    if err := unmarshal(p12Data, pfx); err != nil {
        return nil, nil, errors.New("pkcs12: error reading P12 data: " + err.Error())
    }

    if pfx.Version != 3 {
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

    if len(authenticatedSafe) != expectedItems {
        return nil, nil, NotImplementedError("expected exactly two items in the authenticated safe")
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
                if pbes2.IsPBES2(contentEncryptionAlgorithm.Algorithm) {
                    // change type to utf-8
                    passwordString, err := decodeBMPString(password)
                    if err != nil {
                        return nil, nil, err
                    }

                    password = []byte(passwordString)

                    data, err = pbes2.PBES2Decrypt(encryptedContent, contentEncryptionAlgorithm, password)
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

// for go
func Encode(
    rand io.Reader,
    privateKey any,
    certificate *x509.Certificate,
    password string,
    opts ...Opts,
) (pfxData []byte, err error) {
    return EncodeChain(rand, privateKey, certificate, nil, password, opts...)
}

// EncodeChain produces pfxData containing one private key (privateKey), an
// end-entity certificate (certificate), and any number of CA certificates
// (caCerts).
//
// The private key is encrypted with the provided password, but due to the
// weak encryption primitives used by PKCS#12, it is RECOMMENDED that you
// specify a hard-coded password (such as pkcs12.DefaultPassword) and protect
// the resulting pfxData using other means.
//
// The rand argument is used to provide entropy for the encryption, and
// can be set to rand.Reader from the crypto/rand package.
//
// EncodeChain emulates the behavior of OpenSSL's PKCS12_create: it creates two
// SafeContents: one that's encrypted with RC2 and contains the certificates,
// and another that is unencrypted and contains the private key shrouded with
// 3DES  The private key bag and the end-entity certificate bag have the
// LocalKeyId attribute set to the SHA-1 fingerprint of the end-entity
// certificate.
func EncodeChain(
    rand io.Reader,
    privateKey any,
    certificate *x509.Certificate,
    caCerts []*x509.Certificate,
    password string,
    opts ...Opts,
) (pfxData []byte, err error) {
    var opt = DefaultOpts
    if len(opts) > 0 {
        opt = opts[0]
    }

    encodedPassword, err := bmpStringZeroTerminated(password)
    if err != nil {
        return nil, err
    }

    var pfx PfxPdu
    pfx.Version = 3

    var certFingerprint = sha1.Sum(certificate.Raw)
    var localKeyIdAttr PKCS12Attribute
    localKeyIdAttr.Id = oidLocalKeyID
    localKeyIdAttr.Value.Class = 0
    localKeyIdAttr.Value.Tag = 17
    localKeyIdAttr.Value.IsCompound = true
    if localKeyIdAttr.Value.Bytes, err = asn1.Marshal(certFingerprint[:]); err != nil {
        return nil, err
    }

    var certBags []SafeBag
    var certBag *SafeBag
    if certBag, err = makeCertBag(certificate.Raw, []PKCS12Attribute{localKeyIdAttr}); err != nil {
        return nil, err
    }
    certBags = append(certBags, *certBag)

    for _, cert := range caCerts {
        if certBag, err = makeCertBag(cert.Raw, []PKCS12Attribute{}); err != nil {
            return nil, err
        }
        certBags = append(certBags, *certBag)
    }

    var keyBag SafeBag
    keyBag.Value.Class = 2
    keyBag.Value.Tag = 0
    keyBag.Value.IsCompound = true

    if opt.KeyCipher != nil {
        keyBag.Id = oidPKCS8ShroundedKeyBag
        if keyBag.Value.Bytes, err = encodePkcs8ShroudedKeyBag(rand, privateKey, encodedPassword, opt); err != nil {
            return nil, err
        }
    } else {
        keyBag.Id = oidKeyBag
        if keyBag.Value.Bytes, err = MarshalPKCS8PrivateKey(privateKey); err != nil {
            return nil, err
        }
    }

    keyBag.Attributes = append(keyBag.Attributes, localKeyIdAttr)

    // Construct an authenticated safe with two SafeContents.
    // The first SafeContents is encrypted and contains the cert bags.
    // The second SafeContents is unencrypted and contains the shrouded key bag.
    var authenticatedSafe [2]ContentInfo
    if authenticatedSafe[0], err = makeSafeContents(rand, certBags, encodedPassword, opt); err != nil {
        return nil, err
    }
    if authenticatedSafe[1], err = makeSafeContents(rand, []SafeBag{keyBag}, nil, Opts{}); err != nil {
        return nil, err
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

// EncodeTrustStore produces pfxData containing any number of CA certificates
// (certs) to be trusted. The certificates will be marked with a special OID that
// allow it to be used as a Java TrustStore in Java 1.8 and newer.
//
// Due to the weak encryption primitives used by PKCS#12, it is RECOMMENDED that
// you specify a hard-coded password (such as pkcs12.DefaultPassword) and protect
// the resulting pfxData using other means.
//
// The rand argument is used to provide entropy for the encryption, and
// can be set to rand.Reader from the crypto/rand package.
//
// EncodeTrustStore creates a single SafeContents that's encrypted with RC2
// and contains the certificates.
//
// The Subject of the certificates are used as the Friendly Names (Aliases)
// within the resulting pfxData. If certificates share a Subject, then the
// resulting Friendly Names (Aliases) will be identical, which Java may treat as
// the same entry when used as a Java TrustStore, e.g. with `keytool`.  To
// customize the Friendly Names, use EncodeTrustStoreEntries.
func EncodeTrustStore(
    rand io.Reader,
    certs []*x509.Certificate,
    password string,
    opts ...Opts,
) (pfxData []byte, err error) {
    var certsWithFriendlyNames []TrustStoreEntry
    for _, cert := range certs {
        certsWithFriendlyNames = append(certsWithFriendlyNames, TrustStoreEntry{
            Cert:         cert,
            FriendlyName: cert.Subject.String(),
        })
    }

    return EncodeTrustStoreEntries(rand, certsWithFriendlyNames, password, opts...)
}

// TrustStoreEntry represents an entry in a Java TrustStore.
type TrustStoreEntry struct {
    Cert         *x509.Certificate
    FriendlyName string
}

// EncodeTrustStoreEntries produces pfxData containing any number of CA
// certificates (entries) to be trusted. The certificates will be marked with a
// special OID that allow it to be used as a Java TrustStore in Java 1.8 and newer.
//
// This is identical to EncodeTrustStore, but also allows for setting specific
// Friendly Names (Aliases) to be used per certificate, by specifying a slice
// of TrustStoreEntry.
//
// If the same Friendly Name is used for more than one certificate, then the
// resulting Friendly Names (Aliases) in the pfxData will be identical, which Java
// may treat as the same entry when used as a Java TrustStore, e.g. with `keytool`.
//
// Due to the weak encryption primitives used by PKCS#12, it is RECOMMENDED that
// you specify a hard-coded password (such as pkcs12.DefaultPassword) and protect
// the resulting pfxData using other means.
//
// The rand argument is used to provide entropy for the encryption, and
// can be set to rand.Reader from the crypto/rand package.
//
// EncodeTrustStoreEntries creates a single SafeContents that's encrypted
// with RC2 and contains the certificates.
func EncodeTrustStoreEntries(
    rand io.Reader,
    entries []TrustStoreEntry,
    password string,
    opts ...Opts,
) (pfxData []byte, err error) {
    var opt = DefaultOpts
    if len(opts) > 0 {
        opt = opts[0]
    }

    encodedPassword, err := bmpStringZeroTerminated(password)
    if err != nil {
        return nil, err
    }

    var pfx PfxPdu
    pfx.Version = 3

    var certAttributes []PKCS12Attribute

    extKeyUsageOidBytes, err := asn1.Marshal(oidAnyExtendedKeyUsage)
    if err != nil {
        return nil, err
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

    var certBags []SafeBag
    for _, entry := range entries {

        bmpFriendlyName, err := bmpString(entry.FriendlyName)
        if err != nil {
            return nil, err
        }

        encodedFriendlyName, err := asn1.Marshal(asn1.RawValue{
            Class:      0,
            Tag:        30,
            IsCompound: false,
            Bytes:      bmpFriendlyName,
        })
        if err != nil {
            return nil, err
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

        certBag, err := makeCertBag(entry.Cert.Raw, append(certAttributes, friendlyName))
        if err != nil {
            return nil, err
        }

        certBags = append(certBags, *certBag)
    }

    // Construct an authenticated safe with one SafeContent.
    // The SafeContents is encrypted and contains the cert bags.
    var authenticatedSafe [1]ContentInfo
    if authenticatedSafe[0], err = makeSafeContents(rand, certBags, encodedPassword, opt); err != nil {
        return nil, err
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

// Encode Secret with der
func EncodeSecret(rand io.Reader, secretKey []byte, password string, opts ...Opts) (pfxData []byte, err error) {
    var opt = DefaultOpts
    if len(opts) > 0 {
        opt = opts[0]
    }

    pkcs12 := NewPKCS12Encode()
    pkcs12.AddSecretKey(secretKey)

    pfxData, err = pkcs12.Marshal(rand, password, opt)
    if err != nil {
        return nil, err
    }

    return pfxData, nil
}

func makeCertBag(certBytes []byte, attributes []PKCS12Attribute) (certBag *SafeBag, err error) {
    certBag = new(SafeBag)
    certBag.Id = oidCertBag
    certBag.Value.Class = 2
    certBag.Value.Tag = 0
    certBag.Value.IsCompound = true

    if certBag.Value.Bytes, err = encodeCertBag(certBytes); err != nil {
        return nil, err
    }

    certBag.Attributes = attributes
    return
}

func makeSafeContents(rand io.Reader, bags []SafeBag, password []byte, opts Opts) (ci ContentInfo, err error) {
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

// 解析加密数据
func parseContentEncryptionAlgorithm(contentEncryptionAlgorithm pkix.AlgorithmIdentifier) (Cipher, []byte, error) {
    oid := contentEncryptionAlgorithm.Algorithm.String()

    newCipher, err := pbes1.GetCipher(oid)
    if err != nil {
        return nil, nil, fmt.Errorf("pkcs8: unsupported cipher (OID: %s)", oid)
    }

    params := contentEncryptionAlgorithm.Parameters.FullBytes

    return newCipher, params, nil
}
