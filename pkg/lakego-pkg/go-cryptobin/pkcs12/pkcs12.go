package pkcs12

import (
    "io"
    "errors"
    "crypto/sha1"
    "crypto/x509"
    "crypto/x509/pkix"
    "encoding/asn1"
    "encoding/hex"
    "encoding/pem"
)

// DefaultPassword is the string "changeit", a commonly-used password for
// PKCS#12 files. Due to the weak encryption used by PKCS#12, it is
// RECOMMENDED that you use DefaultPassword when encoding PKCS#12 files,
// and protect the PKCS#12 files using other means.
const DefaultPassword = "changeit"

var (
    oidDataContentType          = asn1.ObjectIdentifier([]int{1, 2, 840, 113549, 1, 7, 1})
    oidEncryptedDataContentType = asn1.ObjectIdentifier([]int{1, 2, 840, 113549, 1, 7, 6})

    oidFriendlyName     = asn1.ObjectIdentifier([]int{1, 2, 840, 113549, 1, 9, 20})
    oidLocalKeyID       = asn1.ObjectIdentifier([]int{1, 2, 840, 113549, 1, 9, 21})
    oidMicrosoftCSPName = asn1.ObjectIdentifier([]int{1, 3, 6, 1, 4, 1, 311, 17, 1})

    oidJavaTrustStore      = asn1.ObjectIdentifier([]int{2, 16, 840, 1, 113894, 746875, 1, 1})
    oidAnyExtendedKeyUsage = asn1.ObjectIdentifier([]int{2, 5, 29, 37, 0})
)

type contentInfo struct {
    ContentType asn1.ObjectIdentifier
    Content     asn1.RawValue `asn1:"tag:0,explicit,optional"`
}

type pfxPdu struct {
    Version  int
    AuthSafe contentInfo
    MacData  macData `asn1:"optional"`
}

type encryptedData struct {
    Version              int
    EncryptedContentInfo encryptedContentInfo
}

type encryptedContentInfo struct {
    ContentType                asn1.ObjectIdentifier
    ContentEncryptionAlgorithm pkix.AlgorithmIdentifier
    EncryptedContent           []byte `asn1:"tag:0,optional"`
}

func (this encryptedContentInfo) Algorithm() pkix.AlgorithmIdentifier {
    return this.ContentEncryptionAlgorithm
}

func (this encryptedContentInfo) Data() []byte {
    return this.EncryptedContent
}

type safeBag struct {
    Id         asn1.ObjectIdentifier
    Value      asn1.RawValue     `asn1:"tag:0,explicit"`
    Attributes []pkcs12Attribute `asn1:"set,optional"`
}

func (bag *safeBag) hasAttribute(id asn1.ObjectIdentifier) bool {
    for _, attr := range bag.Attributes {
        if attr.Id.Equal(id) {
            return true
        }
    }
    return false
}

type pkcs12Attribute struct {
    Id    asn1.ObjectIdentifier
    Value asn1.RawValue `asn1:"set"`
}

// PEM block types
const (
    certificateType = "CERTIFICATE"
    privateKeyType  = "PRIVATE KEY"
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

func convertBag(bag *safeBag, password []byte) (*pem.Block, error) {
    block := &pem.Block{
        Headers: make(map[string]string),
    }

    for _, attribute := range bag.Attributes {
        k, v, err := convertAttribute(&attribute)
        if err != nil {
            return nil, err
        }

        block.Headers[k] = v
    }

    switch {
        case bag.Id.Equal(oidCertBag):
            block.Type = certificateType
            certsData, err := decodeCertBag(bag.Value.Bytes)
            if err != nil {
                return nil, err
            }
            block.Bytes = certsData
        case bag.Id.Equal(oidPKCS8ShroundedKeyBag):
            block.Type = privateKeyType

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

func convertAttribute(attribute *pkcs12Attribute) (key, value string, err error) {
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
        default:
            return "", "", errors.New("pkcs12: unknown attribute with OID " + attribute.Id.String())
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
                    return nil, nil, nil, err
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
                    return nil, err
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

// 解析出 Secret
func DecodeSecret(pfxData []byte, password string) (secretKeys []SecretKey, err error) {
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
            case bag.Id.Equal(oidSecretBag):
                seckey := &secretkey{
                    attrs: make(map[string]string),
                }

                for _, attr := range bag.Attributes {
                    attr := attr
                    k, v, err := convertAttribute(&attr)
                    if err != nil {
                        return nil, err
                    }

                    seckey.attrs[k] = v
                }

                seckey.key, err = decodeSecretBag(bag.Value.Bytes, encodedPassword)
                if err != nil {
                    return nil, err
                }

                secretKeys = append(secretKeys, seckey)

            default:
                return nil, errors.New("pkcs12: expected only secret bags")
        }
    }

    return
}

func getSafeContents(p12Data, password []byte, expectedItems int) (bags []safeBag, updatedPassword []byte, err error) {
    pfx := new(pfxPdu)
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

    var authenticatedSafe []contentInfo
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
                var encryptedData encryptedData
                if err := unmarshal(ci.Content.Bytes, &encryptedData); err != nil {
                    return nil, nil, err
                }

                if encryptedData.Version != 0 {
                    return nil, nil, NotImplementedError("only version 0 of EncryptedData is supported")
                }

                encryptedContentInfo := encryptedData.EncryptedContentInfo
                encryptedContent := encryptedContentInfo.EncryptedContent
                contentEncryptionAlgorithm := encryptedContentInfo.ContentEncryptionAlgorithm

                newCipher, enParams, err := parseContentEncryptionAlgorithm(contentEncryptionAlgorithm)
                if err != nil {
                    return nil, nil, err
                }

                data, err = newCipher.Decrypt(password, enParams, encryptedContent)
                if err != nil {
                    return nil, nil, err
                }
            default:
                return nil, nil, NotImplementedError("only data and encryptedData content types are supported in authenticated safe")
        }

        var safeContents []safeBag
        if err := unmarshal(data, &safeContents); err != nil {
            return nil, nil, err
        }

        bags = append(bags, safeContents...)
    }

    return bags, password, nil
}

// 兼容 go 默认包
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

    cipher := opt.Cipher
    if cipher == nil {
        return nil, errors.New("pkcs12: unknown opts cipher")
    }

    kdfOpts := opt.KDFOpts
    if kdfOpts == nil {
        return nil, errors.New("pkcs12: unknown opts kdfOpts")
    }

    pkcs8Cipher := opt.PKCS8Cipher
    if pkcs8Cipher == nil {
        return nil, errors.New("pkcs12: unknown opts pkcs8Cipher")
    }

    encodedPassword, err := bmpStringZeroTerminated(password)
    if err != nil {
        return nil, err
    }

    var pfx pfxPdu
    pfx.Version = 3

    var certFingerprint = sha1.Sum(certificate.Raw)
    var localKeyIdAttr pkcs12Attribute
    localKeyIdAttr.Id = oidLocalKeyID
    localKeyIdAttr.Value.Class = 0
    localKeyIdAttr.Value.Tag = 17
    localKeyIdAttr.Value.IsCompound = true
    if localKeyIdAttr.Value.Bytes, err = asn1.Marshal(certFingerprint[:]); err != nil {
        return nil, err
    }

    var certBags []safeBag
    var certBag *safeBag
    if certBag, err = makeCertBag(certificate.Raw, []pkcs12Attribute{localKeyIdAttr}); err != nil {
        return nil, err
    }
    certBags = append(certBags, *certBag)

    for _, cert := range caCerts {
        if certBag, err = makeCertBag(cert.Raw, []pkcs12Attribute{}); err != nil {
            return nil, err
        }
        certBags = append(certBags, *certBag)
    }

    var keyBag safeBag
    keyBag.Id = oidPKCS8ShroundedKeyBag
    keyBag.Value.Class = 2
    keyBag.Value.Tag = 0
    keyBag.Value.IsCompound = true
    if keyBag.Value.Bytes, err = encodePkcs8ShroudedKeyBag(rand, privateKey, encodedPassword, opt); err != nil {
        return nil, err
    }
    keyBag.Attributes = append(keyBag.Attributes, localKeyIdAttr)

    // Construct an authenticated safe with two SafeContents.
    // The first SafeContents is encrypted and contains the cert bags.
    // The second SafeContents is unencrypted and contains the shrouded key bag.
    var authenticatedSafe [2]contentInfo
    if authenticatedSafe[0], err = makeSafeContents(rand, certBags, encodedPassword, opt.Cipher); err != nil {
        return nil, err
    }
    if authenticatedSafe[1], err = makeSafeContents(rand, []safeBag{keyBag}, nil, nil); err != nil {
        return nil, err
    }

    var authenticatedSafeBytes []byte
    if authenticatedSafeBytes, err = asn1.Marshal(authenticatedSafe[:]); err != nil {
        return nil, err
    }

    // compute the MAC
    var kdfMacData KDFParameters
    kdfMacData, err = opt.KDFOpts.Compute(authenticatedSafeBytes, encodedPassword)
    if err != nil {
        return nil, err
    }

    pfx.MacData = kdfMacData.(macData)

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

    cipher := opt.Cipher
    if cipher == nil {
        return nil, errors.New("pkcs12: unknown opts cipher")
    }

    kdfOpts := opt.KDFOpts
    if kdfOpts == nil {
        return nil, errors.New("pkcs12: unknown opts kdfOpts")
    }

    encodedPassword, err := bmpStringZeroTerminated(password)
    if err != nil {
        return nil, err
    }

    var pfx pfxPdu
    pfx.Version = 3

    var certAttributes []pkcs12Attribute

    extKeyUsageOidBytes, err := asn1.Marshal(oidAnyExtendedKeyUsage)
    if err != nil {
        return nil, err
    }

    // the oidJavaTrustStore attribute contains the EKUs for which
    // this trust anchor will be valid
    certAttributes = append(certAttributes, pkcs12Attribute{
        Id: oidJavaTrustStore,
        Value: asn1.RawValue{
            Class:      0,
            Tag:        17,
            IsCompound: true,
            Bytes:      extKeyUsageOidBytes,
        },
    })

    var certBags []safeBag
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

        friendlyName := pkcs12Attribute{
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
    var authenticatedSafe [1]contentInfo
    if authenticatedSafe[0], err = makeSafeContents(rand, certBags, encodedPassword, opt.Cipher); err != nil {
        return nil, err
    }

    var authenticatedSafeBytes []byte
    if authenticatedSafeBytes, err = asn1.Marshal(authenticatedSafe[:]); err != nil {
        return nil, err
    }

    // compute the MAC
    var kdfMacData KDFParameters
    kdfMacData, err = opt.KDFOpts.Compute(authenticatedSafeBytes, encodedPassword)
    if err != nil {
        return nil, err
    }

    pfx.MacData = kdfMacData.(macData)

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

// 编码 Secret
func EncodeSecret(rand io.Reader, secretKey []byte, password string, opts ...Opts) (pfxData []byte, err error) {
    var opt = DefaultOpts
    if len(opts) > 0 {
        opt = opts[0]
    }

    cipher := opt.Cipher
    if cipher == nil {
        return nil, errors.New("pkcs12: unknown opts cipher")
    }

    kdfOpts := opt.KDFOpts
    if kdfOpts == nil {
        return nil, errors.New("pkcs12: unknown opts kdfOpts")
    }

    pkcs8Cipher := opt.PKCS8Cipher
    if pkcs8Cipher == nil {
        return nil, errors.New("pkcs12: unknown opts pkcs8Cipher")
    }

    encodedPassword, err := bmpStringZeroTerminated(password)
    if err != nil {
        return nil, err
    }

    var pfx pfxPdu
    pfx.Version = 3

    var secretFingerprint = sha1.Sum(secretKey)
    var localKeyIdAttr pkcs12Attribute
    localKeyIdAttr.Id = oidLocalKeyID
    localKeyIdAttr.Value.Class = 0
    localKeyIdAttr.Value.Tag = 17
    localKeyIdAttr.Value.IsCompound = true
    if localKeyIdAttr.Value.Bytes, err = asn1.Marshal(secretFingerprint[:]); err != nil {
        return nil, err
    }

    var keyBag safeBag
    keyBag.Id = oidSecretBag
    keyBag.Value.Class = 2
    keyBag.Value.Tag = 0
    keyBag.Value.IsCompound = true
    if keyBag.Value.Bytes, err = encodeSecretBag(rand, secretKey, encodedPassword, opt); err != nil {
        return nil, err
    }
    keyBag.Attributes = append(keyBag.Attributes, localKeyIdAttr)

    var authenticatedSafe [1]contentInfo
    if authenticatedSafe[0], err = makeSafeContents(rand, []safeBag{keyBag}, nil, nil); err != nil {
        return nil, err
    }

    var authenticatedSafeBytes []byte
    if authenticatedSafeBytes, err = asn1.Marshal(authenticatedSafe[:]); err != nil {
        return nil, err
    }

    // compute the MAC
    var kdfMacData KDFParameters
    kdfMacData, err = opt.KDFOpts.Compute(authenticatedSafeBytes, encodedPassword)
    if err != nil {
        return nil, err
    }

    pfx.MacData = kdfMacData.(macData)

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

func makeCertBag(certBytes []byte, attributes []pkcs12Attribute) (certBag *safeBag, err error) {
    certBag = new(safeBag)
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

func makeSafeContents(rand io.Reader, bags []safeBag, password []byte, cipher Cipher) (ci contentInfo, err error) {
    var data []byte
    if data, err = asn1.Marshal(bags); err != nil {
        return
    }

    if password == nil {
        ci.ContentType = oidDataContentType
        ci.Content.Class = 2
        ci.Content.Tag = 0
        ci.Content.IsCompound = true
        if ci.Content.Bytes, err = asn1.Marshal(data); err != nil {
            return
        }
    } else {
        randomSalt := make([]byte, 8)
        if _, err = rand.Read(randomSalt); err != nil {
            return
        }

        var encrypted, params []byte
        encrypted, params, err = cipher.Encrypt(password, data)
        if err != nil {
            return
        }

        var algo pkix.AlgorithmIdentifier
        algo.Algorithm = cipher.OID()
        algo.Parameters.FullBytes = params

        var encryptedData encryptedData
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
