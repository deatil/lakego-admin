package pkcs12

import (
    "io"
    "errors"
    "crypto"
    "crypto/x509"
    "encoding/pem"
)

type TrustStoreKey interface {
    // Attributes return the PKCS12AttrSet of the safe bag
    // https://tools.ietf.org/html/rfc7292#section-4.2
    Attributes() map[string]string
    // Cert
    Cert() *x509.Certificate
    // FriendlyName return the value of `friendlyName`
    // attribute if exists, otherwise it will return empty string
    FriendlyName() string
}

type trustStoreKey struct {
    attrs map[string]string
    cert  *x509.Certificate
}

func (this trustStoreKey) Attributes() map[string]string {
    return this.attrs
}

func (this trustStoreKey) Cert() *x509.Certificate {
    return this.cert
}

func (this trustStoreKey) FriendlyName() string {
    return this.attrs["friendlyName"]
}

// ToPEM converts all "safe bags" contained in pfxData to PEM blocks.
func ToPEM(pfxData []byte, password string) ([]*pem.Block, error) {
    p12, err := LoadFromBytes(pfxData, password)
    if err != nil {
        return nil, err
    }

    return p12.ToPEM()
}

// Decode extracts a certificate and private key from pfxData, which must be a DER-encoded PKCS#12 file.
func Decode(pfxData []byte, password string) (
    privateKey crypto.PrivateKey,
    certificate *x509.Certificate,
    err error,
) {
    var caCerts []*x509.Certificate

    privateKey, certificate, caCerts, err = DecodeChain(pfxData, password)
    if len(caCerts) != 0 {
        err = errors.New("go-cryptobin/pkcs12: expected exactly two safe bags in the PFX PDU")
    }

    return
}

// DecodeChain extracts a certificate, a CA certificate chain, and private key
// from pfxData, which must be a DER-encoded PKCS#12 file.
func DecodeChain(pfxData []byte, password string) (
    privateKey crypto.PrivateKey,
    certificate *x509.Certificate,
    caCerts []*x509.Certificate,
    err error,
) {
    p12, err := LoadFromBytes(pfxData, password)
    if err != nil {
        return
    }

    privateKey, _, err = p12.GetPrivateKey()
    if err != nil {
        return nil, nil, nil, errors.New("go-cryptobin/pkcs12: private key missing")
    }

    certificate, _, err = p12.GetCert()
    if err != nil {
        return nil, nil, nil, errors.New("go-cryptobin/pkcs12: certificate missing")
    }

    caCerts, _ = p12.GetCaCerts()

    return
}

// DecodeTrustStore extracts the certificates from pfxData, which must be a DER-encoded
func DecodeTrustStore(pfxData []byte, password string) (certs []*x509.Certificate, err error) {
    p12, err := LoadFromBytes(pfxData, password)
    if err != nil {
        return nil, err
    }

    return p12.GetTrustStores()
}

// DecodeTrustStoreEntries extracts the certificates from pfxData, which must be a DER-encoded
func DecodeTrustStoreEntries(pfxData []byte, password string) (trustStoreKeys []TrustStoreKey, err error) {
    p12, err := LoadFromBytes(pfxData, password)
    if err != nil {
        return nil, err
    }

    certs, err := p12.GetTrustStoreEntries()
    if err != nil {
        return nil, err
    }

    for _, cert := range certs {
        trustkey := new(trustStoreKey)
        trustkey.cert = cert.Cert
        trustkey.attrs = cert.Attrs.ToArray()

        trustStoreKeys = append(trustStoreKeys, trustkey)
    }

    return
}

// DecodeSecret extracts the Secret key from pfxData, which must be a DER-encoded
func DecodeSecret(pfxData []byte, password string) (secretKey []byte, err error) {
    p12, err := LoadFromBytes(pfxData, password)
    if err != nil {
        return nil, err
    }

    secretKey, _, err = p12.GetSecretKey()

    return
}

// for go
func Encode(
    rand io.Reader,
    privateKey crypto.PrivateKey,
    certificate *x509.Certificate,
    password string,
    opts ...Opts,
) (pfxData []byte, err error) {
    return EncodeChain(rand, privateKey, certificate, nil, password, opts...)
}

// EncodeChain produces pfxData containing one private key (privateKey), an
// end-entity certificate (certificate), and any number of CA certificates
// (caCerts).
func EncodeChain(
    rand io.Reader,
    privateKey crypto.PrivateKey,
    certificate *x509.Certificate,
    caCerts []*x509.Certificate,
    password string,
    opts ...Opts,
) (pfxData []byte, err error) {
    p12 := NewPKCS12()

    err = p12.AddPrivateKey(privateKey)
    if err != nil {
        return
    }

    p12.AddCert(certificate)
    p12.AddCaCerts(caCerts)

    pfxData, err = p12.Marshal(rand, password, opts...)

    return
}

// EncodeTrustStore produces pfxData containing any number of CA certificates
// (certs) to be trusted. The certificates will be marked with a special OID that
// allow it to be used as a Java TrustStore in Java 1.8 and newer.
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
func EncodeTrustStoreEntries(
    rand io.Reader,
    entries []TrustStoreEntry,
    password string,
    opts ...Opts,
) (pfxData []byte, err error) {
    p12 := NewPKCS12()

    for _, entry := range entries {
        p12.AddTrustStoreEntry(entry.Cert, entry.FriendlyName)
    }

    pfxData, err = p12.Marshal(rand, password, opts...)

    return
}

// Encode Secret with der
func EncodeSecret(rand io.Reader, secretKey []byte, password string, opts ...Opts) (pfxData []byte, err error) {
    pkcs12 := NewPKCS12()
    pkcs12.AddSecretKey(secretKey)

    pfxData, err = pkcs12.Marshal(rand, password, opts...)
    if err != nil {
        return nil, err
    }

    return pfxData, nil
}
