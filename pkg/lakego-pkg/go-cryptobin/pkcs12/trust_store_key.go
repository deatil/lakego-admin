package pkcs12

import "crypto/x509"

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
