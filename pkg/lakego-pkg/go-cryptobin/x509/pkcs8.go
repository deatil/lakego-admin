package x509

import (
    "encoding/asn1"
    "crypto/x509/pkix"
)

// pkcs8 attribute info
type pkcs8Attribute struct {
    Id     asn1.ObjectIdentifier
    Values []asn1.RawValue `asn1:"set"`
}

// pkcs8 info
type pkcs8 struct {
    Version    int
    Algo       pkix.AlgorithmIdentifier
    PrivateKey []byte
    Attributes []asn1.RawValue `asn1:"optional,tag:0"`
}

// GetAttributes
func (this *pkcs8) GetAttributes() (attributes []pkcs8Attribute) {
    for _, rawAttr := range this.Attributes {
        var attr pkcs8Attribute
        rest, err := asn1.Unmarshal(rawAttr.FullBytes, &attr)
        if err == nil && len(rest) == 0 {
            attributes = append(attributes, attr)
        }
    }

    return
}

// Pasrse PKCS8 Key
func PasrsePKCS8Key(privateKey []byte) (*pkcs8, error) {
    var privKey pkcs8
    _, err := asn1.Unmarshal(privateKey, &privKey)
    if err != nil {
        return nil, err
    }

    return &privKey, nil
}
