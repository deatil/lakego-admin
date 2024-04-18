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

// GetAttribute
func (this *pkcs8) GetAttribute(id asn1.ObjectIdentifier) (pa pkcs8Attribute) {
    attrs := this.GetAttributes()

    for _, attr := range attrs {
        if attr.Id.Equal(id) {
            return attr
        }
    }

    return
}

// UpdateVersion
func (this *pkcs8) UpdateVersion(ver int) {
    this.Version = ver
}

// UpdateAlgo
func (this *pkcs8) UpdateAlgo(algo pkix.AlgorithmIdentifier) {
    this.Algo = algo
}

// UpdatePrivateKey
func (this *pkcs8) UpdatePrivateKey(privateKey []byte) {
    this.PrivateKey = privateKey
}

// UpdateAttributes
func (this *pkcs8) UpdateAttributes(attrs []asn1.RawValue) {
    this.Attributes = attrs
}

// AddAttribute
func (this *pkcs8) AddAttribute(attr asn1.RawValue) {
    this.Attributes = append(this.Attributes, attr)
}

// AddAttr
func (this *pkcs8) AddAttr(id asn1.ObjectIdentifier, attrs []asn1.RawValue) error {
    newAttr, err := asn1.Marshal(pkcs8Attribute{
        Id: id,
        Values: attrs,
    })
    if err != nil {
        return err
    }

    this.Attributes = append(this.Attributes, asn1.RawValue{
        FullBytes: newAttr,
    })

    return nil
}

// UpdateAttr
func (this *pkcs8) UpdateAttr(id asn1.ObjectIdentifier, attrs []asn1.RawValue) error {
    newAttr, err := asn1.Marshal(pkcs8Attribute{
        Id: id,
        Values: attrs,
    })
    if err != nil {
        return err
    }

    attributes := this.GetAttributes()

    for k, attr := range attributes {
        if attr.Id.Equal(id) {
            this.Attributes[k] = asn1.RawValue{
                FullBytes: newAttr,
            }
        }
    }

    return nil
}

// DeleteAttr
func (this *pkcs8) DeleteAttr(id asn1.ObjectIdentifier) {
    newAttrs := make([]asn1.RawValue, 0)

    for _, rawAttr := range this.Attributes {
        var attr pkcs8Attribute
        rest, err := asn1.Unmarshal(rawAttr.FullBytes, &attr)
        if err == nil && len(rest) == 0 {
            if !attr.Id.Equal(id) {
                newAttrs = append(newAttrs, rawAttr)
            }
        }
    }

    this.Attributes = newAttrs
}

// HasAttr
func (this *pkcs8) HasAttr(id asn1.ObjectIdentifier) bool {
    attrs := this.GetAttributes()

    for _, attr := range attrs {
        if attr.Id.Equal(id) {
            return true
        }
    }

    return false
}

// GetAttrCount
func (this *pkcs8) GetAttrCount(id asn1.ObjectIdentifier) int {
    attrs := this.GetAttributes()

    var count int = 0
    for _, attr := range attrs {
        if attr.Id.Equal(id) {
            count++
        }
    }

    return count
}

// Marshal
func (this *pkcs8) Marshal() ([]byte, error) {
    return asn1.Marshal(*this)
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
