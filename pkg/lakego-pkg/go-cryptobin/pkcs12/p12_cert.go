package pkcs12

import (
    "errors"
    "encoding/asn1"
    "encoding/base64"
)

type CertType uint

const (
    CertTypeX509 CertType = 1 + iota
    CertTypeSdsi
)

type CertBagCheckData struct {
    Id   asn1.ObjectIdentifier
    Data asn1.RawValue
}

type CertX509BagData struct {
    Id   asn1.ObjectIdentifier
    Data []byte `asn1:"tag:0,explicit"`
}

type CertSdsiBagData struct {
    Id   asn1.ObjectIdentifier
    Data string `asn1:"ia5"`
}

type CertBagEntry struct {
    Type CertType
}

func NewCertBagEntry() *CertBagEntry {
    return &CertBagEntry{}
}

func (this *CertBagEntry) WithType(typ CertType) *CertBagEntry {
    this.Type = typ

    return this
}

func (this *CertBagEntry) GetType() CertType {
    return this.Type
}

func (this *CertBagEntry) DecodeCertBag(asn1Data []byte) (cert []byte, err error) {
    checkBag := new(CertBagCheckData)
    if err := unmarshal(asn1Data, checkBag); err != nil {
        return nil, errors.New("go-cryptobin/pkcs12: error decoding cert bag: " + err.Error())
    }

    switch {
        case checkBag.Id.Equal(oidCertTypeX509Certificate):
            this.Type = CertTypeX509

            bag := new(CertX509BagData)
            if err := unmarshal(asn1Data, bag); err != nil {
                return nil, errors.New("go-cryptobin/pkcs12: error decoding cert bag: " + err.Error())
            }

            return bag.Data, nil

        case checkBag.Id.Equal(oidCertTypeSdsiCertificate):
            this.Type = CertTypeSdsi

            bag := new(CertSdsiBagData)
            if err := unmarshal(asn1Data, bag); err != nil {
                return nil, errors.New("go-cryptobin/pkcs12: error decoding cert bag: " + err.Error())
            }

            cert, err := base64.StdEncoding.DecodeString(bag.Data)
            if err != nil {
                return nil, errors.New("go-cryptobin/pkcs12: " + err.Error())
            }

            return cert, nil
    }

    return nil, NotImplementedError("only X509 certificates or CRL are supported")
}

func (this *CertBagEntry) EncodeCertBag(cert []byte) (asn1Data []byte, err error) {
    if this.Type == CertTypeSdsi {
        var bag CertSdsiBagData
        bag.Id = oidCertTypeSdsiCertificate
        bag.Data = base64.StdEncoding.EncodeToString(cert)

        if asn1Data, err = asn1.Marshal(bag); err != nil {
            return nil, errors.New("go-cryptobin/pkcs12: error encoding cert bag: " + err.Error())
        }
    } else {
        var bag CertX509BagData
        bag.Id = oidCertTypeX509Certificate
        bag.Data = cert

        if asn1Data, err = asn1.Marshal(bag); err != nil {
            return nil, errors.New("go-cryptobin/pkcs12: error encoding cert bag: " + err.Error())
        }
    }

    return asn1Data, nil
}

func (this *CertBagEntry) MakeCertBag(certBytes []byte, attributes []PKCS12Attribute) (certBag *SafeBag, err error) {
    certBag = new(SafeBag)
    certBag.Id = oidCertBag
    certBag.Value.Class = 2
    certBag.Value.Tag = 0
    certBag.Value.IsCompound = true

    if certBag.Value.Bytes, err = this.EncodeCertBag(certBytes); err != nil {
        return nil, err
    }

    certBag.Attributes = attributes
    return
}
