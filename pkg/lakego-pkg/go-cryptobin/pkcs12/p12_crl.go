package pkcs12

import (
    "errors"
    "encoding/asn1"
)

type CRLBagData struct {
    Id   asn1.ObjectIdentifier
    Data []byte `asn1:"tag:0,explicit"`
}

type CRLBagEntry struct {}

func NewCRLBagEntry() *CRLBagEntry {
    return &CRLBagEntry{}
}

func (this *CRLBagEntry) DecodeCertBag(asn1Data []byte) (cert []byte, err error) {
    bag := new(CRLBagData)
    if err := unmarshal(asn1Data, bag); err != nil {
        return nil, errors.New("go-cryptobin/pkcs12: error decoding crl bag: " + err.Error())
    }

    if !bag.Id.Equal(oidCertTypeX509CRL) {
        return nil, NotImplementedError("crl: oid is not support")
    }

    return bag.Data, nil
}

func (this *CRLBagEntry) EncodeCertBag(cert []byte) (asn1Data []byte, err error) {
    var bag CRLBagData

    bag.Id = oidCertTypeX509CRL
    bag.Data = cert

    if asn1Data, err = asn1.Marshal(bag); err != nil {
        return nil, errors.New("go-cryptobin/pkcs12: error encoding crl bag: " + err.Error())
    }

    return asn1Data, nil
}

func (this *CRLBagEntry) MakeCertBag(certBytes []byte, attributes []PKCS12Attribute) (certBag *SafeBag, err error) {
    certBag = new(SafeBag)
    certBag.Id = oidCRLBag
    certBag.Value.Class = 2
    certBag.Value.Tag = 0
    certBag.Value.IsCompound = true

    if certBag.Value.Bytes, err = this.EncodeCertBag(certBytes); err != nil {
        return nil, err
    }

    certBag.Attributes = attributes
    return
}
