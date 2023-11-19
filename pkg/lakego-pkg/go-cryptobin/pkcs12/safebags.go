package pkcs12

import (
    "io"
    "errors"
    "encoding/pem"
    "encoding/asn1"

    pkcs8_pbes1 "github.com/deatil/go-cryptobin/pkcs8/pbes1"
    pkcs8_pbes2 "github.com/deatil/go-cryptobin/pkcs8/pbes2"
)

func decodePkcs8ShroudedKeyBag(asn1Data, password []byte) (privateKey any, err error) {
    var pkData []byte

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

    if privateKey, err = ParsePKCS8PrivateKey(pkData); err != nil {
        return nil, err
    }

    return privateKey, nil
}

func encodePkcs8ShroudedKeyBag(
    rand io.Reader,
    privateKey any,
    password []byte,
    opt Opts,
) (asn1Data []byte, err error) {
    var pkData []byte
    if pkData, err = MarshalPKCS8PrivateKey(privateKey); err != nil {
        return nil, err
    }

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

// ============

type certBag struct {
    Id   asn1.ObjectIdentifier
    Data []byte `asn1:"tag:0,explicit"`
}

func decodeCertBag(asn1Data []byte) (x509Certificates []byte, err error) {
    bag := new(certBag)
    if err := unmarshal(asn1Data, bag); err != nil {
        return nil, errors.New("pkcs12: error decoding cert bag: " + err.Error())
    }

    if !bag.Id.Equal(oidCertTypeX509Certificate) {
        return nil, NotImplementedError("only X509 certificates are supported")
    }

    return bag.Data, nil
}

func encodeCertBag(x509Certificates []byte) (asn1Data []byte, err error) {
    var bag certBag

    bag.Id = oidCertTypeX509Certificate
    bag.Data = x509Certificates

    if asn1Data, err = asn1.Marshal(bag); err != nil {
        return nil, errors.New("pkcs12: error encoding cert bag: " + err.Error())
    }

    return asn1Data, nil
}
