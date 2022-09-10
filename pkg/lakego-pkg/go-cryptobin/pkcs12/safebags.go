package pkcs12

import (
    "io"
    "errors"
    "encoding/pem"
    "encoding/asn1"

    cryptobin_pkcs8 "github.com/deatil/go-cryptobin/pkcs8"
    cryptobin_pkcs8pbe "github.com/deatil/go-cryptobin/pkcs8pbe"
)

var (
    // see https://tools.ietf.org/html/rfc7292#appendix-D
    oidCertTypeX509Certificate = asn1.ObjectIdentifier([]int{1, 2, 840, 113549, 1, 9, 22, 1})
    oidPKCS8ShroundedKeyBag    = asn1.ObjectIdentifier([]int{1, 2, 840, 113549, 1, 12, 10, 1, 2})
    oidCertBag                 = asn1.ObjectIdentifier([]int{1, 2, 840, 113549, 1, 12, 10, 1, 3})
    oidSecretKeyBag            = asn1.ObjectIdentifier([]int{1, 2, 840, 113549, 1, 12, 10, 1, 5})
)

type certBag struct {
    Id   asn1.ObjectIdentifier
    Data []byte `asn1:"tag:0,explicit"`
}

func decodePkcs8ShroudedKeyBag(asn1Data, password []byte) (privateKey any, err error) {
    var pkData []byte

    pkData, err = cryptobin_pkcs8pbe.DecryptPKCS8PrivateKey(asn1Data, password)
    if err != nil {
        pkData, err = cryptobin_pkcs8.DecryptPKCS8PrivateKey(asn1Data, password)
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

    if opt.PKCS8KDFOpts != nil {
        keyBlock, err = cryptobin_pkcs8.EncryptPKCS8PrivateKey(rand, "KEY", pkData, password, cryptobin_pkcs8.Opts{
            opt.PKCS8Cipher,
            opt.PKCS8KDFOpts,
        })
    } else {
        keyBlock, err = cryptobin_pkcs8pbe.EncryptPKCS8PrivateKey(rand, "KEY", pkData, password, opt.PKCS8Cipher)
    }

    asn1Data = keyBlock.Bytes

    return asn1Data, nil
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
