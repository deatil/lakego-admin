package encrypt

import (
    "fmt"
    "errors"
    "bytes"
    "crypto"
    "crypto/x509"
    "crypto/x509/pkix"
    "encoding/asn1"

    pkcs7_ber "github.com/deatil/go-cryptobin/pkcs7/ber"
)

// 解析
func Decrypt(data []byte, cert *x509.Certificate, pkey crypto.PrivateKey) ([]byte, error) {
    info, contentType, err := parseData(data)
    if err != nil {
        return nil, err
    }

    if !contentType.Equal(oidEnvelopedData) {
        return nil, errors.New("pkcs7: contentType error")
    }

    var endata envelopedData
    if _, err := asn1.Unmarshal(info, &endata); err != nil {
        return nil, err
    }

    recipient := selectRecipientForCertificate(endata.RecipientInfos, cert)
    if recipient.EncryptedKey == nil {
        return nil, errors.New("pkcs7: no enveloped recipient for provided certificate")
    }

    keyEncrypt, err := parseKeyEncrypt(recipient.KeyEncryptionAlgorithm)
    if err != nil {
        return nil, err
    }

    contentKey, err := keyEncrypt.Decrypt(recipient.EncryptedKey, pkey)
    if err != nil {
        return nil, err
    }

    return encryptedContentInfoDecrypt(endata.EncryptedContentInfo, contentKey)
}

// DecryptUsingPSK decrypts encrypted data using caller provided
// pre-shared secret
func DecryptUsingPSK(data []byte, key []byte) ([]byte, error) {
    info, contentType, err := parseData(data)
    if err != nil {
        return nil, err
    }

    if !contentType.Equal(oidEncryptedData) {
        return nil, errors.New("pkcs7: contentType error")
    }

    var endata encryptedData
    if _, err := asn1.Unmarshal(info, &endata); err != nil {
        return nil, err
    }

    return encryptedContentInfoDecrypt(endata.EncryptedContentInfo, key)
}

func encryptedContentInfoDecrypt(eci encryptedContentInfo, key []byte) ([]byte, error) {
    // EncryptedContent can either be constructed of multple OCTET STRINGs
    // or _be_ a tagged OCTET STRING
    var cyphertext []byte
    if eci.EncryptedContent.IsCompound {
        // Complex case to concat all of the children OCTET STRINGs
        var buf bytes.Buffer
        cypherbytes := eci.EncryptedContent.Bytes
        for {
            var part []byte
            cypherbytes, _ = asn1.Unmarshal(cypherbytes, &part)
            buf.Write(part)
            if cypherbytes == nil {
                break
            }
        }
        cyphertext = buf.Bytes()
    } else {
        // Simple case, the bytes _are_ the cyphertext
        cyphertext = eci.EncryptedContent.Bytes
    }

    cipher, cipherParams, err := parseEncryptionScheme(eci.ContentEncryptionAlgorithm)
    if err != nil {
        return nil, err
    }

    decryptedKey, err := cipher.Decrypt(key, cipherParams, cyphertext)
    if err != nil {
        return nil, err
    }

    return decryptedKey, nil
}

func parseKeyEncrypt(keyEncrypt pkix.AlgorithmIdentifier) (KeyEncrypt, error) {
    oid := keyEncrypt.Algorithm.String()
    fn, ok := keyens[oid]
    if !ok {
        return nil, fmt.Errorf("pkcs7: unsupported KDF (OID: %s)", oid)
    }

    newFunc := fn()

    return newFunc, nil
}

func parseEncryptionScheme(encryptionScheme pkix.AlgorithmIdentifier) (Cipher, []byte, error) {
    oid := encryptionScheme.Algorithm.String()
    cipher, ok := ciphers[oid]
    if !ok {
        return nil, nil, fmt.Errorf("pkcs7: unsupported cipher (OID: %s)", oid)
    }

    newCipher := cipher()

    params := encryptionScheme.Parameters.FullBytes

    return newCipher, params, nil
}

// Parse decodes a DER encoded PKCS7 package
func parseData(data []byte) ([]byte, asn1.ObjectIdentifier, error) {
    if len(data) == 0 {
        return nil, asn1.ObjectIdentifier{}, errors.New("pkcs7: input data is empty")
    }

    der, err := pkcs7_ber.Ber2der(data)
    if err != nil {
        return nil, asn1.ObjectIdentifier{}, err
    }

    var info contentInfo
    rest, err := asn1.Unmarshal(der, &info)
    if len(rest) > 0 {
        err = asn1.SyntaxError{Msg: "trailing data"}
        return nil, asn1.ObjectIdentifier{}, err
    }

    content := info.Content.Bytes
    contentType := info.ContentType

    return content, contentType, nil
}

func selectRecipientForCertificate(recipients []recipientInfo, cert *x509.Certificate) recipientInfo {
    for _, recp := range recipients {
        if isCertMatchForIssuerAndSerial(cert, recp.IssuerAndSerialNumber) {
            return recp
        }
    }

    return recipientInfo{}
}

func isCertMatchForIssuerAndSerial(cert *x509.Certificate, ias issuerAndSerial) bool {
    return cert.SerialNumber.Cmp(ias.SerialNumber) == 0 && bytes.Equal(cert.RawIssuer, ias.IssuerName.FullBytes)
}
