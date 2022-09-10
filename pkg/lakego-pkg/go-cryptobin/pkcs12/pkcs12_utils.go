package pkcs12

import (
    "fmt"
    "errors"
    "encoding/asn1"
    "crypto/x509/pkix"
)

// unmarshal calls asn1.Unmarshal, but also returns an error if there is any
// trailing data after unmarshaling.
func unmarshal(in []byte, out any) error {
    trailing, err := asn1.Unmarshal(in, out)
    if err != nil {
        return err
    }

    if len(trailing) != 0 {
        return errors.New("pkcs12: trailing data found")
    }

    return nil
}

// 解析加密数据
func parseContentEncryptionAlgorithm(contentEncryptionAlgorithm pkix.AlgorithmIdentifier) (Cipher, []byte, error) {
    oid := contentEncryptionAlgorithm.Algorithm.String()
    cipher, ok := ciphers[oid]
    if !ok {
        return nil, nil, fmt.Errorf("pkcs12: unsupported cipher (OID: %s)", oid)
    }

    newCipher := cipher()

    params := contentEncryptionAlgorithm.Parameters.FullBytes

    return newCipher, params, nil
}
