package pkcs12

import (
    "fmt"
    "errors"
    "encoding/asn1"
    "crypto/x509/pkix"

    "github.com/deatil/go-cryptobin/pkcs8/pbes1"
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

    newCipher, err := pbes1.GetCipher(oid)
    if err != nil {
        return nil, nil, fmt.Errorf("pkcs8: unsupported cipher (OID: %s)", oid)
    }

    params := contentEncryptionAlgorithm.Parameters.FullBytes

    return newCipher, params, nil
}
