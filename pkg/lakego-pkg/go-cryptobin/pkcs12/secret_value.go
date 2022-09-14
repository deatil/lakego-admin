package pkcs12

import (
    "crypto/x509/pkix"
)

type secretValue struct {
    AlgorithmIdentifier pkix.AlgorithmIdentifier
    EncryptedContent    []byte
}

func (this secretValue) Algorithm() pkix.AlgorithmIdentifier {
    return this.AlgorithmIdentifier
}

func (this secretValue) Data() []byte {
    return this.EncryptedContent
}

