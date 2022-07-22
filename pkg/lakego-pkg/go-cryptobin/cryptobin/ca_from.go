package cryptobin

import (
    "crypto/rsa"
    "crypto/rand"
    "crypto/x509"
)

// 私钥
func (this CA) FromCsr(csr *x509.Certificate) CA {
    this.csr = csr

    return this
}

// 私钥
func (this CA) FromPrivateKey(key *rsa.PrivateKey) CA {
    this.privateKey = key

    return this
}

// 公钥
func (this CA) FromPublicKey(key *rsa.PublicKey) CA {
    this.publicKey = key

    return this
}

// 生成密钥
// bits = 512 | 1024 | 2048 | 4096
func (this CA) GenerateKey(bits int) CA {
    this.privateKey, this.Error = rsa.GenerateKey(rand.Reader, bits)

    return this
}
