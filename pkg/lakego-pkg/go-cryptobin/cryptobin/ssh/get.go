package ecgdsa

import (
    "crypto"
    "crypto/dsa"
    "crypto/elliptic"

    "golang.org/x/crypto/ssh"
)

// get PrivateKey
func (this SSH) GetPrivateKey() crypto.PrivateKey {
    return this.privateKey
}

// get PublicKey
func (this SSH) GetPublicKey() crypto.PublicKey {
    return this.publicKey
}

// get openssh PublicKey
func (this SSH) GetOpensshPublicKey() (ssh.PublicKey, error) {
    return ssh.NewPublicKey(this.publicKey)
}

// get Options
func (this SSH) GetOptions() Options {
    return this.options
}

// get Options Comment
func (this SSH) GetComment() string {
    return this.options.Comment
}

// get DSA ParameterSizes
func (this SSH) GetParameterSizes() dsa.ParameterSizes {
    return this.options.ParameterSizes
}

// get Options Curve
func (this SSH) GetCurve() elliptic.Curve {
    return this.options.Curve
}

// get Options Bits
func (this SSH) GetBits() int {
    return this.options.Bits
}

// get keyData
func (this SSH) GetKeyData() []byte {
    return this.keyData
}

// get data
func (this SSH) GetData() []byte {
    return this.data
}

// get parsedData
func (this SSH) GetParsedData() []byte {
    return this.parsedData
}

// get verify data
func (this SSH) GetVerify() bool {
    return this.verify
}

// get errors
func (this SSH) GetErrors() []error {
    return this.Errors
}
