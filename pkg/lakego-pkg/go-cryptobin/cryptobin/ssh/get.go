package ssh

import (
    "crypto"
    "crypto/rsa"
    "crypto/dsa"
    "crypto/ecdsa"
    "crypto/ed25519"
    "crypto/elliptic"

    "golang.org/x/crypto/ssh"

    "github.com/deatil/go-cryptobin/gm/sm2"
    cryptobin_ssh "github.com/deatil/go-cryptobin/ssh"
)

// get PrivateKey
func (this SSH) GetPrivateKey() crypto.PrivateKey {
    return this.privateKey
}

// get PrivateKey Type
func (this SSH) GetPrivateKeyType() PublicKeyType {
    switch this.privateKey.(type) {
        case *rsa.PrivateKey:
            return KeyTypeRSA
        case *dsa.PrivateKey:
            return KeyTypeDSA
        case *ecdsa.PrivateKey:
            return KeyTypeECDSA
        case ed25519.PrivateKey:
            return KeyTypeEdDSA
        case *sm2.PrivateKey:
            return KeyTypeSM2
    }

    return KeyTypeUnknown
}

// get openssh Signer
func (this SSH) GetOpenSSHSigner() (ssh.Signer, error) {
    return cryptobin_ssh.NewSignerFromKey(this.privateKey)
}

// get PublicKey
func (this SSH) GetPublicKey() crypto.PublicKey {
    return this.publicKey
}

// get PublicKey Type
func (this SSH) GetPublicKeyType() PublicKeyType {
    switch this.publicKey.(type) {
        case *rsa.PublicKey:
            return KeyTypeRSA
        case *dsa.PublicKey:
            return KeyTypeDSA
        case *ecdsa.PublicKey:
            return KeyTypeECDSA
        case ed25519.PublicKey:
            return KeyTypeEdDSA
        case *sm2.PublicKey:
            return KeyTypeSM2
    }

    return KeyTypeUnknown
}

// get openssh PublicKey
func (this SSH) GetOpenSSHPublicKey() (ssh.PublicKey, error) {
    return cryptobin_ssh.NewPublicKey(this.publicKey)
}

// get Options
func (this SSH) GetOptions() Options {
    return this.options
}

// get Options CipherName
func (this SSH) GetCipherName() string {
    return this.options.CipherName
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
