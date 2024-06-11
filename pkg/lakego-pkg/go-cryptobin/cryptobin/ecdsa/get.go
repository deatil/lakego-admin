package ecdsa

import (
    "crypto/ecdsa"
    "crypto/elliptic"

    "github.com/deatil/go-cryptobin/tool"
)

// get PrivateKey
func (this ECDSA) GetPrivateKey() *ecdsa.PrivateKey {
    return this.privateKey
}

// get PrivateKey Curve
func (this ECDSA) GetPrivateKeyCurve() elliptic.Curve {
    return this.privateKey.Curve
}

// get PrivateKey D hex string
func (this ECDSA) GetPrivateKeyDString() string {
    data := this.privateKey.D

    dataHex := tool.HexEncode(data.Bytes())

    return dataHex
}

// get PrivateKey data hex string
func (this ECDSA) GetPrivateKeyString() string {
    return this.GetPrivateKeyDString()
}

// get PublicKey
func (this ECDSA) GetPublicKey() *ecdsa.PublicKey {
    return this.publicKey
}

// get PublicKey Curve
func (this ECDSA) GetPublicKeyCurve() elliptic.Curve {
    return this.publicKey.Curve
}

// get PublicKey X hex string
func (this ECDSA) GetPublicKeyXString() string {
    data := this.publicKey.X

    dataHex := tool.HexEncode(data.Bytes())

    return dataHex
}

// get PublicKey Y hex string
func (this ECDSA) GetPublicKeyYString() string {
    data := this.publicKey.Y

    dataHex := tool.HexEncode(data.Bytes())

    return dataHex
}

// get PublicKey X and Y Hex string
func (this ECDSA) GetPublicKeyXYString() string {
    dataHex := this.GetPublicKeyXString() + this.GetPublicKeyYString()

    return dataHex
}

// get PublicKey Uncompress Hex string
func (this ECDSA) GetPublicKeyUncompressString() string {
    key := elliptic.Marshal(this.publicKey.Curve, this.publicKey.X, this.publicKey.Y)

    return tool.HexEncode(key)
}

// get PublicKey Compress Hex string
func (this ECDSA) GetPublicKeyCompressString() string {
    key := elliptic.MarshalCompressed(this.publicKey.Curve, this.publicKey.X, this.publicKey.Y)

    return tool.HexEncode(key)
}

// get Curve
func (this ECDSA) GetCurve() elliptic.Curve {
    return this.curve
}

// get signHash type
func (this ECDSA) GetSignHash() HashFunc {
    return this.signHash
}

// get keyData
func (this ECDSA) GetKeyData() []byte {
    return this.keyData
}

// get data
func (this ECDSA) GetData() []byte {
    return this.data
}

// get parsedData
func (this ECDSA) GetParsedData() []byte {
    return this.parsedData
}

// get verify data
func (this ECDSA) GetVerify() bool {
    return this.verify
}

// get errors
func (this ECDSA) GetErrors() []error {
    return this.Errors
}
