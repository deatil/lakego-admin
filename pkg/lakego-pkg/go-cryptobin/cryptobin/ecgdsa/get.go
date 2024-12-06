package ecgdsa

import (
    "crypto/elliptic"

    "github.com/deatil/go-cryptobin/tool/encoding"
    "github.com/deatil/go-cryptobin/pubkey/ecgdsa"
)

// get PrivateKey
func (this ECGDSA) GetPrivateKey() *ecgdsa.PrivateKey {
    return this.privateKey
}

// get PrivateKey Curve
func (this ECGDSA) GetPrivateKeyCurve() elliptic.Curve {
    return this.privateKey.Curve
}

// get PrivateKey D hex string
func (this ECGDSA) GetPrivateKeyDString() string {
    data := this.privateKey.D

    return encoding.HexEncode(data.Bytes())
}

// get PrivateKey data hex string
func (this ECGDSA) GetPrivateKeyString() string {
    priv := ecgdsa.PrivateKeyTo(this.privateKey)

    return encoding.HexEncode(priv)
}

// get PublicKey
func (this ECGDSA) GetPublicKey() *ecgdsa.PublicKey {
    return this.publicKey
}

// get PublicKey Curve
func (this ECGDSA) GetPublicKeyCurve() elliptic.Curve {
    return this.publicKey.Curve
}

// get PublicKey X hex string
func (this ECGDSA) GetPublicKeyXString() string {
    x := this.publicKey.X

    return encoding.HexEncode(x.Bytes())
}

// get PublicKey Y hex string
func (this ECGDSA) GetPublicKeyYString() string {
    y := this.publicKey.Y

    return encoding.HexEncode(y.Bytes())
}

// get PublicKey X and Y Hex string
func (this ECGDSA) GetPublicKeyXYString() string {
    key := elliptic.Marshal(this.publicKey.Curve, this.publicKey.X, this.publicKey.Y)

    return encoding.HexEncode(key[1:])
}

// get PublicKey Uncompress Hex string
func (this ECGDSA) GetPublicKeyUncompressString() string {
    key := elliptic.Marshal(this.publicKey.Curve, this.publicKey.X, this.publicKey.Y)

    return encoding.HexEncode(key)
}

// get PublicKey Compress Hex string
func (this ECGDSA) GetPublicKeyCompressString() string {
    key := elliptic.MarshalCompressed(this.publicKey.Curve, this.publicKey.X, this.publicKey.Y)

    return encoding.HexEncode(key)
}

// get Curve
func (this ECGDSA) GetCurve() elliptic.Curve {
    return this.curve
}

// get signHash type
func (this ECGDSA) GetSignHash() HashFunc {
    return this.signHash
}

// get keyData
func (this ECGDSA) GetKeyData() []byte {
    return this.keyData
}

// get data
func (this ECGDSA) GetData() []byte {
    return this.data
}

// get parsedData
func (this ECGDSA) GetParsedData() []byte {
    return this.parsedData
}

// get Encoding type
func (this ECGDSA) GetEncoding() EncodingType {
    return this.encoding
}

// get verify data
func (this ECGDSA) GetVerify() bool {
    return this.verify
}

// get errors
func (this ECGDSA) GetErrors() []error {
    return this.Errors
}
