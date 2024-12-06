package bign

import (
    "crypto/elliptic"

    "github.com/deatil/go-cryptobin/tool/encoding"
    "github.com/deatil/go-cryptobin/pubkey/bign"
)

// get PrivateKey
func (this Bign) GetPrivateKey() *bign.PrivateKey {
    return this.privateKey
}

// get PrivateKey Curve
func (this Bign) GetPrivateKeyCurve() elliptic.Curve {
    return this.privateKey.Curve
}

// get PrivateKey D hex string
func (this Bign) GetPrivateKeyDString() string {
    data := this.privateKey.D

    return encoding.HexEncode(data.Bytes())
}

// get PrivateKey data hex string
func (this Bign) GetPrivateKeyString() string {
    priv := bign.PrivateKeyTo(this.privateKey)

    return encoding.HexEncode(priv)
}

// get PublicKey
func (this Bign) GetPublicKey() *bign.PublicKey {
    return this.publicKey
}

// get PublicKey Curve
func (this Bign) GetPublicKeyCurve() elliptic.Curve {
    return this.publicKey.Curve
}

// get PublicKey X hex string
func (this Bign) GetPublicKeyXString() string {
    x := this.publicKey.X

    return encoding.HexEncode(x.Bytes())
}

// get PublicKey Y hex string
func (this Bign) GetPublicKeyYString() string {
    y := this.publicKey.Y

    return encoding.HexEncode(y.Bytes())
}

// get PublicKey X and Y Hex string
func (this Bign) GetPublicKeyXYString() string {
    key := elliptic.Marshal(this.publicKey.Curve, this.publicKey.X, this.publicKey.Y)

    return encoding.HexEncode(key[1:])
}

// get PublicKey Uncompress Hex string
func (this Bign) GetPublicKeyUncompressString() string {
    key := elliptic.Marshal(this.publicKey.Curve, this.publicKey.X, this.publicKey.Y)

    return encoding.HexEncode(key)
}

// get PublicKey Compress Hex string
func (this Bign) GetPublicKeyCompressString() string {
    key := elliptic.MarshalCompressed(this.publicKey.Curve, this.publicKey.X, this.publicKey.Y)

    return encoding.HexEncode(key)
}

// get Curve
func (this Bign) GetCurve() elliptic.Curve {
    return this.curve
}

// get signHash type
func (this Bign) GetSignHash() HashFunc {
    return this.signHash
}

// get keyData
func (this Bign) GetKeyData() []byte {
    return this.keyData
}

// get data
func (this Bign) GetData() []byte {
    return this.data
}

// get adata
func (this Bign) GetAdata() []byte {
    return this.adata
}

// get parsedData
func (this Bign) GetParsedData() []byte {
    return this.parsedData
}

// get Encoding type
func (this Bign) GetEncoding() EncodingType {
    return this.encoding
}

// get verify data
func (this Bign) GetVerify() bool {
    return this.verify
}

// get errors
func (this Bign) GetErrors() []error {
    return this.Errors
}
