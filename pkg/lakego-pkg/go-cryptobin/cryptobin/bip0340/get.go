package bip0340

import (
    "crypto/elliptic"

    "github.com/deatil/go-cryptobin/tool/encoding"
    "github.com/deatil/go-cryptobin/pubkey/bip0340"
)

// get PrivateKey
func (this BIP0340) GetPrivateKey() *bip0340.PrivateKey {
    return this.privateKey
}

// get PrivateKey Curve
func (this BIP0340) GetPrivateKeyCurve() elliptic.Curve {
    return this.privateKey.Curve
}

// get PrivateKey D hex string
func (this BIP0340) GetPrivateKeyDString() string {
    data := this.privateKey.D

    return encoding.HexEncode(data.Bytes())
}

// get PrivateKey data hex string
func (this BIP0340) GetPrivateKeyString() string {
    priv := bip0340.PrivateKeyTo(this.privateKey)

    return encoding.HexEncode(priv)
}

// get PublicKey
func (this BIP0340) GetPublicKey() *bip0340.PublicKey {
    return this.publicKey
}

// get PublicKey Curve
func (this BIP0340) GetPublicKeyCurve() elliptic.Curve {
    return this.publicKey.Curve
}

// get PublicKey X hex string
func (this BIP0340) GetPublicKeyXString() string {
    x := this.publicKey.X

    return encoding.HexEncode(x.Bytes())
}

// get PublicKey Y hex string
func (this BIP0340) GetPublicKeyYString() string {
    y := this.publicKey.Y

    return encoding.HexEncode(y.Bytes())
}

// get PublicKey X and Y Hex string
func (this BIP0340) GetPublicKeyXYString() string {
    key := elliptic.Marshal(this.publicKey.Curve, this.publicKey.X, this.publicKey.Y)

    return encoding.HexEncode(key[1:])
}

// get PublicKey Uncompress Hex string
func (this BIP0340) GetPublicKeyUncompressString() string {
    key := elliptic.Marshal(this.publicKey.Curve, this.publicKey.X, this.publicKey.Y)

    return encoding.HexEncode(key)
}

// get PublicKey Compress Hex string
func (this BIP0340) GetPublicKeyCompressString() string {
    key := elliptic.MarshalCompressed(this.publicKey.Curve, this.publicKey.X, this.publicKey.Y)

    return encoding.HexEncode(key)
}

// get Curve
func (this BIP0340) GetCurve() elliptic.Curve {
    return this.curve
}

// get signHash type
func (this BIP0340) GetSignHash() HashFunc {
    return this.signHash
}

// get keyData
func (this BIP0340) GetKeyData() []byte {
    return this.keyData
}

// get data
func (this BIP0340) GetData() []byte {
    return this.data
}

// get parsedData
func (this BIP0340) GetParsedData() []byte {
    return this.parsedData
}

// get Encoding type
func (this BIP0340) GetEncoding() EncodingType {
    return this.encoding
}

// get verify data
func (this BIP0340) GetVerify() bool {
    return this.verify
}

// get errors
func (this BIP0340) GetErrors() []error {
    return this.Errors
}
