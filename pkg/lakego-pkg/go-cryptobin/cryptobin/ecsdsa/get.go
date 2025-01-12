package ecsdsa

import (
    "crypto/elliptic"

    "github.com/deatil/go-cryptobin/tool/encoding"
    "github.com/deatil/go-cryptobin/pubkey/ecsdsa"
)

// get PrivateKey
func (this ECSDSA) GetPrivateKey() *ecsdsa.PrivateKey {
    return this.privateKey
}

// get PrivateKey Curve
func (this ECSDSA) GetPrivateKeyCurve() elliptic.Curve {
    return this.privateKey.Curve
}

// get PrivateKey D hex string
func (this ECSDSA) GetPrivateKeyDString() string {
    data := this.privateKey.D

    return encoding.HexEncode(data.Bytes())
}

// get PrivateKey data hex string
func (this ECSDSA) GetPrivateKeyString() string {
    priv := ecsdsa.PrivateKeyTo(this.privateKey)

    return encoding.HexEncode(priv)
}

// get PublicKey
func (this ECSDSA) GetPublicKey() *ecsdsa.PublicKey {
    return this.publicKey
}

// get PublicKey Curve
func (this ECSDSA) GetPublicKeyCurve() elliptic.Curve {
    return this.publicKey.Curve
}

// get PublicKey X hex string
func (this ECSDSA) GetPublicKeyXString() string {
    x := this.publicKey.X

    return encoding.HexEncode(x.Bytes())
}

// get PublicKey Y hex string
func (this ECSDSA) GetPublicKeyYString() string {
    y := this.publicKey.Y

    return encoding.HexEncode(y.Bytes())
}

// get PublicKey X and Y Hex string
func (this ECSDSA) GetPublicKeyXYString() string {
    key := elliptic.Marshal(this.publicKey.Curve, this.publicKey.X, this.publicKey.Y)

    return encoding.HexEncode(key[1:])
}

// get PublicKey Uncompress Hex string
func (this ECSDSA) GetPublicKeyUncompressString() string {
    key := elliptic.Marshal(this.publicKey.Curve, this.publicKey.X, this.publicKey.Y)

    return encoding.HexEncode(key)
}

// get PublicKey Compress Hex string
func (this ECSDSA) GetPublicKeyCompressString() string {
    key := elliptic.MarshalCompressed(this.publicKey.Curve, this.publicKey.X, this.publicKey.Y)

    return encoding.HexEncode(key)
}

// get Curve
func (this ECSDSA) GetCurve() elliptic.Curve {
    return this.curve
}

// get signHash type
func (this ECSDSA) GetSignHash() HashFunc {
    return this.signHash
}

// get keyData
func (this ECSDSA) GetKeyData() []byte {
    return this.keyData
}

// get data
func (this ECSDSA) GetData() []byte {
    return this.data
}

// get parsedData
func (this ECSDSA) GetParsedData() []byte {
    return this.parsedData
}

// get Encoding type
func (this ECSDSA) GetEncoding() EncodingType {
    return this.encoding
}

// get verify data
func (this ECSDSA) GetVerify() bool {
    return this.verify
}

// get errors
func (this ECSDSA) GetErrors() []error {
    return this.Errors
}
