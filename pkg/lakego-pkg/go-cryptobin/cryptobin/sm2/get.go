package sm2

import (
    "crypto/elliptic"

    "github.com/deatil/go-cryptobin/gm/sm2"
    "github.com/deatil/go-cryptobin/tool/encoding"
)

// get PrivateKey
func (this SM2) GetPrivateKey() *sm2.PrivateKey {
    return this.privateKey
}

// get PrivateKey Curve
func (this SM2) GetPrivateKeyCurve() elliptic.Curve {
    return this.privateKey.Curve
}

// get PrivateKey D hex string
func (this SM2) GetPrivateKeyDString() string {
    data := this.privateKey.D

    return encoding.HexEncode(data.Bytes())
}

// get PrivateKey data hex string
func (this SM2) GetPrivateKeyString() string {
    return this.GetPrivateKeyDString()
}

// get PublicKey
func (this SM2) GetPublicKey() *sm2.PublicKey {
    return this.publicKey
}

// get PublicKey Curve
func (this SM2) GetPublicKeyCurve() elliptic.Curve {
    return this.publicKey.Curve
}

// get PublicKey X hex string
func (this SM2) GetPublicKeyXString() string {
    x := this.publicKey.X

    return encoding.HexEncode(x.Bytes())
}

// get PublicKey Y hex string
func (this SM2) GetPublicKeyYString() string {
    y := this.publicKey.Y

    return encoding.HexEncode(y.Bytes())
}

// get PublicKey X and Y Hex string
func (this SM2) GetPublicKeyXYString() string {
    data := sm2.PublicKeyTo(this.publicKey)

    return encoding.HexEncode(data[1:])
}

// get PublicKey Uncompress Hex string
func (this SM2) GetPublicKeyUncompressString() string {
    data := sm2.PublicKeyTo(this.publicKey)

    return encoding.HexEncode(data)
}

// get PublicKey Compress Hex string
func (this SM2) GetPublicKeyCompressString() string {
    data := sm2.Compress(this.publicKey)

    return encoding.HexEncode(data)
}

// get key Data
func (this SM2) GetKeyData() []byte {
    return this.keyData
}

// get mode
func (this SM2) GetMode() sm2.Mode {
    return this.mode
}

// get data
func (this SM2) GetData() []byte {
    return this.data
}

// get parsedData
func (this SM2) GetParsedData() []byte {
    return this.parsedData
}

// get uid
func (this SM2) GetUID() []byte {
    return this.uid
}

// get Encoding type
func (this SM2) GetEncoding() EncodingType {
    return this.encoding
}

// get verify data
func (this SM2) GetVerify() bool {
    return this.verify
}

// get errors
func (this SM2) GetErrors() []error {
    return this.Errors
}
