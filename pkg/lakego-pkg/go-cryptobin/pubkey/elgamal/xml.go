package elgamal

import (
    "errors"
    "math/big"
    "encoding/xml"
    "encoding/base64"
)

// 私钥
type xmlPrivateKey struct {
    XMLName xml.Name `xml:"ElGamalKeyValue"`
    P       string   `xml:"P"`
    G       string   `xml:"G"`
    Q       string   `xml:"Q,omitempty"`
    Y       string   `xml:"Y"`
    X       string   `xml:"X"`
}

// 公钥
type xmlPublicKey struct {
    XMLName xml.Name `xml:"ElGamalKeyValue"`
    P       string   `xml:"P"`
    G       string   `xml:"G"`
    Q       string   `xml:"Q,omitempty"`
    Y       string   `xml:"Y"`
}

var (
    errPublicKeyXMLValue = func(name string) error {
        return errors.New("elgamal xml: public key [" + name + "] value is error")
    }

    errPrivateKeyXMLValue = func(name string) error {
        return errors.New("elgamal xml: private key [" + name + "] value is error")
    }
)

var defaultXMLKey = NewXMLKey()

/**
 * elgamal xml密钥
 *
 * @create 2023-6-16
 * @author deatil
 */
type XMLKey struct {}

// 构造函数
func NewXMLKey() XMLKey {
    return XMLKey{}
}

// 包装公钥
func (this XMLKey) MarshalPublicKey(key *PublicKey) ([]byte, error) {
    // q = (p - 1) / 2
    q := new(big.Int).Set(key.P)
    q.Sub(q, one)
    q.Div(q, two)

    publicKey := xmlPublicKey{
        P: this.bigintToB64(key.P),
        G: this.bigintToB64(key.G),
        Q: this.bigintToB64(q),
        Y: this.bigintToB64(key.Y),
    }

    return xml.MarshalIndent(publicKey, "", "    ")
}

func MarshalXMLPublicKey(key *PublicKey) ([]byte, error) {
    return defaultXMLKey.MarshalPublicKey(key)
}

// 解析公钥
func (this XMLKey) ParsePublicKey(data []byte) (*PublicKey, error) {
    var pub xmlPublicKey
    err := xml.Unmarshal(data, &pub)
    if err != nil {
        return nil, err
    }

    g, err := this.b64ToBigint(pub.G)
    if err != nil {
        return nil, errPublicKeyXMLValue("G")
    }

    p, err := this.b64ToBigint(pub.P)
    if err != nil {
        return nil, errPublicKeyXMLValue("P")
    }

    y, err := this.b64ToBigint(pub.Y)
    if err != nil {
        return nil, errPublicKeyXMLValue("Y")
    }

    if g.Sign() <= 0 || p.Sign() <= 0 || y.Sign() <= 0 {
        return nil, errors.New("elgamal xml: public key contains zero or negative value")
    }

    publicKey := &PublicKey{
        G: g,
        P: p,
        Y: y,
    }

    return publicKey, nil
}

func ParseXMLPublicKey(der []byte) (*PublicKey, error) {
    return defaultXMLKey.ParsePublicKey(der)
}

// ====================

// 包装私钥
func (this XMLKey) MarshalPrivateKey(key *PrivateKey) ([]byte, error) {
    // q = (p - 1) / 2
    q := new(big.Int).Set(key.P)
    q.Sub(q, one)
    q.Div(q, two)

    // 构造私钥信息
    priv := xmlPrivateKey{
        P: this.bigintToB64(key.P),
        G: this.bigintToB64(key.G),
        Q: this.bigintToB64(q),
        Y: this.bigintToB64(key.Y),
        X: this.bigintToB64(key.X),
    }

    return xml.MarshalIndent(priv, "", "    ")
}

func MarshalXMLPrivateKey(key *PrivateKey) ([]byte, error) {
    return defaultXMLKey.MarshalPrivateKey(key)
}

// 解析私钥
func (this XMLKey) ParsePrivateKey(data []byte) (*PrivateKey, error) {
    var priv xmlPrivateKey
    err := xml.Unmarshal(data, &priv)
    if err != nil {
        return nil, err
    }

    g, err := this.b64ToBigint(priv.G)
    if err != nil {
        return nil, errPrivateKeyXMLValue("G")
    }

    p, err := this.b64ToBigint(priv.P)
    if err != nil {
        return nil, errPrivateKeyXMLValue("P")
    }

    y, err := this.b64ToBigint(priv.Y)
    if err != nil {
        return nil, errPrivateKeyXMLValue("Y")
    }

    x, err := this.b64ToBigint(priv.X)
    if err != nil {
        return nil, errPrivateKeyXMLValue("X")
    }

    if g.Sign() <= 0 || p.Sign() <= 0 || y.Sign() <= 0 || x.Sign() <= 0 {
        return nil, errors.New("elgamal xml: private key contains zero or negative value")
    }

    privateKey := &PrivateKey{
        PublicKey: PublicKey{
            G: g,
            P: p,
            Y: y,
        },
        X: x,
    }

    return privateKey, nil
}

func ParseXMLPrivateKey(der []byte) (*PrivateKey, error) {
    return defaultXMLKey.ParsePrivateKey(der)
}

// ====================

func (this XMLKey) b64d(str string) ([]byte, error) {
    decoded, err := base64.StdEncoding.DecodeString(str)

    return []byte(decoded), err
}

func (this XMLKey) b64e(src []byte) string {
    return base64.StdEncoding.EncodeToString(src)
}

func (this XMLKey) b64ToBigint(str string) (*big.Int, error) {
    decoded, err := this.b64d(str)
    if err != nil {
        return nil, err
    }

    bInt := &big.Int{}
    bInt.SetBytes(decoded)

    return bInt, nil
}

func (this XMLKey) bigintToB64(encoded *big.Int) string {
    return this.b64e(encoded.Bytes())
}
