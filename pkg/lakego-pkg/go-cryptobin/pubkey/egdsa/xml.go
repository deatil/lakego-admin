package egdsa

import (
    "errors"
    "math/big"
    "encoding/xml"
    "encoding/base64"
)

// xml PrivateKey
type xmlPrivateKey struct {
    XMLName xml.Name `xml:"EGDSAKeyValue"`
    P       string   `xml:"P"`
    G       string   `xml:"G"`
    Q       string   `xml:"Q,omitempty"`
    Y       string   `xml:"Y"`
    X       string   `xml:"X"`
}

// xml PublicKey
type xmlPublicKey struct {
    XMLName xml.Name `xml:"EGDSAKeyValue"`
    P       string   `xml:"P"`
    G       string   `xml:"G"`
    Q       string   `xml:"Q,omitempty"`
    Y       string   `xml:"Y"`
}

var (
    errPublicKeyXMLValue = func(name string) error {
        return errors.New("egdsa xml: public key [" + name + "] value is error")
    }

    errPrivateKeyXMLValue = func(name string) error {
        return errors.New("egdsa xml: private key [" + name + "] value is error")
    }
)

var defaultXMLKey = NewXMLKey()

/**
 * egdsa xml
 *
 * @create 2024-8-12
 * @author deatil
 */
type XMLKey struct {}

// NewXMLKey
func NewXMLKey() XMLKey {
    return XMLKey{}
}

// Marshal XML PublicKey
func (this XMLKey) MarshalPublicKey(key *PublicKey) ([]byte, error) {
    publicKey := xmlPublicKey{
        P: this.bigintToB64(key.P),
        G: this.bigintToB64(key.G),
        Y: this.bigintToB64(key.Y),
    }

    return xml.MarshalIndent(publicKey, "", "    ")
}

// Marshal XML PublicKey
func MarshalXMLPublicKey(key *PublicKey) ([]byte, error) {
    return defaultXMLKey.MarshalPublicKey(key)
}

// Parse XML PublicKey
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
        return nil, errors.New("egdsa xml: public key contains zero or negative value")
    }

    publicKey := &PublicKey{
        P: p,
        G: g,
        Y: y,
    }

    return publicKey, nil
}

// Parse XML PublicKey
func ParseXMLPublicKey(der []byte) (*PublicKey, error) {
    return defaultXMLKey.ParsePublicKey(der)
}

// Marshal XML PrivateKey
func (this XMLKey) MarshalPrivateKey(key *PrivateKey) ([]byte, error) {
    // 构造私钥信息
    priv := xmlPrivateKey{
        P: this.bigintToB64(key.P),
        G: this.bigintToB64(key.G),
        Y: this.bigintToB64(key.Y),
        X: this.bigintToB64(key.X),
    }

    return xml.MarshalIndent(priv, "", "    ")
}

// Marshal XML PrivateKey
func MarshalXMLPrivateKey(key *PrivateKey) ([]byte, error) {
    return defaultXMLKey.MarshalPrivateKey(key)
}

// Parse XML PrivateKey
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
        return nil, errors.New("egdsa xml: private key contains zero or negative value")
    }

    privateKey := &PrivateKey{
        PublicKey: PublicKey{
            P: p,
            G: g,
            Y: y,
        },
        X: x,
    }

    return privateKey, nil
}

// Parse XML PrivateKey
func ParseXMLPrivateKey(der []byte) (*PrivateKey, error) {
    return defaultXMLKey.ParsePrivateKey(der)
}

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
