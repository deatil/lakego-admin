package rsa

import (
    "errors"
    "math/big"
    "crypto/rsa"
    "encoding/xml"
    "encoding/base64"
)

// xml PrivateKey
type xmlPrivateKey struct {
    XMLName  xml.Name `xml:"RSAKeyValue"`
    Modulus  string   `xml:"Modulus"`
    Exponent string   `xml:"Exponent"`
    D        string   `xml:"D"`
    P        string   `xml:"P"`
    Q        string   `xml:"Q"`
    DP       string   `xml:"DP"`
    DQ       string   `xml:"DQ"`
    InverseQ string   `xml:"InverseQ"`
}

// xml PublicKey
type xmlPublicKey struct {
    XMLName  xml.Name `xml:"RSAKeyValue"`
    Modulus  string   `xml:"Modulus"`
    Exponent string   `xml:"Exponent"`
}

var (
    errPublicKeyXMLValue = func(name string) error {
        return errors.New("rsa xml: public key [" + name + "] value is error")
    }

    errPrivateKeyXMLValue = func(name string) error {
        return errors.New("rsa xml: private key [" + name + "] value is error")
    }
)

var defaultXMLKey = NewXMLKey()

/**
 * rsa xml
 *
 * @create 2023-4-10
 * @author deatil
 */
type XMLKey struct {}

// NewXMLKey
func NewXMLKey() XMLKey {
    return XMLKey{}
}

// Marshal XML PublicKey
func (this XMLKey) MarshalPublicKey(key *rsa.PublicKey) ([]byte, error) {
    publicKey := xmlPublicKey{
        Modulus:  this.bigintToB64(key.N),
        Exponent: this.bigintToB64(big.NewInt(int64(key.E))),
    }

    return xml.MarshalIndent(publicKey, "", "    ")
}

// Marshal XML PublicKey
func MarshalXMLPublicKey(key *rsa.PublicKey) ([]byte, error) {
    return defaultXMLKey.MarshalPublicKey(key)
}

// Parse XML PublicKey
func (this XMLKey) ParsePublicKey(der []byte) (*rsa.PublicKey, error) {
    var pub xmlPublicKey
    err := xml.Unmarshal(der, &pub)
    if err != nil {
        return nil, err
    }

    n, err := this.b64ToBigint(pub.Modulus)
    if err != nil {
        return nil, errPublicKeyXMLValue("Modulus")
    }

    e, err := this.b64ToBigint(pub.Exponent)
    if err != nil {
        return nil, errPublicKeyXMLValue("Exponent")
    }

    if n.Sign() <= 0 {
        return nil, errors.New("rsa xml: public key contains zero or negative value")
    }

    publicKey := &rsa.PublicKey{
        N: n,
        E: int(e.Int64()),
    }

    return publicKey, nil
}

// Parse XML PublicKey
func ParseXMLPublicKey(der []byte) (*rsa.PublicKey, error) {
    return defaultXMLKey.ParsePublicKey(der)
}

// Marshal XML PrivateKey
func (this XMLKey) MarshalPrivateKey(key *rsa.PrivateKey) ([]byte, error) {
    key.Precompute()

    // 构造私钥信息
    priv := xmlPrivateKey{
        Modulus:  this.bigintToB64(key.N),
        Exponent: this.bigintToB64(big.NewInt(int64(key.E))),
        D:        this.bigintToB64(key.D),
        P:        this.bigintToB64(key.Primes[0]),
        Q:        this.bigintToB64(key.Primes[1]),
        DP:       this.bigintToB64(key.Precomputed.Dp),
        DQ:       this.bigintToB64(key.Precomputed.Dq),
        InverseQ: this.bigintToB64(key.Precomputed.Qinv),
    }

    return xml.MarshalIndent(priv, "", "    ")
}

// Marshal XML PrivateKey
func MarshalXMLPrivateKey(key *rsa.PrivateKey) ([]byte, error) {
    return defaultXMLKey.MarshalPrivateKey(key)
}

// Parse XML PrivateKey
func (this XMLKey) ParsePrivateKey(der []byte) (*rsa.PrivateKey, error) {
    var priv xmlPrivateKey
    err := xml.Unmarshal(der, &priv)
    if err != nil {
        return nil, err
    }

    n, err := this.b64ToBigint(priv.Modulus)
    if err != nil {
        return nil, errPrivateKeyXMLValue("Modulus")
    }

    e, err := this.b64ToBigint(priv.Exponent)
    if err != nil {
        return nil, errPrivateKeyXMLValue("Exponent")
    }

    d, err := this.b64ToBigint(priv.D)
    if err != nil {
        return nil, errPrivateKeyXMLValue("D")
    }

    p, err := this.b64ToBigint(priv.P)
    if err != nil {
        return nil, errPrivateKeyXMLValue("P")
    }

    q, err := this.b64ToBigint(priv.Q)
    if err != nil {
        return nil, errPrivateKeyXMLValue("Q")
    }

    if n.Sign() <= 0 || d.Sign() <= 0 || p.Sign() <= 0 || q.Sign() <= 0 {
        return nil, errors.New("rsa xml: private key contains zero or negative value")
    }

    key := new(rsa.PrivateKey)
    key.PublicKey = rsa.PublicKey{
        N: n,
        E: int(e.Int64()),
    }

    key.D = d
    key.Primes = make([]*big.Int, 2)
    key.Primes[0] = p
    key.Primes[1] = q

    err = key.Validate()
    if err != nil {
        return nil, err
    }

    key.Precompute()

    return key, nil
}

// Parse XML PrivateKey
func ParseXMLPrivateKey(der []byte) (*rsa.PrivateKey, error) {
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

// big.NewInt(int64)
func (this XMLKey) bigintToB64(encoded *big.Int) string {
    return this.b64e(encoded.Bytes())
}
