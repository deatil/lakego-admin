package rsa

import (
    "errors"
    "strconv"
    "math/big"
    "crypto/rsa"
    "encoding/xml"

    "github.com/deatil/go-cryptobin/tool"
)

// 私钥
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

// 公钥
type xmlPublicKey struct {
    XMLName  xml.Name `xml:"RSAKeyValue"`
    Modulus  string   `xml:"Modulus"`
    Exponent string   `xml:"Exponent"`
}

// 构造函数
func NewXMLKey() XMLKey {
    return XMLKey{}
}

var defaultXMLKey = NewXMLKey()

/**
 * rsa 密钥
 *
 * @create 2023-4-10
 * @author deatil
 */
type XMLKey struct {}

// 包装公钥
func (this XMLKey) MarshalPublicKey(key *rsa.PublicKey) ([]byte, error) {
    publicKey := xmlPublicKey{
        Modulus:  bigIntToString(key.N),
        Exponent: intToString(key.E),
    }

    return xml.MarshalIndent(publicKey, "", "    ")
}

func MarshalXMLPublicKey(key *rsa.PublicKey) ([]byte, error) {
    return defaultXMLKey.MarshalPublicKey(key)
}

// 解析公钥
func (this XMLKey) ParsePublicKey(der []byte) (*rsa.PublicKey, error) {
    var priv xmlPublicKey
    err := xml.Unmarshal(der, &priv)
    if err != nil {
        return nil, err
    }

    publicKey := &rsa.PublicKey{
        N: stringToBigInt(priv.Modulus),
        E: stringToInt(priv.Exponent),
    }

    return publicKey, nil
}

func ParseXMLPublicKey(der []byte) (*rsa.PublicKey, error) {
    return defaultXMLKey.ParsePublicKey(der)
}

// ====================

// 包装私钥
func (this XMLKey) MarshalPrivateKey(key *rsa.PrivateKey) ([]byte, error) {
    key.Precompute()

    // 构造私钥信息
    priv := xmlPrivateKey{
        Modulus:  bigIntToString(key.N),
        Exponent: intToString(key.PublicKey.E),
        D:        bigIntToString(key.D),
        P:        bigIntToString(key.Primes[0]),
        Q:        bigIntToString(key.Primes[1]),
        DP:       bigIntToString(key.Precomputed.Dp),
        DQ:       bigIntToString(key.Precomputed.Dq),
        InverseQ: bigIntToString(key.Precomputed.Qinv),
    }

    return xml.MarshalIndent(priv, "", "    ")
}

func MarshalXMLPrivateKey(key *rsa.PrivateKey) ([]byte, error) {
    return defaultXMLKey.MarshalPrivateKey(key)
}

// 解析私钥
func (this XMLKey) ParsePrivateKey(der []byte) (*rsa.PrivateKey, error) {
    var priv xmlPrivateKey
    err := xml.Unmarshal(der, &priv)
    if err != nil {
        return nil, err
    }

    e := stringToInt(priv.Exponent)
    n := stringToBigInt(priv.Modulus)
    d := stringToBigInt(priv.D)
    p := stringToBigInt(priv.P)
    q := stringToBigInt(priv.Q)

    if n.Sign() <= 0 || d.Sign() <= 0 || p.Sign() <= 0 || q.Sign() <= 0 {
        return nil, errors.New("rsa xml: private key contains zero or negative value")
    }

    key := new(rsa.PrivateKey)
    key.PublicKey = rsa.PublicKey{
        N: n,
        E: e,
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

func ParseXMLPrivateKey(der []byte) (*rsa.PrivateKey, error) {
    return defaultXMLKey.ParsePrivateKey(der)
}

func stringToInt(s string) int {
    ds := Base64Decode(s)

    return bytesToInt(ds)
}

func intToString(i int) string {
    return Base64Encode(intToBytes(i))
}

func stringToBigInt(s string) *big.Int {
    ds := Base64Decode(s)

    return new(big.Int).SetBytes(ds)
}

func bigIntToString(i *big.Int) string {
    return Base64Encode(i.Bytes())
}

func intToBytes(i int) []byte {
    s := strconv.Itoa(i)

    return []byte(s)
}

func bytesToInt(b []byte) int {
    v, err := strconv.ParseInt(string(b), 0, 0)
    if err == nil {
        return int(v)
    }

    return 0
}

func Base64Encode(src []byte) string {
    return tool.Base64Encode(src)
}

func Base64Decode(s string) []byte {
    b, _ := tool.Base64Decode(s)

    return b
}
