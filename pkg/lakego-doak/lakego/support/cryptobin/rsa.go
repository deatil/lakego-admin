package cryptobin

import (
    "fmt"
    "crypto"
    "crypto/rand"
    "crypto/rsa"
    "crypto/x509"
    "crypto/sha256"
    "encoding/pem"
)

// 构造函数
func NewRsa() *Rsa {
    return &Rsa{}
}

/**
 * Rsa 加密
 *
 * @create 2021-8-28
 * @author deatil
 */
type Rsa struct {}

// RSA公钥私钥产生
func (this *Rsa) MakeKey(bits int) ([]byte, []byte, error) {
    var prvkey []byte
    var pubkey []byte

    // 生成私钥文件
    privateKey, err := rsa.GenerateKey(rand.Reader, bits)
    if err != nil {
        return nil, nil, err
    }

    derStream := x509.MarshalPKCS1PrivateKey(privateKey)
    block := &pem.Block{
        Type:  "RSA PRIVATE KEY",
        Bytes: derStream,
    }
    prvkey = pem.EncodeToMemory(block)

    // 公钥
    publicKey := &privateKey.PublicKey
    derPkix, err := x509.MarshalPKIXPublicKey(publicKey)
    if err != nil {
        return nil, nil, err
    }

    block = &pem.Block{
        Type:  "RSA PUBLIC KEY",
        Bytes: derPkix,
    }
    pubkey = pem.EncodeToMemory(block)

    return prvkey, pubkey, nil
}

// 私钥
func (this *Rsa) MakePrvKey(bits int) ([]byte, error) {
    privateKey, err := rsa.GenerateKey(rand.Reader, bits)
    if err != nil {
        return nil, err
    }

    X509PrivateKey := x509.MarshalPKCS1PrivateKey(privateKey)

    privateBlock := pem.Block{
        Type: "RSA Private Key",
        Bytes: X509PrivateKey,
    }

    rs := pem.EncodeToMemory(&privateBlock)
    return rs, nil
}

// 公钥
func (this *Rsa) MakePubKeyFromPrvKey(prvKey []byte) ([]byte, error) {
    privateKey, err := ParseRSAPrivateKeyFromPEM(prvKey)
    if err != nil {
        return nil, err
    }

    publicKey := privateKey.PublicKey

    X509PublicKey, err := x509.MarshalPKIXPublicKey(&publicKey)
    if err != nil {
        return nil, err
    }

    publicBlock := pem.Block{
        Type: "RSA Public Key",
        Bytes: X509PublicKey,
    }

    rs := pem.EncodeToMemory(&publicBlock)
    return rs, nil
}

// 带密码私钥
func (this *Rsa) MakePassPrvKey(bits int, password string) ([]byte, error) {
    privateKey, err := rsa.GenerateKey(rand.Reader, bits)
    if err != nil {
        return nil, err
    }

    x509PrivateKey := x509.MarshalPKCS1PrivateKey(privateKey)

    privateBlock, err := x509.EncryptPEMBlock(rand.Reader, "RSA Private Key", x509PrivateKey, []byte(password), x509.PEMCipherAES256)
    if err != nil {
        return nil, err
    }

    rs := pem.EncodeToMemory(privateBlock)
    return rs, nil
}

// 公钥
func (this *Rsa) MakePubKeyFromPassPrvKey(prvKey []byte, password string) ([]byte, error) {
    privateKey, err := ParseRSAPrivateKeyFromPEMWithPassword(prvKey, password)
    if err != nil {
        return nil, err
    }

    publicKey := privateKey.PublicKey

    X509PublicKey, err := x509.MarshalPKIXPublicKey(&publicKey)
    if err != nil {
        return nil, err
    }

    publicBlock := pem.Block{
        Type: "RSA Public Key",
        Bytes: X509PublicKey,
    }

    rs := pem.EncodeToMemory(&publicBlock)
    return rs, nil
}

// 签名
func (this *Rsa) SignWithSha256(data []byte, keyBytes []byte, password ...string) ([]byte, error) {
    h := sha256.New()
    h.Write(data)
    hashed := h.Sum(nil)

    var priv *rsa.PrivateKey
    var err error

    if len(password) > 0 {
        priv, err = ParseRSAPrivateKeyFromPEMWithPassword(keyBytes, password[0])
    } else {
        priv, err = ParseRSAPrivateKeyFromPEM(keyBytes)
    }

    signature, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, hashed)
    if err != nil {
        fmt.Printf("Error from signing: %s\n", err)
        return nil, err
    }

    return signature, nil
}

// 验证
func (this *Rsa) VeryWithSha256(data, signData, keyBytes []byte) (bool, error) {
    pubKey, err := ParseRSAPublicKeyFromPEM(keyBytes)
    if err != nil {
        return false, err
    }

    hashed := sha256.Sum256(data)
    err = rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, hashed[:], signData)
    if err != nil {
        return false, err
    }

    return true, nil
}

// 公钥加密
func (this *Rsa) Encrypt(data []byte, keyBytes []byte) ([]byte, error) {
    // 解析公钥
    pub, err := ParseRSAPublicKeyFromPEM(keyBytes)
    if err != nil {
        return nil, err
    }

    //加密
    ciphertext, err := rsa.EncryptPKCS1v15(rand.Reader, pub, data)
    if err != nil {
        return nil, err
    }

    return ciphertext, nil
}

// 私钥解密
func (this *Rsa) Decrypt(ciphertext []byte, keyBytes []byte, password ...string) ([]byte, error) {
    var priv *rsa.PrivateKey
    var err error

    if len(password) > 0 {
        priv, err = ParseRSAPrivateKeyFromPEMWithPassword(keyBytes, password[0])
    } else {
        priv, err = ParseRSAPrivateKeyFromPEM(keyBytes)
    }

    if err != nil {
        return nil, err
    }

    // 解密
    data, err := rsa.DecryptPKCS1v15(rand.Reader, priv, ciphertext)
    if err != nil {
        return nil, err
    }

    return data, nil
}
