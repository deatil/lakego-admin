package rsa

import (
    "fmt"
    "errors"
    "crypto"
    "crypto/rand"
    "crypto/rsa"
    "crypto/sha256"
    "crypto/x509"
    "encoding/pem"
)

// "github.com/deatil/lakego-admin/lakego/support/rsa"
type Rsa struct {

}

func New() *Rsa {
    return &Rsa{}
}

// RSA公钥私钥产生
func (*Rsa) MakeRsaKey() ([]byte, []byte, error) {
    var prvkey []byte
    var pubkey []byte

    // 生成私钥文件
    privateKey, err := rsa.GenerateKey(rand.Reader, 1024)
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
        Type:  "PUBLIC KEY",
        Bytes: derPkix,
    }
    pubkey = pem.EncodeToMemory(block)

    return prvkey, pubkey, nil
}

// RsaSignWithSha256 签名
func (*Rsa) RsaSignWithSha256(data []byte, keyBytes []byte) ([]byte, error) {
    h := sha256.New()
    h.Write(data)
    hashed := h.Sum(nil)

    block, _ := pem.Decode(keyBytes)
    if block == nil {
        return nil, errors.New("private key error!")
    }

    privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
    if err != nil {
        fmt.Println("ParsePKCS8PrivateKey err", err)
        return nil, err
    }

    signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hashed)
    if err != nil {
        fmt.Printf("Error from signing: %s\n", err)
        return nil, err
    }

    return signature, nil
}

// RsaVerySignWithSha256 验证
func (*Rsa) RsaVerySignWithSha256(data, signData, keyBytes []byte) (bool, error) {
    block, _ := pem.Decode(keyBytes)
    if block == nil {
        return false, errors.New("public key error!")
    }

    pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
    if err != nil {
        return false, err
    }

    hashed := sha256.Sum256(data)
    err = rsa.VerifyPKCS1v15(pubKey.(*rsa.PublicKey), crypto.SHA256, hashed[:], signData)
    if err != nil {
        return false, err
    }

    return true, nil
}

// RsaEncrypt 公钥加密
func (*Rsa) RsaEncrypt(data, keyBytes []byte) ([]byte, error) {
    // 解密pem格式的公钥
    block, _ := pem.Decode(keyBytes)
    if block == nil {
        return nil, errors.New("public key error!")
    }

    // 解析公钥
    pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
    if err != nil {
        return nil, err
    }

    // 类型断言
    pub := pubInterface.(*rsa.PublicKey)

    //加密
    ciphertext, err := rsa.EncryptPKCS1v15(rand.Reader, pub, data)
    if err != nil {
        return nil, err
    }

    return ciphertext, nil
}

// RsaDecrypt 私钥解密
func (*Rsa) RsaDecrypt(ciphertext, keyBytes []byte) ([]byte, error) {
    //获取私钥
    block, _ := pem.Decode(keyBytes)
    if block == nil {
        return nil, errors.New("private key error!")
    }

    //解析PKCS1格式的私钥
    priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
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
