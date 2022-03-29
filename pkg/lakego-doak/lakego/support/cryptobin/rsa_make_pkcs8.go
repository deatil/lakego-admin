package cryptobin

import (
    "crypto/rand"
    "crypto/rsa"
    "crypto/x509"
    "encoding/pem"
)

// 生成 PKCS8 私钥
// bits = 512 | 1024 | 2048 | 4096
func (this *Rsa) MakePKCS8PrivateKey(bits int) ([]byte, error) {
    private, err := rsa.GenerateKey(rand.Reader, bits)
    if err != nil {
        return nil, err
    }

    X509PrivateKey, err := x509.MarshalPKCS8PrivateKey(private)
    if err != nil {
        return nil, err
    }

    privateBlock := pem.Block{
        Type: "PRIVATE KEY",
        Bytes: X509PrivateKey,
    }

    rs := pem.EncodeToMemory(&privateBlock)
    return rs, nil
}

// 公钥
func (this *Rsa) MakePKCS8PubKeyFromPKCS8PrvKey(prvKey []byte) ([]byte, error) {
    return this.MakePubKeyFromPrvKey(prvKey)
}

// 带密码私钥
func (this *Rsa) MakePassPKCS8PrvKey(bits int, password string, PEMCipher ...string) ([]byte, error) {
    privateKey, err := rsa.GenerateKey(rand.Reader, bits)
    if err != nil {
        return nil, err
    }

    PEMCiphers := map[string]x509.PEMCipher{
        "DES":    x509.PEMCipherDES,
        "3DES":   x509.PEMCipher3DES,
        "AES128": x509.PEMCipherAES128,
        "AES192": x509.PEMCipherAES192,
        "AES256": x509.PEMCipherAES256,
    }

    usePEMCipher := x509.PEMCipherAES256
    if len(PEMCipher) > 0 {
        userPEMCipher, ok := PEMCiphers[PEMCipher[0]]
        if ok {
            usePEMCipher = userPEMCipher
        }
    }

    x509Encoded, err := x509.MarshalPKCS8PrivateKey(privateKey)
    if err != nil {
        return nil, err
    }

    block, err := EncryptPKCS8PrivateKey(
        rand.Reader,
        "ENCRYPTED PRIVATE KEY",
        x509Encoded,
        []byte(password),
        usePEMCipher,
        "SHA256",
    )
    if err != nil {
        return nil, err
    }

    rs := pem.EncodeToMemory(block)
    return rs, nil
}

// 公钥
func (this *Rsa) MakePKCS8PubKeyFromPassPKCS8PrvKey(prvKey []byte, password string) ([]byte, error) {
    privateKey, err := this.ParseRSAPKCS8PrivateKeyFromPEMWithPassword(prvKey, password)
    if err != nil {
        return nil, err
    }

    publicKey := privateKey.PublicKey

    X509PublicKey, err := x509.MarshalPKIXPublicKey(&publicKey)
    if err != nil {
        return nil, err
    }

    publicBlock := pem.Block{
        Type: "PUBLIC KEY",
        Bytes: X509PublicKey,
    }

    rs := pem.EncodeToMemory(&publicBlock)
    return rs, nil
}
