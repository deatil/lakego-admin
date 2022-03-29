package cryptobin

import (
    "crypto/rand"
    "crypto/x509"
    "encoding/pem"
)

// pkc1 转 pkc8
func (this *Rsa) PrvKeyPKCS1ToPKCS8(key []byte) ([]byte, error) {
    priv, err := this.ParseRSAPrivateKeyFromPEM(key)
    if err != nil {
        return nil, err
    }

    X509PrivateKey, err := x509.MarshalPKCS8PrivateKey(priv)
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

// pkc8 转 pkc1
func (this *Rsa) PrvKeyPKCS8ToPKCS1(key []byte) ([]byte, error) {
    priv, err := this.ParseRSAPrivateKeyFromPEM(key)
    if err != nil {
        return nil, err
    }

    X509PrivateKey := x509.MarshalPKCS1PrivateKey(priv)

    privateBlock := pem.Block{
        Type: "RSA PRIVATE KEY",
        Bytes: X509PrivateKey,
    }

    rs := pem.EncodeToMemory(&privateBlock)
    return rs, nil
}

// 带密码 pkc1 转 pkc8
func (this *Rsa) PassPrvKeyPKCS1ToPKCS8(key []byte, oldPass string, newPass string, PEMCipher ...string) ([]byte, error) {
    priv, err := this.ParseRSAPrivateKeyFromPEMWithPassword(key, oldPass)
    if err != nil {
        return nil, err
    }

    if oldPass == "" {
        X509PrivateKey, err := x509.MarshalPKCS8PrivateKey(priv)
        if err != nil {
            return nil, err
        }

        privateBlock := pem.Block{
            Type: "PRIVATE KEY",
            Bytes: X509PrivateKey,
        }

        rs := pem.EncodeToMemory(&privateBlock)
        return rs, nil
    } else {
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

        x509PrivateKey, err := x509.MarshalPKCS8PrivateKey(priv)
        if err != nil {
            return nil, err
        }

        privateBlock, err := EncryptPKCS8PrivateKey(
            rand.Reader,
            "ENCRYPTED PRIVATE KEY",
            x509PrivateKey,
            []byte(newPass),
            usePEMCipher,
        )
        if err != nil {
            return nil, err
        }

        rs := pem.EncodeToMemory(privateBlock)
        return rs, nil
    }
}

// 带密码 pkc8 转 pkc1
func (this *Rsa) PassPrvKeyPKCS8ToPKCS1(key []byte, oldPass string, newPass string, PEMCipher ...string) ([]byte, error) {
    privateKey, err := this.ParseRSAPKCS8PrivateKeyFromPEMWithPassword(key, oldPass)
    if err != nil {
        return nil, err
    }

    if oldPass == "" {
        X509PrivateKey := x509.MarshalPKCS1PrivateKey(privateKey)

        privateBlock := pem.Block{
            Type: "RSA PRIVATE KEY",
            Bytes: X509PrivateKey,
        }

        rs := pem.EncodeToMemory(&privateBlock)
        return rs, nil
    } else {
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

        x509PrivateKey := x509.MarshalPKCS1PrivateKey(privateKey)

        privateBlock, err := x509.EncryptPEMBlock(
            rand.Reader,
            "RSA PRIVATE KEY",
            x509PrivateKey,
            []byte(newPass),
            usePEMCipher,
        )
        if err != nil {
            return nil, err
        }

        rs := pem.EncodeToMemory(privateBlock)
        return rs, nil
    }
}

