package jceks

import (
    "fmt"
    "time"
    "crypto"
)

type privateKeyEntry struct {
    date       time.Time
    encodedKey []byte
    certs      [][]byte
}

func (this *privateKeyEntry) String() string {
    return fmt.Sprintf("private-key: %s", this.date)
}

func (this *privateKeyEntry) Recover(password []byte) (crypto.PrivateKey, error) {
    decryptedKey, err := DecodeData(this.encodedKey, password)
    if err != nil {
        return nil, fmt.Errorf("encrypted-private-key %s", err.Error())
    }

    privateKey, err := ParsePKCS8PrivateKey(decryptedKey)
    if err != nil {
        return nil, err
    }

    return privateKey, nil
}

func (this *privateKeyEntry) Encode(privateKey crypto.PrivateKey, password string, cipher ...Cipher) ([]byte, error) {
    marshaledPrivateKey, err := MarshalPKCS8PrivateKey(privateKey)
    if err != nil {
        return nil, err
    }

    encodedData, err := EncodeData(marshaledPrivateKey, password, cipher...)
    if err != nil {
        return nil, err
    }

    return encodedData, nil
}

// ===================

type trustedCertEntry struct {
    date time.Time
    cert []byte
}

func (this *trustedCertEntry) String() string {
    return fmt.Sprintf("trusted-cert: %s", this.date)
}

// ===================

type secretKeyEntry struct {
    date       time.Time
    encodedKey []byte
}

func (this *secretKeyEntry) String() string {
    return fmt.Sprintf("secret-key: %s", this.date)
}

func (this *secretKeyEntry) Recover(password []byte) ([]byte, error) {
    decryptedKey, err := DecodeData(this.encodedKey, password)
    if err != nil {
        return nil, fmt.Errorf("encrypted-secret-key %s", err.Error())
    }

    return decryptedKey, nil
}

func (this *secretKeyEntry) Encode(secretKey []byte, password string, cipher ...Cipher) ([]byte, error) {
    encodedData, err := EncodeData(secretKey, password, cipher...)
    if err != nil {
        return nil, err
    }

    return encodedData, nil
}
