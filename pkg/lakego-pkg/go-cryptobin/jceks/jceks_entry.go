package jceks

import (
    "fmt"
    "time"
)

type privateKeyEntry struct {
    date       time.Time
    encodedKey []byte
    certs      [][]byte
}

func (this *privateKeyEntry) String() string {
    return fmt.Sprintf("private-key: %s", this.date)
}

func (this *privateKeyEntry) Recover(password []byte) ([]byte, error) {
    privateKey, err := DecodeData(this.encodedKey, password)
    if err != nil {
        return nil, fmt.Errorf("encrypted-private-key %s", err.Error())
    }

    return privateKey, nil
}

func (this *privateKeyEntry) Encode(privateKey []byte, password string, cipher ...Cipher) ([]byte, error) {
    encodedData, err := EncodeData(privateKey, password, cipher...)
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
