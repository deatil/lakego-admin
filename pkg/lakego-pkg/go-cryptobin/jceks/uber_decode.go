package jceks

import (
    "fmt"
    "bytes"
    "crypto/sha1"
    "crypto/subtle"
    "encoding/asn1"
)

// 解析
func (this *UBER) Parse(data []byte, password string) error {
    r := bytes.NewReader(data)

    version, err := readUint32(r)
    if err != nil {
        return err
    }

    if version != UberVersionV1 {
        return fmt.Errorf("Unsupported UBER keystore version; only v1 supported, found v%d", version)
    }

    this.version = version
    this.storeType = "uber"

    salt, err := readBytes(r)
    if err != nil {
        return err
    }

    iterationCount, err := readInt32(r)
    if err != nil {
        return err
    }

    encryptedBlob := data[len(salt) + 12:]

    params, err := asn1.Marshal(pbeParam{
        Salt:           salt,
        IterationCount: int(iterationCount),
    })
    if err != nil {
        return err
    }

    decrypted, err := CipherSHA1AndTwofishForUBER.Decrypt([]byte(password), params, encryptedBlob)
    if err != nil {
        return err
    }

    hashFn := sha1.New
    hashDigestSize := hashFn().Size()

    dataLen := len(decrypted) - hashDigestSize

    uberStore := decrypted[:dataLen]
    actual := decrypted[dataLen:]

    h := hashFn()
    h.Write(uberStore)
    computed := h.Sum([]byte{})

    if subtle.ConstantTimeCompare(computed, actual) != 1 {
        return fmt.Errorf("keystore was tampered with or password was incorrect")
    }

    rr := bytes.NewReader(uberStore)

    err = this.loadEntries(rr, password)
    if err != nil {
        return err
    }

    return nil
}
