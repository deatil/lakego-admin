package jceks

import (
    "fmt"
    "bytes"
    "errors"
    "crypto/sha1"
    "crypto/subtle"
)

// Parse data
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

    encryptedLen := len(salt) + 12

    if len(data) < encryptedLen {
        return errors.New("go-cryptobin/jceks: data not right length")
    }

    encryptedBlob := data[encryptedLen:]

    decrypted, err := CipherSHA1AndTwofishForUBER.decrypt([]byte(password), salt, int(iterationCount), encryptedBlob)
    if err != nil {
        return err
    }

    hashFn := sha1.New
    hashDigestSize := hashFn().Size()

    dataLen := len(decrypted) - hashDigestSize

    if len(decrypted) < dataLen {
        return errors.New("go-cryptobin/jceks: decrypted not right length")
    }

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
