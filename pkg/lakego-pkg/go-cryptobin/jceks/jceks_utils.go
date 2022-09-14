package jceks

import (
    "io"
    "fmt"
    "hash"
    "errors"
    "crypto/sha1"
    "encoding/asn1"
    "crypto/x509/pkix"
)

// Returns a SHA1 hash which has been pre-keyed with the specified
// password according to the JCEKS algorithm.
func getPreKeyedHash(password []byte) hash.Hash {
    md := sha1.New()

    buf := make([]byte, len(password)*2)
    for i := 0; i < len(password); i++ {
        buf[i*2+1] = password[i]
    }

    md.Write(buf)

    // Yes, "Mighty Aphrodite" is a constant used by this method.
    md.Write([]byte("Mighty Aphrodite"))

    return md
}

func parseHeader(r io.Reader) (uint32, error) {
    magic, err := readUint32(r)
    if err != nil {
        return 0, err
    }

    if magic != jceksMagic && magic != jksMagic {
        return 0, fmt.Errorf("unexpected magic: %08x != (%08x || %08x)", magic, uint32(jceksMagic), uint32(jksMagic))
    }

    version, err := readUint32(r)
    if err != nil {
        return 0, err
    }

    return version, nil
}

func writeHeader(w io.Writer) error {
    var err error

    err = writeUint32(w, jceksMagic)
    if err != nil {
        return err
    }

    err = writeUint32(w, jceksVersion)
    if err != nil {
        return err
    }

    return nil
}

// unmarshal calls asn1.Unmarshal, but also returns an error if there is any
// trailing data after unmarshaling.
func unmarshal(in []byte, out any) error {
    trailing, err := asn1.Unmarshal(in, out)
    if err != nil {
        return err
    }

    if len(trailing) != 0 {
        return errors.New("jceks: trailing data found")
    }

    return nil
}

// 解析加密数据
func parseContentEncryptionAlgorithm(contentEncryptionAlgorithm pkix.AlgorithmIdentifier) (Cipher, []byte, error) {
    oid := contentEncryptionAlgorithm.Algorithm.String()
    cipher, ok := ciphers[oid]
    if !ok {
        return nil, nil, fmt.Errorf("jceks: unsupported cipher (OID: %s)", oid)
    }

    newCipher := cipher()

    params := contentEncryptionAlgorithm.Parameters.FullBytes

    return newCipher, params, nil
}

// 加密结构图
type encryptedDataInfo struct {
    Algo          pkix.AlgorithmIdentifier
    EncryptedData []byte
}

// 加密数据
func EncodeData(data []byte, password string, cipher ...Cipher) ([]byte, error) {
    var newCipher Cipher
    if len(cipher) > 0 {
        newCipher = cipher[0]
    } else {
        newCipher = DefaultCipher
    }

    encodedData, params, err := newCipher.Encrypt([]byte(password), data)
    if err != nil {
        return nil, err
    }

    var eData encryptedDataInfo
    eData.Algo = pkix.AlgorithmIdentifier{
        Algorithm:  newCipher.OID(),
        Parameters: asn1.RawValue{
            FullBytes: params,
        },
    }
    eData.EncryptedData = encodedData

    return asn1.Marshal(eData)
}

// 解密数据
func DecodeData(encodedData, password []byte) ([]byte, error) {
    var eData encryptedDataInfo
    err := unmarshal(encodedData, &eData)
    if err != nil {
        return nil, err
    }

    var decryptedData []byte

    newCipher, params, err := parseContentEncryptionAlgorithm(eData.Algo)
    if err != nil {
        return nil, fmt.Errorf("unsupported algorithm: %v", eData.Algo.Algorithm)
    }

    decryptedData, err = newCipher.Decrypt(password, params, eData.EncryptedData)
    if err != nil {
        return nil, err
    }

    return decryptedData, nil
}
