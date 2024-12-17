package ber

import (
    "io"
    "bytes"
    "errors"
    "encoding/asn1"
    "crypto/x509"
    "crypto/x509/pkix"

    "github.com/deatil/go-cryptobin/tool/bmp_string"
    cryptobin_ber "github.com/deatil/go-cryptobin/ber"
    cryptobin_asn1 "github.com/deatil/go-cryptobin/ber/asn1"
    cryptobin_pkcs12 "github.com/deatil/go-cryptobin/pkcs12"
)

var (
    oidDataContentType = cryptobin_asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
)

type AlgorithmIdentifier struct {
    Algorithm  cryptobin_asn1.ObjectIdentifier
    Parameters cryptobin_asn1.RawValue `asn1:"optional"`
}

type ContentInfo struct {
    ContentType cryptobin_asn1.ObjectIdentifier
    Content     cryptobin_asn1.RawValue `asn1:"tag:0,explicit,optional"`
}

// from PKCS#7:
type DigestInfo struct {
    Algorithm AlgorithmIdentifier
    Digest    []byte
}

type MacData struct {
    Mac        DigestInfo
    MacSalt    []byte
    Iterations int `asn1:"optional,default:1"`
}

func (this MacData) Verify(message []byte, password []byte) error {
    mac := cryptobin_pkcs12.MacData{
        Mac: cryptobin_pkcs12.DigestInfo{
            Algorithm: pkix.AlgorithmIdentifier{
                Algorithm:  asn1.ObjectIdentifier(this.Mac.Algorithm.Algorithm),
                Parameters: asn1.RawValue{
                    FullBytes: this.Mac.Algorithm.Parameters.FullBytes,
                },
            },
            Digest: this.Mac.Digest,
        },
        MacSalt: this.MacSalt,
        Iterations: this.Iterations,
    }

    return mac.Verify(message, password)
}

type PfxPdu struct {
    Version  int
    AuthSafe ContentInfo
    MacData  MacData `asn1:"optional"`
}

type EncryptedContentInfo struct {
    ContentType                cryptobin_asn1.ObjectIdentifier
    ContentEncryptionAlgorithm AlgorithmIdentifier
    EncryptedContent           cryptobin_asn1.RawValue `asn1:"tag:0,optional"`
}

type EncryptedData struct {
    Version              int
    EncryptedContentInfo EncryptedContentInfo
}

// 转换 BER 编码的 PKCS12 证书为 DER 编码
// change DER encoded PKCS12 cert to the DER
func Parse(ber []byte, password []byte) ([]byte, error) {
    var pfx *PfxPdu
    var err error

    pfx = new(PfxPdu)
    if _, err = cryptobin_asn1.Unmarshal(ber, pfx); err != nil {
        return nil, err
    }

    if pfx.Version != 3 {
        return nil, cryptobin_pkcs12.NotImplementedError("can only decode v3 PFX PDU's")
    }

    if !pfx.AuthSafe.ContentType.Equal(oidDataContentType) {
        return nil, cryptobin_pkcs12.NotImplementedError("only password-protected PFX is implemented")
    }

    if _, err = cryptobin_asn1.Unmarshal(pfx.AuthSafe.Content.Bytes, &pfx.AuthSafe.Content); err != nil {
        return nil, err
    }

    var authenticatedSafes []byte
    if pfx.AuthSafe.Content.IsCompound {
        var buf bytes.Buffer
        authSafeBytes := pfx.AuthSafe.Content.Bytes

        for {
            var part []byte
            authSafeBytes, _ = asn1.Unmarshal(authSafeBytes, &part)

            buf.Write(part)

            if authSafeBytes == nil {
                break
            }
        }

        authenticatedSafes = buf.Bytes()
    } else {
        authenticatedSafes = pfx.AuthSafe.Content.Bytes
    }

    password, err = bmp_string.BmpStringZeroTerminated(string(password))
    if err != nil {
        return nil, err
    }

    if len(pfx.MacData.Mac.Algorithm.Algorithm) == 0 {
        if !(len(password) == 2 && password[0] == 0 && password[1] == 0) {
            return nil, errors.New("go-cryptobin/pkcs12: no MAC in data")
        }
    } else {
        if err := pfx.MacData.Verify(authenticatedSafes, password); err != nil {
            if err == cryptobin_pkcs12.ErrIncorrectPassword && len(password) == 2 && password[0] == 0 && password[1] == 0 {
                password = nil
                err = pfx.MacData.Verify(authenticatedSafes, password)
            }

            if err != nil {
                return nil, err
            }
        }
    }

    var contentInfos []ContentInfo
    _, err = cryptobin_asn1.Unmarshal(authenticatedSafes, &contentInfos)
    if err != nil {
        return nil, err
    }

    newContentInfos := make([]cryptobin_pkcs12.ContentInfo, 0)
    for _, ci := range contentInfos {
        var newBytes []byte

        if ci.ContentType.Equal(oidDataContentType) {
            if _, err = cryptobin_asn1.Unmarshal(ci.Content.Bytes, &ci.Content); err != nil {
                return nil, err
            }

            newBytes = ci.Content.Bytes
        } else {
            var encryptedData EncryptedData
            if _, err = cryptobin_asn1.Unmarshal(ci.Content.Bytes, &encryptedData); err != nil {
                return nil, err
            }

            encryptedContentInfo := encryptedData.EncryptedContentInfo
            contentType := encryptedContentInfo.ContentType
            contentEncryptionAlgo := encryptedContentInfo.ContentEncryptionAlgorithm

            encryptedContent := encryptedContentInfo.EncryptedContent
            if _, err = cryptobin_asn1.Unmarshal(encryptedContent.Bytes, &encryptedContent); err != nil {
                return nil, err
            }

            newEncryptedContentInfo := cryptobin_pkcs12.EncryptedContentInfo{
                ContentType: asn1.ObjectIdentifier(contentType),
                ContentEncryptionAlgorithm: pkix.AlgorithmIdentifier{
                    Algorithm: asn1.ObjectIdentifier(contentEncryptionAlgo.Algorithm),
                    Parameters: asn1.RawValue{
                        FullBytes: contentEncryptionAlgo.Parameters.FullBytes,
                    },
                },
                EncryptedContent: encryptedContent.Bytes,
            }

            newEncryptedData := cryptobin_pkcs12.EncryptedData{
                Version: encryptedData.Version,
                EncryptedContentInfo: newEncryptedContentInfo,
            }

            if newBytes, err = asn1.Marshal(newEncryptedData); err != nil {
                return nil, err
            }
        }

        newBytes, err = cryptobin_ber.Ber2der(newBytes)
        if err != nil {
            return nil, err
        }

        newContentInfos = append(newContentInfos, cryptobin_pkcs12.ContentInfo{
            ContentType: asn1.ObjectIdentifier(ci.ContentType),
            Content: asn1.RawValue{
                Class: 2,
                Tag: 0,
                IsCompound: true,
                Bytes: newBytes,
            },
        })
    }

    var authenticatedSafeBytes []byte
    if authenticatedSafeBytes, err = asn1.Marshal(newContentInfos[:]); err != nil {
        return nil, err
    }

    var pfxPdu cryptobin_pkcs12.PfxPdu
    pfxPdu.Version = 3

    // mac opts
    macOpts := cryptobin_pkcs12.MacOpts{
        SaltSize: 8,
        IterationCount: pfx.MacData.Iterations,
        HMACHash: cryptobin_pkcs12.SHA1,
    }

    // compute the MAC
    var kdfMacData cryptobin_pkcs12.MacKDFParameters
    kdfMacData, err = macOpts.Compute(authenticatedSafeBytes, password)
    if err != nil {
        return nil, err
    }

    pfxPdu.MacData = kdfMacData.(cryptobin_pkcs12.MacData)

    // compute the AuthSafe
    pfxPdu.AuthSafe.ContentType = asn1.ObjectIdentifier(oidDataContentType)
    pfxPdu.AuthSafe.Content.Class = 2
    pfxPdu.AuthSafe.Content.Tag = 0
    pfxPdu.AuthSafe.Content.IsCompound = true
    if pfxPdu.AuthSafe.Content.Bytes, err = asn1.Marshal(authenticatedSafeBytes); err != nil {
        return nil, err
    }

    pfxData, err := asn1.Marshal(pfxPdu)
    if err != nil {
        return nil, errors.New("go-cryptobin/pkcs12: error writing P12 data: " + err.Error())
    }

    return pfxData, nil
}

// 解析 ber 编码的 PKCS12 证书
// Decode for PKCS12
func Decode(pfxData []byte, password string) (
    privateKey any,
    certificate *x509.Certificate,
    err error,
) {
    data, err := Parse(pfxData, []byte(password))
    if err != nil {
        return
    }

    return cryptobin_pkcs12.Decode(data, password)
}

// 解析 ber 编码的 PKCS12 证书
// DecodeChain for PKCS12
func DecodeChain(pfxData []byte, password string) (
    privateKey any,
    certificate *x509.Certificate,
    caCerts []*x509.Certificate,
    err error,
) {
    data, err := Parse(pfxData, []byte(password))
    if err != nil {
        return
    }

    return cryptobin_pkcs12.DecodeChain(data, password)
}

// 解析 ber 编码的 PKCS12 证书
// DecodeTrustStore for PKCS12
func DecodeTrustStore(pfxData []byte, password string) (certs []*x509.Certificate, err error) {
    data, err := Parse(pfxData, []byte(password))
    if err != nil {
        return
    }

    return cryptobin_pkcs12.DecodeTrustStore(data, password)
}

// 解析 ber 编码的 PKCS12 证书
// DecodeTrustStoreEntries for PKCS12
func DecodeTrustStoreEntries(pfxData []byte, password string) (trustStoreKeys []cryptobin_pkcs12.TrustStoreKey, err error) {
    data, err := Parse(pfxData, []byte(password))
    if err != nil {
        return
    }

    return cryptobin_pkcs12.DecodeTrustStoreEntries(data, password)
}

// 解析 ber 编码的 PKCS12 证书
// DecodeSecret for PKCS12
func DecodeSecret(pfxData []byte, password string) (secretKey []byte, err error) {
    data, err := Parse(pfxData, []byte(password))
    if err != nil {
        return
    }

    return cryptobin_pkcs12.DecodeSecret(data, password)
}

// LoadFromReader loads the key store from the specified file.
func LoadFromReader(reader io.Reader, password string) (*cryptobin_pkcs12.PKCS12, error) {
    buf := bytes.NewBuffer(nil)

    // 保存
    if _, err := io.Copy(buf, reader); err != nil {
        return nil, err
    }

    return LoadFromBytes(buf.Bytes(), password)
}

// LoadFromBytes loads the key store from the bytes data.
func LoadFromBytes(pfxData []byte, password string) (*cryptobin_pkcs12.PKCS12, error) {
    data, err := Parse(pfxData, []byte(password))
    if err != nil {
        return nil, err
    }

    return cryptobin_pkcs12.LoadFromBytes(data, password)
}

// 别名
var (
    // LoadPKCS12 loads the key store from the bytes data.
    LoadPKCS12 = LoadFromBytes

    // LoadPKCS12FromBytes loads the key store from the bytes data.
    LoadPKCS12FromBytes = LoadFromBytes

    // LoadPKCS12FromReader loads the key store from the specified file.
    LoadPKCS12FromReader = LoadFromReader
)
