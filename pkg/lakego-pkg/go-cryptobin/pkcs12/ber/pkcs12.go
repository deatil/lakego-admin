package ber

import (
    "errors"
    "encoding/asn1"
    "crypto/x509"
    "crypto/x509/pkix"

    "github.com/deatil/go-cryptobin/tool"
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
type digestInfo struct {
    Algorithm AlgorithmIdentifier
    Digest    []byte
}

type macData struct {
    Mac        digestInfo
    MacSalt    []byte
    Iterations int `asn1:"optional,default:1"`
}

func (this macData) Verify(message []byte, password []byte) error {
    mac := cryptobin_pkcs12.MacData{
        Mac: cryptobin_pkcs12.DigestInfo{
            Algorithm: pkix.AlgorithmIdentifier{
                Algorithm:  asn1.ObjectIdentifier(this.Mac.Algorithm.Algorithm),
                Parameters: asn1.RawValue{
                    Tag: asn1.TagNull,
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
    MacData  macData `asn1:"optional"`
}

type encryptedData struct {
    Version              int
    EncryptedContentInfo struct {
        ContentType                cryptobin_asn1.ObjectIdentifier
        ContentEncryptionAlgorithm AlgorithmIdentifier
        EncryptedContent           cryptobin_asn1.RawValue `asn1:"tag:0,optional"`
    }
}

type encryptedDataDer struct {
    Version              int
    EncryptedContentInfo struct {
        ContentType                asn1.ObjectIdentifier
        ContentEncryptionAlgorithm pkix.AlgorithmIdentifier
        EncryptedContent           []byte `asn1:"tag:0,optional"`
    }
}

// 转换 BER 编码的 PKCS12 证书为 DER 编码
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

    data := pfx.AuthSafe.Content.Bytes

    var authenticatedSafes = make([]cryptobin_asn1.RawValue, 0)

    for {
        var authenticatedSafe cryptobin_asn1.RawValue
        data, err = cryptobin_asn1.Unmarshal(data, &authenticatedSafe)
        if err != nil {
            return nil, errors.New("Unmarshal octet err: " + err.Error())
        }

        authenticatedSafes = append(authenticatedSafes, authenticatedSafe)

        if len(data) == 0 {
            break
        }
    }

    checkData := make([]byte, 0)
    for _, as := range authenticatedSafes {
        checkData = append(checkData, as.Bytes...)
    }

    password, err = tool.BmpStringZeroTerminated(string(password))
    if err != nil {
        return nil, err
    }

    if len(pfx.MacData.Mac.Algorithm.Algorithm) == 0 {
        if !(len(password) == 2 && password[0] == 0 && password[1] == 0) {
            return nil, errors.New("pkcs12: no MAC in data")
        }
    } else {
        if err := pfx.MacData.Verify(checkData, password); err != nil {
            if err == cryptobin_pkcs12.ErrIncorrectPassword && len(password) == 2 && password[0] == 0 && password[1] == 0 {
                password = nil
                err = pfx.MacData.Verify(checkData, password)
            }

            if err != nil {
                return nil, err
            }
        }
    }

    var contentInfos []ContentInfo
    _, err = cryptobin_asn1.Unmarshal(checkData, &contentInfos)
    if err != nil {
        return nil, err
    }

    newContentInfos := make([]cryptobin_pkcs12.ContentInfo, 0)
    for _, ci := range contentInfos {
        var newBytes []byte

        if ci.ContentType.Equal(oidDataContentType) {
            var data1 cryptobin_asn1.RawValue
            if _, err = cryptobin_asn1.Unmarshal(ci.Content.Bytes, &data1); err != nil {
                return nil, err
            }

            newBytes = data1.Bytes
        } else {
            var data1 encryptedData
            if _, err = cryptobin_asn1.Unmarshal(ci.Content.Bytes, &data1); err != nil {
                return nil, err
            }

            var data2 cryptobin_asn1.RawValue
            if _, err = cryptobin_asn1.Unmarshal(data1.EncryptedContentInfo.EncryptedContent.Bytes, &data2); err != nil {
                return nil, err
            }

            var newData encryptedDataDer
            newData.Version = data1.Version
            newData.EncryptedContentInfo.ContentType = asn1.ObjectIdentifier(data1.EncryptedContentInfo.ContentType)
            newData.EncryptedContentInfo.ContentEncryptionAlgorithm = pkix.AlgorithmIdentifier{
                Algorithm: asn1.ObjectIdentifier(data1.EncryptedContentInfo.ContentEncryptionAlgorithm.Algorithm),
                Parameters: asn1.RawValue{
                    FullBytes: data1.EncryptedContentInfo.ContentEncryptionAlgorithm.Parameters.FullBytes,
                },
            }
            newData.EncryptedContentInfo.EncryptedContent = data2.Bytes

            if newBytes, err = asn1.Marshal(newData); err != nil {
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

    // mac
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

    // AuthSafe
    pfxPdu.AuthSafe.ContentType = asn1.ObjectIdentifier(oidDataContentType)
    pfxPdu.AuthSafe.Content.Class = 2
    pfxPdu.AuthSafe.Content.Tag = 0
    pfxPdu.AuthSafe.Content.IsCompound = true
    if pfxPdu.AuthSafe.Content.Bytes, err = asn1.Marshal(authenticatedSafeBytes); err != nil {
        return nil, err
    }

    pfxData, err := asn1.Marshal(pfxPdu)
    if err != nil {
        return nil, errors.New("pkcs12: error writing P12 data: " + err.Error())
    }

    return pfxData, nil
}

// 解析 ber 编码的 PKCS12 证书
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
func DecodeTrustStore(pfxData []byte, password string) (certs []*x509.Certificate, err error) {
    data, err := Parse(pfxData, []byte(password))
    if err != nil {
        return
    }

    return cryptobin_pkcs12.DecodeTrustStore(data, password)
}

// 解析 ber 编码的 PKCS12 证书
func DecodeTrustStoreEntries(pfxData []byte, password string) (trustStoreKeys []cryptobin_pkcs12.TrustStoreKey, err error) {
    data, err := Parse(pfxData, []byte(password))
    if err != nil {
        return
    }

    return cryptobin_pkcs12.DecodeTrustStoreEntries(data, password)
}

// 解析 ber 编码的 PKCS12 证书
func DecodeSecret(pfxData []byte, password string) (secretKeys []cryptobin_pkcs12.SecretKey, err error) {
    data, err := Parse(pfxData, []byte(password))
    if err != nil {
        return
    }

    return cryptobin_pkcs12.DecodeSecret(data, password)
}
