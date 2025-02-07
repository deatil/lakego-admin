package ca

import (
    "net"
    "time"
    "math/big"
    "math/rand"
    "crypto/x509/pkix"

    "github.com/deatil/go-cryptobin/x509"
)

// 生成 CA 证书
func (this CA) MakeCA(
    subject     pkix.Name,
    expire      int,
    signAlgName string,
) CA {
    signAlg := getSignatureAlgorithm(signAlgName)

    this.cert = &x509.Certificate{
        SerialNumber: big.NewInt(rand.Int63n(time.Now().Unix())),
        Subject:      subject,

        // 生效时间
        NotBefore: time.Now(),
        // 过期时间，年为单位
        NotAfter:  time.Now().AddDate(expire, 0, 0),

        // openssl 中的 extendedKeyUsage = clientAuth, serverAuth 字段
        ExtKeyUsage: []x509.ExtKeyUsage{
            x509.ExtKeyUsageClientAuth,
            x509.ExtKeyUsageServerAuth,
        },
        // openssl 中的 keyUsage 字段
        KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,

        // 表示用于CA
        IsCA:                  true,
        BasicConstraintsValid: true,

        // 签名方式
        SignatureAlgorithm: signAlg,
    }

    return this
}

// 生成证书
func (this CA) MakeCert(
    subject     pkix.Name,
    expire      int,
    dns         []string,
    ip          []net.IP,
    signAlgName string,
) CA {
    signAlg := getSignatureAlgorithm(signAlgName)

    this.cert = &x509.Certificate{
        SerialNumber: big.NewInt(rand.Int63n(time.Now().Unix())),
        Subject:      subject,
        SubjectKeyId: []byte{1, 2, 3, 4, 6},

        IPAddresses:  ip,
        DNSNames:     dns,

        NotBefore: time.Now(),
        // 过期时间，年为单位
        NotAfter:  time.Now().AddDate(expire, 0, 0),

        ExtKeyUsage: []x509.ExtKeyUsage{
            x509.ExtKeyUsageClientAuth,
            x509.ExtKeyUsageServerAuth,
        },
        KeyUsage: x509.KeyUsageDigitalSignature,

        IsCA: false,

        // 签名方式
        SignatureAlgorithm: signAlg,
    }

    return this
}

// 生成证书请求
func (this CA) MakeCSR(
    commonName   string,
    organization []string,
    signAlgName  string,
) CA {
    signAlg := getSignatureAlgorithm(signAlgName)

    this.certRequest = &x509.CertificateRequest{
        Subject: pkix.Name{
            CommonName:   commonName,
            Organization: organization,

            // OrganizationalUnit: organizationalUnit,
            // Country: country,
            // Locality: locality,
            // Province: province,
            // StreetAddress: streetAddress,
            // PostalCode: postalCode,

            // SerialNumber: string,
            // Names: []pkix.AttributeTypeAndValue{}
            // ExtraNames: []pkix.AttributeTypeAndValue{}
        },
        SignatureAlgorithm: signAlg,
    }

    return this
}

// 更新 Cert 数据
func (this CA) UpdateCert(fn func(*x509.Certificate)) CA {
    fn(this.cert)

    return this
}

// 更新证书请求数据
func (this CA) UpdateCertRequest(fn func(*x509.CertificateRequest)) CA {
    fn(this.certRequest)

    return this
}

// 获取签名 alg
func getSignatureAlgorithm(name string) x509.SignatureAlgorithm {
    data := map[string]x509.SignatureAlgorithm {
        "MD2WithRSA":       x509.MD2WithRSA,
        "MD5WithRSA":       x509.MD5WithRSA,
        "SHA1WithRSA":      x509.SHA1WithRSA,
        "SHA256WithRSA":    x509.SHA256WithRSA,
        "SHA384WithRSA":    x509.SHA384WithRSA,
        "SHA512WithRSA":    x509.SHA512WithRSA,
        "SHA256WithRSAPSS": x509.SHA256WithRSAPSS,
        "SHA384WithRSAPSS": x509.SHA384WithRSAPSS,
        "SHA512WithRSAPSS": x509.SHA512WithRSAPSS,
        "PureEd25519":      x509.PureEd25519,
        "DSAWithSHA1":      x509.DSAWithSHA1,
        "DSAWithSHA256":    x509.DSAWithSHA256,
        "ECDSAWithSHA1":    x509.ECDSAWithSHA1,
        "ECDSAWithSHA256":  x509.ECDSAWithSHA256,
        "ECDSAWithSHA384":  x509.ECDSAWithSHA384,
        "ECDSAWithSHA512":  x509.ECDSAWithSHA512,
        "SM2WithSM3":       x509.SM2WithSM3,
        "SM2WithSHA1":      x509.SM2WithSHA1,
        "SM2WithSHA256":    x509.SM2WithSHA256,
        "SM3WithRSA":       x509.SM3WithRSA,
        "GOST3410WithGOST34112001":    x509.GOST3410WithGOST34112001,
        "GOST3410WithGOST34112012256": x509.GOST3410WithGOST34112012256,
        "GOST3410WithGOST34112012512": x509.GOST3410WithGOST34112012512,
        "ElGamalWithSHA1":      x509.ElGamalWithSHA1,
        "ElGamalWithRIPEMD160": x509.ElGamalWithRIPEMD160,
    }

    if alg, ok := data[name]; ok {
        return alg
    }

    return data["SHA256WithRSA"]
}
