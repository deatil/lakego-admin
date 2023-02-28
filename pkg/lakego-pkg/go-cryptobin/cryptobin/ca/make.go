package ca

import (
    "net"
    "time"
    "math/big"
    "math/rand"
    "crypto/x509"
    "crypto/x509/pkix"
)

// 生成证书请求
func (this CA) MakeCSR(
    country []string,
    organization []string,
    organizationalUnit []string,
    locality []string,
    province []string,
    streetAddress []string,
    postalCode []string,
    commonName string,
) CA {
    this.certRequest = &x509.CertificateRequest{
        Subject: pkix.Name{
            Country: country,
            Organization: organization,
            OrganizationalUnit: organizationalUnit,
            Locality: locality,
            Province: province,
            StreetAddress: streetAddress,
            PostalCode: postalCode,
            CommonName: commonName,

            // SerialNumber: string,
            // Names: []pkix.AttributeTypeAndValue{}
            // ExtraNames: []pkix.AttributeTypeAndValue{}
        },
    }

    return this
}


// 生成 CA 证书
func (this CA) MakeCA(
    subject *pkix.Name,
    expire int,
    signAlgName string,
) CA {
    signAlg := this.GetSignatureAlgorithm(signAlgName)

    this.cert = &x509.Certificate{
        SerialNumber: big.NewInt(rand.Int63n(time.Now().Unix())),
        Subject:      *subject,

        // 生效时间
        NotBefore:    time.Now(),
        // 过期时间，年为单位
        NotAfter:     time.Now().AddDate(expire, 0, 0),

        // openssl 中的 extendedKeyUsage = clientAuth, serverAuth 字段
        ExtKeyUsage:  []x509.ExtKeyUsage{
            x509.ExtKeyUsageClientAuth,
            x509.ExtKeyUsageServerAuth,
        },
        // openssl 中的 keyUsage 字段
        KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,

        // 表示用于CA
        IsCA:                  true,
        BasicConstraintsValid: true,

        // 签名方式
        SignatureAlgorithm: signAlg,
    }

    return this
}

// 生成自签名证书
func (this CA) MakeCert(
    subject *pkix.Name,
    expire int,
    dns []string,
    ip []net.IP,
    signAlgName string,
) CA {
    signAlg := this.GetSignatureAlgorithm(signAlgName)

    this.cert = &x509.Certificate{
        SerialNumber: big.NewInt(rand.Int63n(time.Now().Unix())),
        Subject:      *subject,
        SubjectKeyId: []byte{1, 2, 3, 4, 6},

        IPAddresses:  ip,
        DNSNames:     dns,

        NotBefore:    time.Now(),
        // 过期时间，年为单位
        NotAfter:     time.Now().AddDate(expire, 0, 0),

        ExtKeyUsage:  []x509.ExtKeyUsage{
            x509.ExtKeyUsageClientAuth,
            x509.ExtKeyUsageServerAuth,
        },
        KeyUsage:     x509.KeyUsageDigitalSignature,

        // 签名方式
        SignatureAlgorithm: signAlg,
    }

    return this
}

// 更新 Cert 数据
func (this CA) UpdateCert(fn func(*x509.Certificate) *x509.Certificate) CA {
    this.cert = fn(this.cert.(*x509.Certificate))

    return this
}

// 更新证书请求数据
func (this CA) UpdateCertRequest(fn func(*x509.CertificateRequest) *x509.CertificateRequest) CA {
    this.certRequest = fn(this.certRequest.(*x509.CertificateRequest))

    return this
}
