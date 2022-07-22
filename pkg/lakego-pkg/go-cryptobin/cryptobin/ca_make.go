package cryptobin

import (
    "net"
    "time"
    "math/big"
    "math/rand"
    "crypto/x509"
    "crypto/x509/pkix"
)

type (
    // Subject 数据
    /*
    type Name struct {
        Country            []string
        Organization       []string
        OrganizationalUnit []string
        Locality           []string
        Province           []string
        StreetAddress      []string
        PostalCode         []string
        SerialNumber       string
        CommonName         string
        Names              []AttributeTypeAndValue
        ExtraNames         []AttributeTypeAndValue
    }
    subj := &pkix.Name{
        CommonName:    "chinamobile.com",
        Organization:  []string{"Company, INC."},
        Country:       []string{"US"},
        Province:      []string{""},
        Locality:      []string{"San Francisco"},
        StreetAddress: []string{"Golden Gate Bridge"},
        PostalCode:    []string{"94016"},
    }
    */
    CAPkixName = pkix.Name
)

// 生成 CA
func (this CA) MakeCa(subject *pkix.Name, expire int) CA {
    this.csr = &x509.Certificate{
        SerialNumber: big.NewInt(rand.Int63n(2000)),
        Subject:      *subject,
        // 生效时间
        NotBefore:    time.Now(),
        // 过期时间，年为单位
        NotAfter:     time.Now().AddDate(expire, 0, 0),
        // 表示用于CA
        IsCA:         true,
        // openssl 中的 extendedKeyUsage = clientAuth, serverAuth 字段
        ExtKeyUsage:  []x509.ExtKeyUsage{
            x509.ExtKeyUsageClientAuth,
            x509.ExtKeyUsageServerAuth,
        },
        // openssl 中的 keyUsage 字段
        KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
        BasicConstraintsValid: true,
    }

    return this
}

// 生成 TLS
func (this CA) MakeTLS(subject *pkix.Name, expire int, dns []string, ip []net.IP) CA {
    this.csr = &x509.Certificate{
        SerialNumber: big.NewInt(rand.Int63n(2000)),
        Subject:      *subject,
        IPAddresses:  ip,
        DNSNames:     dns,
        NotBefore:    time.Now(),
        // 过期时间，年为单位
        NotAfter:     time.Now().AddDate(expire, 0, 0),
        SubjectKeyId: []byte{1, 2, 3, 4, 6},
        ExtKeyUsage:  []x509.ExtKeyUsage{
            x509.ExtKeyUsageClientAuth,
            x509.ExtKeyUsageServerAuth,
        },
        KeyUsage:     x509.KeyUsageDigitalSignature,
    }

    return this
}
