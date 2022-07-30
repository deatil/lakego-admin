### CA 证书相关

* 使用
~~~go
package main

import (
    "fmt"

    cryptobin "github.com/deatil/go-cryptobin/cryptobin/ca"
    "github.com/deatil/lakego-filesystem/filesystem"
)

func main() {
    // 文件管理器
    fs := filesystem.New()

    // ca 证书生成
    caSubj := &cryptobin.CAPkixName{
        CommonName:    "github.com",
        Organization:  []string{"Company, INC."},
        Country:       []string{"US"},
        Province:      []string{""},
        Locality:      []string{"San Francisco"},
        StreetAddress: []string{"Golden Gate Bridge"},
        PostalCode:    []string{"94016"},
    }
    ca := cryptobin.NewCA().GenerateRsaKey(4096)
    ca1KeyString := ca.CreatePrivateKey().ToKeyString()

    // ca
    ca1 := ca.MakeCA(caSubj, 1, "SHA256WithRSA")
    ca1String := ca1.CreateCA().ToKeyString()

    // tls
    ca1Csr := ca1.GetCert()
    ca2 := ca.MakeCert(caSubj, 1, []string{"test.default.svc", "test"}, []net.IP{}, "SHA256WithRSA")
    ca2String := ca2.CreateCert(ca1Csr).ToKeyString()

    // fs.Put("./runtime/key/ca.cst", ca1String)
    // fs.Put("./runtime/key/ca.key", ca1KeyString)
    // fs.Put("./runtime/key/ca_tls.cst", ca2String)
    // fs.Put("./runtime/key/ca_tls.key", ca2KeyString)

    // =====

    // pkcs12 证书生成
    caSubj := &cryptobin.CAPkixName{
        CommonName:    "github.com",
        Organization:  []string{"Company, INC."},
        Country:       []string{"US"},
        Province:      []string{""},
        Locality:      []string{"San Francisco"},
        StreetAddress: []string{"Golden Gate Bridge"},
        PostalCode:    []string{"94016"},
    }
    ca := cryptobin.NewCA().GenerateSM2Key()
    cert := ca.MakeSM2Cert(caSubj, 1, []string{"test.default.svc", "test"}, []net.IP{}, "SM2WithSHA1")

    pkcs12Data := cert.CreatePKCS12Cert(nil, "123456").ToKeyString()

    // fs.Put("./runtime/key/ec-pkcs12.pfx", pkcs12Data)

    // =====

    // pkcs12 证书生成2
    str := "MIICiTCCAi6gAwIBAgIIICAEFwACVjAwCgYIKoEcz1UBg3UwdjEcMBoGA1UEAwwTU21hcnRDQV9UZXN0X1NNMl9DQTEVMBMGA1UECwwMU21hcnRDQV9UZXN0MRAwDgYDVQQKDAdTbWFydENBMQ8wDQYDVQQHDAbljZfkuqwxDzANBgNVBAgMBuaxn+iLjzELMAkGA1UEBhMCQ04wHhcNMjAwNDE3MDYwNjA4WhcNMTkwOTAzMDE1MzE5WjCBrjFGMEQGA1UELQw9YXBpX2NhX1RFU1RfVE9fUEhfUkFfVE9OR0pJX2FlNTA3MGNiY2E4NTQyYzliYmJmOTRmZjcwNThkNmEzMTELMAkGA1UEBhMCQ04xDTALBgNVBAgMBG51bGwxDTALBgNVBAcMBG51bGwxFTATBgNVBAoMDENGQ0FTTTJBR0VOVDENMAsGA1UECwwEbnVsbDETMBEGA1UEAwwKY2hlbnh1QDEwNDBZMBMGByqGSM49AgEGCCqBHM9VAYItA0IABAWeikXULbz1RqgmVzJWtSDMa3f9wirzwnceb1WIWxTqJaY+3xNlsM63oaIKJCD6pZu14EDkLS0FTP1uX3EySOajbTBrMAsGA1UdDwQEAwIGwDAdBgNVHQ4EFgQUbMrrNQDS1B1yjyrkgq2FWGi5zRcwHwYDVR0jBBgwFoAUXPO6JYzCZQzsZ+++3Y1rp16v46wwDAYDVR0TBAUwAwEB/zAOBggqgRzQFAQBAQQCBQAwCgYIKoEcz1UBg3UDSQAwRgIhAMcbwSDvL78qDSoqQh/019EEk4UNHP7zko0t1GueffTnAiEAupHr3k4vWSWV1SEqds+q8u4CbRuuRDvBOQ6od8vGzjM="
    decodeString := encoding.Base64Decode(str)
    x, _ := x509.ParseCertificate([]byte(decodeString))

    ca := cryptobin.NewCA().GenerateSM2Key()
    ca = ca.WithCert(x)

    pkcs12Data := ca.CreatePKCS12Cert(nil, "123456").ToKeyString()

    // fs.Put("./runtime/key/ec-pkcs12.pfx", pkcs12Data)

    // =====

    // pkcs12 证书生成2
    caSubj := &cryptobin.CAPkixName{
        CommonName:    "github.com",
        Organization:  []string{"Company, INC."},
        Country:       []string{"US"},
        Province:      []string{""},
        Locality:      []string{"San Francisco"},
        StreetAddress: []string{"Golden Gate Bridge"},
        PostalCode:    []string{"94016"},
    }
    ca := cryptobin.NewCA().GenerateEcdsaKey("P256")
    cert := ca.MakeCert(caSubj, 1, []string{"test.default.svc", "test"}, []net.IP{}, "ECDSAWithSHA256")

    pkcs12Data := cert.CreatePKCS12Cert(nil, "123456").ToKeyString()

    fs.Put("./runtime/key/ec-pkcs12.pfx", pkcs12Data)

    // =====

    // pkcs12 证书解析
    pfxData, _ := fs.Get("./runtime/key/sm2-pkcs12.pfx")
    ca := cryptobin.NewCA().FromSM2PKCS12OneCert([]byte(pfxData), "123456")
    pkcs12PrivData := ca.CreatePrivateKey().ToKeyString()


}
~~~
