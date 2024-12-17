package pkcs12

import (
    "errors"
    "crypto"
    "crypto/x509"
    "crypto/x509/pkix"
    "encoding/pem"
    "encoding/asn1"

    cryptobin_x509 "github.com/deatil/go-cryptobin/x509"
)

func (this *PKCS12) formatCert(certsData []byte) (certs []*x509.Certificate, err error) {
    parsedCerts, err := x509.ParseCertificates(certsData)
    if err != nil {
        gmsmCerts, err := cryptobin_x509.ParseCertificates(certsData)
        if err != nil {
            err = errors.New("go-cryptobin/pkcs12: x509 error: " + err.Error())
            return nil, err
        }

        for _, cert := range gmsmCerts {
            parsedCerts = append(parsedCerts, cert.ToX509Certificate())
        }
    }

    return parsedCerts, nil
}

func (this *PKCS12) parseKeyBag(bag *SafeBag) error {
    bagData := NewSafeBagDataWithAttrs(bag.Value.Bytes, bag.Attributes)
    this.parsedData["privateKey"] = append(this.parsedData["privateKey"], bagData)

    return nil
}

func (this *PKCS12) parsePKCS8ShroundedKeyBag(bag *SafeBag, password []byte) error {
    pkData, err := this.decodePKCS8ShroudedKeyBag(bag.Value.Bytes, password)
    if err != nil {
        return err
    }

    bagData := NewSafeBagDataWithAttrs(pkData, bag.Attributes)
    this.parsedData["privateKey"] = append(this.parsedData["privateKey"], bagData)

    return nil
}

func (this *PKCS12) parseCertBag(bag *SafeBag) error {
    newCertBagEntry := NewCertBagEntry()

    certsData, err := newCertBagEntry.DecodeCertBag(bag.Value.Bytes)
    if err != nil {
        return err
    }

    bagData := NewSafeBagDataWithAttrs(certsData, bag.Attributes)

    switch {
        case bag.hasAttribute(oidJavaTrustStore):
            this.parsedData["trustStore"] = append(this.parsedData["trustStore"], bagData)

        case bag.hasAttribute(oidLocalKeyID):
            certType := newCertBagEntry.GetType()

            switch certType {
                case CertTypeX509:
                    this.parsedData["cert"] = append(this.parsedData["cert"], bagData)
                case CertTypeSdsi:
                    this.parsedData["sdsiCert"] = append(this.parsedData["sdsiCert"], bagData)
            }

        default:
            this.parsedData["caCert"] = append(this.parsedData["caCert"], bagData)

    }

    return nil
}

func (this *PKCS12) parseCRLBag(bag *SafeBag) error {
    crlData, err := NewCRLBagEntry().DecodeCertBag(bag.Value.Bytes)
    if err != nil {
        return err
    }

    bagData := NewSafeBagDataWithAttrs(crlData, bag.Attributes)
    this.parsedData["crl"] = append(this.parsedData["crl"], bagData)

    return nil
}

func (this *PKCS12) parseSecretBag(bag *SafeBag, password []byte) error {
    bagData := &SafeBagData{}

    data, err := this.decodeSecretBag(bag.Value.Bytes, password)
    if err != nil {
        return err
    }

    bagData.data = data
    bagData.attrs = NewPKCS12Attributes(bag.Attributes)

    this.parsedData["secretKey"] = append(this.parsedData["secretKey"], bagData)

    return nil
}

func (this *PKCS12) parseUnknowBag(bag *SafeBag) error {
    bag.Attributes = append(bag.Attributes, PKCS12Attribute{
        Id: bag.Id,
        Value: asn1.RawValue{
            Bytes: []byte("unknowOid"),
        },
    })

    bagData := &SafeBagData{}
    bagData.data = bag.Value.Bytes
    bagData.attrs = NewPKCS12Attributes(bag.Attributes)

    this.parsedData["unknow"] = append(this.parsedData["unknow"], bagData)

    return nil
}

// 解析
func (this *PKCS12) Parse(pfxData []byte, password string) (*PKCS12, error) {
    encodedPassword, err := bmpStringZeroTerminated(password)
    if err != nil {
        return nil, err
    }

    bags, encodedPassword, err := this.getSafeContents(pfxData, encodedPassword)
    if err != nil {
        return nil, err
    }

    for _, bag := range bags {
        switch {
            case bag.Id.Equal(oidKeyBag):
                this.parseKeyBag(&bag)

            case bag.Id.Equal(oidPKCS8ShroundedKeyBag):
                this.parsePKCS8ShroundedKeyBag(&bag, encodedPassword)

            case bag.Id.Equal(oidCertBag):
                this.parseCertBag(&bag)

            case bag.Id.Equal(oidCRLBag):
                this.parseCRLBag(&bag)

            case bag.Id.Equal(oidSecretBag):
                this.parseSecretBag(&bag, encodedPassword)

            default:
                this.parseUnknowBag(&bag)
        }
    }

    return this, nil
}

//===============

func (this *PKCS12) GetPrivateKey() (prikey crypto.PrivateKey, attrs PKCS12Attributes, err error) {
    privateKeys, ok := this.parsedData["privateKey"]
    if !ok {
        err = errors.New("no data")
        return
    }

    if len(privateKeys) == 0 {
        err = errors.New("no data")
        return
    }

    privateKey := privateKeys[0].Data()

    parsedKey, err := ParsePKCS8PrivateKey(privateKey)
    if err != nil {
        return
    }

    return parsedKey, privateKeys[0].Attrs(), nil
}

func (this *PKCS12) GetPrivateKeyBytes() (prikey []byte, attrs PKCS12Attributes, err error) {
    privateKeys, ok := this.parsedData["privateKey"]
    if !ok {
        err = errors.New("no data")
        return
    }

    if len(privateKeys) == 0 {
        err = errors.New("no data")
        return
    }

    return privateKeys[0].Data(), privateKeys[0].Attrs(), nil
}

func (this *PKCS12) GetCert() (cert *x509.Certificate, attrs PKCS12Attributes, err error) {
    certs, ok := this.parsedData["cert"]
    if !ok {
        err = errors.New("no data")
        return
    }

    if len(certs) == 0 {
        err = errors.New("no data")
        return
    }

    certData := certs[0].Data()

    parsedCerts, err := this.formatCert(certData)
    if err != nil {
        return
    }

    return parsedCerts[0], certs[0].Attrs(), nil
}

func (this *PKCS12) GetCertBytes() (cert []byte, attrs PKCS12Attributes, err error) {
    certs, ok := this.parsedData["cert"]
    if !ok {
        err = errors.New("no data")
        return
    }

    if len(certs) == 0 {
        err = errors.New("no data")
        return
    }

    return certs[0].Data(), certs[0].Attrs(), nil
}

func (this *PKCS12) GetCaCerts() (caCerts []*x509.Certificate, err error) {
    certs, ok := this.parsedData["caCert"]
    if !ok {
        err = errors.New("no data")
        return
    }

    if len(certs) == 0 {
        err = errors.New("no data")
        return
    }

    for _, cert := range certs {
        c := cert.Data()

        parsedCerts, err := this.formatCert(c)
        if err != nil {
            return nil, err
        }

        caCerts = append(caCerts, parsedCerts[0])
    }

    return caCerts, nil
}

func (this *PKCS12) GetCaCertsBytes() (caCerts [][]byte, err error) {
    certs, ok := this.parsedData["caCert"]
    if !ok {
        err = errors.New("no data")
        return
    }

    if len(certs) == 0 {
        err = errors.New("no data")
        return
    }

    for _, cert := range certs {
        caCerts = append(caCerts, cert.Data())
    }

    return caCerts, nil
}

func (this *PKCS12) GetTrustStores() (trustStores []*x509.Certificate, err error) {
    certs, ok := this.parsedData["trustStore"]
    if !ok {
        err = errors.New("no data")
        return
    }

    if len(certs) == 0 {
        err = errors.New("no data")
        return
    }

    for _, cert := range certs {
        parsedCerts, err := this.formatCert(cert.Data())
        if err != nil {
            return nil, err
        }

        trustStores = append(trustStores, parsedCerts[0])
    }

    return trustStores, nil
}

func (this *PKCS12) GetTrustStoresBytes() (trustStores [][]byte, err error) {
    certs, ok := this.parsedData["trustStore"]
    if !ok {
        err = errors.New("no data")
        return
    }

    if len(certs) == 0 {
        err = errors.New("no data")
        return
    }

    for _, cert := range certs {
        trustStores = append(trustStores, cert.Data())
    }

    return trustStores, nil
}

type trustStoreKeyData struct {
    Attrs PKCS12Attributes
    Cert  *x509.Certificate
}

func (this *PKCS12) GetTrustStoreEntries() (trustStores []trustStoreKeyData, err error) {
    certs, ok := this.parsedData["trustStore"]
    if !ok {
        err = errors.New("no data")
        return
    }

    if len(certs) == 0 {
        err = errors.New("no data")
        return
    }

    for _, cert := range certs {
        parsedCerts, err := this.formatCert(cert.Data())
        if err != nil {
            return nil, err
        }

        trustStores = append(trustStores, trustStoreKeyData{
            Attrs: cert.Attrs(),
            Cert:  parsedCerts[0],
        })
    }

    return trustStores, nil
}

type trustStoreKeyDataBytes struct {
    Attrs PKCS12Attributes
    Cert  []byte
}

func (this *PKCS12) GetTrustStoreEntriesBytes() (trustStores []trustStoreKeyDataBytes, err error) {
    certs, ok := this.parsedData["trustStore"]
    if !ok {
        err = errors.New("no data")
        return
    }

    if len(certs) == 0 {
        err = errors.New("no data")
        return
    }

    for _, cert := range certs {
        trustStores = append(trustStores, trustStoreKeyDataBytes{
            Attrs: cert.Attrs(),
            Cert:  cert.Data(),
        })
    }

    return trustStores, nil
}

func (this *PKCS12) GetSdsiCertBytes() (cert []byte, attrs PKCS12Attributes, err error) {
    sdsiCerts, ok := this.parsedData["sdsiCert"]
    if !ok {
        err = errors.New("no data")
        return
    }

    if len(sdsiCerts) == 0 {
        err = errors.New("no data")
        return
    }

    return sdsiCerts[0].Data(), sdsiCerts[0].Attrs(), nil
}

func (this *PKCS12) GetCRL() (crl *pkix.CertificateList, attrs PKCS12Attributes, err error) {
    crls, ok := this.parsedData["crl"]
    if !ok {
        err = errors.New("no data")
        return
    }

    if len(crls) == 0 {
        err = errors.New("no data")
        return
    }

    crlBytes := crls[0].Data()

    parsedCRL, err := x509.ParseDERCRL(crlBytes)
    if err != nil {
        return
    }

    return parsedCRL, crls[0].Attrs(), nil
}

func (this *PKCS12) GetCRLBytes() (crl []byte, attrs PKCS12Attributes, err error) {
    crls, ok := this.parsedData["crl"]
    if !ok {
        err = errors.New("no data")
        return
    }

    if len(crls) == 0 {
        err = errors.New("no data")
        return
    }

    return crls[0].Data(), crls[0].Attrs(), nil
}

func (this *PKCS12) GetSecretKey() (secretKey []byte, attrs PKCS12Attributes, err error) {
    keys, ok := this.parsedData["secretKey"]
    if !ok {
        err = errors.New("no data")
        return
    }

    if len(keys) == 0 {
        err = errors.New("no data")
        return
    }

    return keys[0].Data(), keys[0].Attrs(), nil
}

type unknowDataBytes struct {
    Attrs PKCS12Attributes
    Data  []byte
}

func (this *PKCS12) GetUnknowsBytes() (unknowDatas []unknowDataBytes, err error) {
    unknows, ok := this.parsedData["unknow"]
    if !ok {
        err = errors.New("no data")
        return
    }

    if len(unknows) == 0 {
        err = errors.New("no data")
        return
    }

    for _, unknow := range unknows {
        unknowDatas = append(unknowDatas, unknowDataBytes{
            Attrs: unknow.Attrs(),
            Data:  unknow.Data(),
        })
    }

    return unknowDatas, nil
}

//===============

func (this *PKCS12) hasData(name string) bool {
    datas, ok := this.parsedData[name]
    if !ok {
        return false
    }

    if len(datas) == 0 {
        return false
    }

    return true
}

func (this *PKCS12) HasPrivateKey() bool {
    return this.hasData("privateKey")
}

func (this *PKCS12) HasCert() bool {
    return this.hasData("cert")
}

func (this *PKCS12) HasCaCert() bool {
    return this.hasData("caCert")
}

func (this *PKCS12) HasTrustStore() bool {
    return this.hasData("trustStore")
}

func (this *PKCS12) HasSdsiCert() bool {
    return this.hasData("sdsiCert")
}

func (this *PKCS12) HasCRL() bool {
    return this.hasData("crl")
}

func (this *PKCS12) HasSecretKey() bool {
    return this.hasData("secretKey")
}

func (this *PKCS12) HasUnknow() bool {
    return this.hasData("unknow")
}

//===============

func (this *PKCS12) makeBlock(typ string, data []byte, attrs PKCS12Attributes) *pem.Block {
    block := &pem.Block{
        Headers: make(map[string]string),
    }

    block.Headers = attrs.ToArray()
    block.Type = typ
    block.Bytes = data

    return block
}

// 生成PEM证书
func (this *PKCS12) ToPEM() ([]*pem.Block, error) {
    blocks := make([]*pem.Block, 0)

    // 私钥
    prikey, attrs, err := this.GetPrivateKey()
    if err == nil {
        priBytes, err := MarshalPrivateKey(prikey)
        if err != nil {
            return nil, errors.New("found unknown private key type in PKCS#8 wrapping: " + err.Error())
        }

        priBlock := this.makeBlock(PrivateKeyType, priBytes, attrs)

        blocks = append(blocks, priBlock)
    }

    // 证书
    cert, attrs, err := this.GetCert()
    if err == nil {
        certBlock := this.makeBlock(CertificateType, cert.Raw, attrs)

        blocks = append(blocks, certBlock)
    }

    // 证书链
    caCerts, _ := this.GetCaCerts()
    for _, caCert := range caCerts {
        caCertBlock := this.makeBlock(CertificateType, caCert.Raw, NewPKCS12AttributesEmpty())

        blocks = append(blocks, caCertBlock)
    }

    // JAVA 证书链
    trustStores, _ := this.GetTrustStoreEntries()
    for _, entry := range trustStores {
        trustBlock := this.makeBlock(CertificateType, entry.Cert.Raw, entry.Attrs)

        blocks = append(blocks, trustBlock)
    }

    // CRL
    crl, attrs, err := this.GetCRLBytes()
    if err == nil {
        crlBlock := this.makeBlock(CRLType, crl, attrs)

        blocks = append(blocks, crlBlock)
    }

    return blocks, nil
}

// 生成原始数据的PEM证书
func (this *PKCS12) ToOriginalPEM() ([]*pem.Block, error) {
    blocks := make([]*pem.Block, 0)

    // 私钥
    prikey, attrs, err := this.GetPrivateKeyBytes()
    if err == nil {
        priBlock := this.makeBlock(PrivateKeyType, prikey, attrs)

        blocks = append(blocks, priBlock)
    }

    // 证书
    cert, attrs, err := this.GetCertBytes()
    if err == nil {
        certBlock := this.makeBlock(CertificateType, cert, attrs)

        blocks = append(blocks, certBlock)
    }

    // 证书链
    caCerts, _ := this.GetCaCertsBytes()
    for _, caCert := range caCerts {
        caCertBlock := this.makeBlock(CertificateType, caCert, NewPKCS12AttributesEmpty())

        blocks = append(blocks, caCertBlock)
    }

    // JAVA 证书链
    trustStores, _ := this.GetTrustStoreEntriesBytes()
    for _, entry := range trustStores {
        trustBlock := this.makeBlock(CertificateType, entry.Cert, entry.Attrs)

        blocks = append(blocks, trustBlock)
    }

    // CRL
    crl, attrs, err := this.GetCRLBytes()
    if err == nil {
        crlBlock := this.makeBlock(CRLType, crl, attrs)

        blocks = append(blocks, crlBlock)
    }

    return blocks, nil
}
