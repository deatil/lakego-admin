package sm2

import (
    "github.com/deatil/go-cryptobin/gm/sm2"
    "github.com/deatil/go-cryptobin/tool/hash"
)

// 设置 PrivateKey
func (this SM2) WithPrivateKey(data *sm2.PrivateKey) SM2 {
    this.privateKey = data

    return this
}

// 设置 PublicKey
func (this SM2) WithPublicKey(data *sm2.PublicKey) SM2 {
    this.publicKey = data

    return this
}

// 设置 mode
func (this SM2) WithMode(data sm2.Mode) SM2 {
    this.mode = data

    return this
}

// 设置 mode
// C1C3C2 = 0 | C1C2C3 = 1
func (this SM2) SetMode(data string) SM2 {
    switch data {
        case "C1C3C2":
            this.mode = sm2.C1C3C2
        case "C1C2C3":
            this.mode = sm2.C1C2C3
    }

    return this
}

// 设置 data
func (this SM2) WithData(data []byte) SM2 {
    this.data = data

    return this
}

// 设置 parsedData
func (this SM2) WithParsedData(data []byte) SM2 {
    this.parsedData = data

    return this
}

// 设置 hash 类型
func (this SM2) WithSignHash(data HashFunc) SM2 {
    this.signHash = data

    return this
}

// 设置 hash 类型
// 可用参数可查看 Hash 结构体数据
func (this SM2) SetSignHash(data string) SM2 {
    hash, err := hash.GetHash(data)
    if err != nil {
        return this.AppendError(err)
    }

    this.signHash = hash

    return this
}

// 设置 uid
func (this SM2) WithUID(data []byte) SM2 {
    this.uid = data

    return this
}

// 设置 uid
func (this SM2) SetUID(data string) SM2 {
    this.uid = []byte(data)

    return this
}

// 设置编码方式
func (this SM2) WithEncoding(encoding EncodingType) SM2 {
    this.encoding = encoding

    return this
}

// 设置 ASN1 编码方式
func (this SM2) WithEncodingASN1() SM2 {
    return this.WithEncoding(EncodingASN1)
}

// 设置明文编码方式
func (this SM2) WithEncodingBytes() SM2 {
    return this.WithEncoding(EncodingBytes)
}

// 设置 verify
func (this SM2) WithVerify(data bool) SM2 {
    this.verify = data

    return this
}

// 设置错误
func (this SM2) WithErrors(errs []error) SM2 {
    this.Errors = errs

    return this
}
