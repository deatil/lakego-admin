package sm2

import (
    "github.com/tjfoc/gmsm/sm2"
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
func (this SM2) WithMode(data int) SM2 {
    this.mode = data

    return this
}

// 设置 mode
// C1C3C2 | C1C2C3
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

// 设置 paredData
func (this SM2) WithParedData(data []byte) SM2 {
    this.paredData = data

    return this
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

// 添加错误
func (this SM2) AppendError(errs ...error) SM2 {
    this.Errors = append(this.Errors, errs...)

    return this
}
