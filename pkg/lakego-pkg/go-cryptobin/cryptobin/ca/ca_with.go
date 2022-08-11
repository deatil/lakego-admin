package ca

// 设置 cert
// 可用 [*x509.Certificate | *sm2X509.Certificate]
func (this CA) WithCert(data any) CA {
    this.cert = data

    return this
}

// 设置 certRequest
// 可用 [*x509.CertificateRequest | *sm2X509.CertificateRequest]
func (this CA) WithCertRequest(data any) CA {
    this.certRequest = data

    return this
}

// 设置 PrivateKey
func (this CA) WithPrivateKey(data any) CA {
    this.privateKey = data

    return this
}

// 设置 publicKey
func (this CA) WithPublicKey(data any) CA {
    this.publicKey = data

    return this
}

// 设置 keyData
func (this CA) WithKeyData(data []byte) CA {
    this.keyData = data

    return this
}

// 设置错误
func (this CA) WithErrors(errs []error) CA {
    this.Errors = errs

    return this
}

// 添加错误
func (this CA) AppendError(err ...error) CA {
    this.Errors = append(this.Errors, err...)

    return this
}
