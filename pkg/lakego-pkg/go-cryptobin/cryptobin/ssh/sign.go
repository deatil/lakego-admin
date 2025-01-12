package ecgdsa

import (
    "errors"
    "crypto/rand"
    "encoding/pem"

    crypto_ssh "golang.org/x/crypto/ssh"

    "github.com/deatil/go-cryptobin/ssh"
)

// 私钥签名 ASN1
func (this SSH) Sign() SSH {
    if this.privateKey == nil {
        err := errors.New("privateKey empty.")
        return this.AppendError(err)
    }

    signer, err := ssh.NewSignerFromKey(this.privateKey)
    if err != nil {
        return this.AppendError(err)
    }

    sig, err := signer.Sign(rand.Reader, this.data)
    if err != nil {
        return this.AppendError(err)
    }

    sigBlock := &pem.Block{
        Type: "OPENSSH SIGNATURE",
        Headers: map[string]string{
            "Format": sig.Format,
        },
        Bytes: sig.Blob,
    }

    this.parsedData = pem.EncodeToMemory(sigBlock)

    return this.AppendError(err)
}

// 公钥验证 ASN1
// 使用原始数据[data]对比签名后数据
func (this SSH) Verify(data []byte) SSH {
    if this.publicKey == nil {
        err := errors.New("publicKey empty.")
        return this.AppendError(err)
    }

    block, _ := pem.Decode(this.data)
    if block == nil {
        err := errors.New("Signature error.")
        return this.AppendError(err)
    }

    format, ok := block.Headers["Format"]
    if !ok {
        err := errors.New("Signature Format error.")
        return this.AppendError(err)
    }

    pubkey, err := ssh.NewPublicKey(this.publicKey)
    if err != nil {
        return this.AppendError(err)
    }

    err = pubkey.Verify(data, &crypto_ssh.Signature{
        Format: format,
        Blob:   block.Bytes,
    })

    if err == nil {
        this.verify = true
    }

    return this
}
