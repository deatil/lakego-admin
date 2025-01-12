package ecgdsa

import (
    "errors"
    "crypto/rand"
    "encoding/pem"

    "github.com/deatil/go-cryptobin/ssh"
)

type (
    // 配置
    Opts = ssh.Opts
)

var (
    // get Cipher
    GetCipherFromName = ssh.GetCipherFromName

    // Default options
    DefaultOpts = ssh.DefaultOpts
)

// 生成私钥 pem 数据
func (this SSH) CreatePrivateKey() SSH {
    return this.CreateOpensshPrivateKey()
}

// 生成私钥带密码 pem 数据, PKCS1 别名
func (this SSH) CreatePrivateKeyWithPassword(password []byte, opts ...Opts) SSH {
    return this.CreateOpensshPrivateKeyWithPassword(password, opts...)
}

// 生成公钥 pem 数据
func (this SSH) CreatePublicKey() SSH {
    return this.CreateOpensshPublicKey()
}

// ====================

// 生成私钥 pem 数据
func (this SSH) CreateOpensshPrivateKey() SSH {
    if this.privateKey == nil {
        err := errors.New("privateKey empty.")
        return this.AppendError(err)
    }

    privateBlock, err := ssh.MarshalOpenSSHPrivateKey(
        rand.Reader,
        this.privateKey,
        this.options.Comment,
    )
    if err != nil {
        return this.AppendError(err)
    }

    this.keyData = pem.EncodeToMemory(privateBlock)

    return this
}

// 生成私钥带密码 pem 数据
func (this SSH) CreateOpensshPrivateKeyWithPassword(password []byte, opts ...Opts) SSH {
    if this.privateKey == nil {
        err := errors.New("privateKey empty.")
        return this.AppendError(err)
    }

    useOpts := DefaultOpts
    if len(opts) > 0 {
        useOpts = opts[0]
    }

    // 生成私钥
    privateBlock, err := ssh.MarshalOpenSSHPrivateKeyWithPassword(
        rand.Reader,
        this.privateKey,
        this.options.Comment,
        password,
        useOpts,
    )
    if err != nil {
        return this.AppendError(err)
    }

    this.keyData = pem.EncodeToMemory(privateBlock)

    return this
}

// 生成公钥 pem 数据
func (this SSH) CreateOpensshPublicKey() SSH {
    if this.publicKey == nil {
        err := errors.New("publicKey empty.")
        return this.AppendError(err)
    }

    sshPublicKey, err := ssh.NewPublicKey(this.publicKey)
    if err != nil {
        return this.AppendError(err)
    }

    if this.options.Comment != "" {
        this.keyData = ssh.MarshalAuthorizedKeyWithComment(sshPublicKey, this.options.Comment)
    } else {
        this.keyData = ssh.MarshalAuthorizedKey(sshPublicKey)
    }

    return this
}
