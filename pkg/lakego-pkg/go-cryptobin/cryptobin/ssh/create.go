package ssh

import (
    "errors"
    "crypto/rand"
    "crypto/rsa"
    "crypto/dsa"
    "crypto/ecdsa"
    "crypto/ed25519"
    "crypto/x509"
    "encoding/pem"

    "github.com/deatil/go-cryptobin/ssh"
    "github.com/deatil/go-cryptobin/pkcs8"
    "github.com/deatil/go-cryptobin/gm/sm2"
    pubkey_dsa "github.com/deatil/go-cryptobin/pubkey/dsa"
)

type (
    // options
    Opts       = pkcs8.Opts
    // PBKDF2 options
    PBKDF2Opts = pkcs8.PBKDF2Opts
    // Scrypt options
    ScryptOpts = pkcs8.ScryptOpts
)

var (
    // get Cipher type
    GetCipherFromName = pkcs8.GetCipherFromName
    // get hash type
    GetHashFromName   = pkcs8.GetHashFromName
)

type (
    // OpenSSH options
    OpenSSHOpts = ssh.Opts

    // OpenSSH Bcrypt options
    OpenSSHBcryptOpts = ssh.BcryptOpts

    // OpenSSH Bcryptbin options
    OpenSSHBcryptbinOpts = ssh.BcryptbinOpts
)

var (
    // get OpenSSH Cipher
    GetOpenSSHCipherFromName = ssh.GetCipherFromName

    // Default OpenSSH options
    DefaultOpenSSHOpts = ssh.DefaultOpts
)

// Create PrivateKey PEM
func (this SSH) CreatePrivateKey() SSH {
    if this.privateKey == nil {
        err := errors.New("privateKey empty.")
        return this.AppendError(err)
    }

    var privateKeyBytes []byte
    var err error

    // 生成私钥
    switch prikey := this.privateKey.(type) {
        case *rsa.PrivateKey:
            privateKeyBytes, err = x509.MarshalPKCS8PrivateKey(prikey)
        case *dsa.PrivateKey:
            privateKeyBytes, err = pubkey_dsa.MarshalPKCS8PrivateKey(prikey)
        case *ecdsa.PrivateKey:
            privateKeyBytes, err = x509.MarshalPKCS8PrivateKey(prikey)
        case ed25519.PrivateKey:
            privateKeyBytes, err = x509.MarshalPKCS8PrivateKey(prikey)
        case *sm2.PrivateKey:
            privateKeyBytes, err = sm2.MarshalPrivateKey(prikey)
        default:
            err = errors.New("privateKey error.")
    }

    if err != nil {
        return this.AppendError(err)
    }

    privateBlock := &pem.Block{
        Type:  "PRIVATE KEY",
        Bytes: privateKeyBytes,
    }

    this.keyData = pem.EncodeToMemory(privateBlock)

    return this
}

// Create PrivateKey PEM With Password
func (this SSH) CreatePrivateKeyWithPassword(password []byte, opts ...any) SSH {
    if this.privateKey == nil {
        err := errors.New("privateKey empty.")
        return this.AppendError(err)
    }

    opt, err := pkcs8.ParseOpts(opts...)
    if err != nil {
        return this.AppendError(err)
    }

    var privateKeyBytes []byte

    // 生成私钥
    switch prikey := this.privateKey.(type) {
        case *rsa.PrivateKey:
            privateKeyBytes, err = x509.MarshalPKCS8PrivateKey(prikey)
        case *dsa.PrivateKey:
            privateKeyBytes, err = pubkey_dsa.MarshalPKCS8PrivateKey(prikey)
        case *ecdsa.PrivateKey:
            privateKeyBytes, err = x509.MarshalPKCS8PrivateKey(prikey)
        case ed25519.PrivateKey:
            privateKeyBytes, err = x509.MarshalPKCS8PrivateKey(prikey)
        case *sm2.PrivateKey:
            privateKeyBytes, err = sm2.MarshalPrivateKey(prikey)
        default:
            err = errors.New("privateKey error.")
    }

    if err != nil {
        return this.AppendError(err)
    }

    // 生成加密数据
    privateBlock, err := pkcs8.EncryptPEMBlock(
        rand.Reader,
        "ENCRYPTED PRIVATE KEY",
        privateKeyBytes,
        []byte(password),
        opt,
    )
    if err != nil {
        return this.AppendError(err)
    }

    this.keyData = pem.EncodeToMemory(privateBlock)

    return this
}

// Create PublicKey PEM
func (this SSH) CreatePublicKey() SSH {
    if this.publicKey == nil {
        err := errors.New("publicKey empty.")
        return this.AppendError(err)
    }

    var publicKeyBytes []byte
    var err error

    switch pubkey := this.publicKey.(type) {
        case *rsa.PublicKey:
            publicKeyBytes, err = x509.MarshalPKIXPublicKey(pubkey)
        case *dsa.PublicKey:
            publicKeyBytes, err = pubkey_dsa.MarshalPKCS8PublicKey(pubkey)
        case *ecdsa.PublicKey:
            publicKeyBytes, err = x509.MarshalPKIXPublicKey(pubkey)
        case ed25519.PublicKey:
            publicKeyBytes, err = x509.MarshalPKIXPublicKey(pubkey)
        case *sm2.PublicKey:
            publicKeyBytes, err = sm2.MarshalPublicKey(pubkey)
        default:
            err = errors.New("privateKey error.")
    }

    if err != nil {
        return this.AppendError(err)
    }

    publicBlock := &pem.Block{
        Type:  "PUBLIC KEY",
        Bytes: publicKeyBytes,
    }

    this.keyData = pem.EncodeToMemory(publicBlock)

    return this
}

// ====================

// Create OpenSSH PrivateKey PEM
func (this SSH) CreateOpenSSHPrivateKey() SSH {
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

// Create OpenSSH PrivateKey PEM With Password
func (this SSH) CreateOpenSSHPrivateKeyWithPassword(password []byte, opts ...OpenSSHOpts) SSH {
    if this.privateKey == nil {
        err := errors.New("privateKey empty.")
        return this.AppendError(err)
    }

    useOpts := DefaultOpenSSHOpts
    if this.options.CipherName != "" {
        cip, err := ssh.ParseCipher(this.options.CipherName)
        if err != nil {
            return this.AppendError(err)
        }

        useOpts.Cipher = cip
    }

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

// Create OpenSSH PublicKey PEM
func (this SSH) CreateOpenSSHPublicKey() SSH {
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
