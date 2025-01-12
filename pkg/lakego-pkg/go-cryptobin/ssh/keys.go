package ssh

import (
    "bytes"
    "encoding/base64"

    "golang.org/x/crypto/ssh"

    "github.com/deatil/go-cryptobin/gm/sm2"
)

// Parse KnownHosts
func ParseKnownHosts(in []byte) (marker string, hosts []string, pubKey ssh.PublicKey, comment string, rest []byte, err error) {
    return ssh.ParseKnownHosts(in)
}

// Marshal AuthorizedKey
func MarshalAuthorizedKey(key ssh.PublicKey) []byte {
    return ssh.MarshalAuthorizedKey(key)
}

// 创建带信息的 key
// Marshal AuthorizedKey With Comment
func MarshalAuthorizedKeyWithComment(key ssh.PublicKey, comment string) []byte {
    b := &bytes.Buffer{}

    // type
    b.WriteString(key.Type())
    b.WriteByte(' ')

    // key
    e := base64.NewEncoder(base64.StdEncoding, b)
    e.Write(key.Marshal())
    e.Close()

    // comment
    b.WriteByte(' ')
    b.WriteString(comment)

    b.WriteByte('\n')
    return b.Bytes()
}

// RSA | DSA | SM2 | ECDSA | SKECDSA | ED25519 | SKEd25519
// CertAlgoRSAv01 | CertAlgoDSAv01
// CertAlgoECDSA256v01 | CertAlgoECDSA384v01
// CertAlgoECDSA521v01 | CertAlgoSKECDSA256v01
// CertAlgoED25519v01 | CertAlgoSKED25519v01
func NewPublicKey(key any) (out ssh.PublicKey, err error) {
    switch k := key.(type) {
        case *sm2.PublicKey:
            return NewSM2PublicKey(k), nil
    }

    return ssh.NewPublicKey(key)
}

func ParseAuthorizedKey(in []byte) (out ssh.PublicKey, comment string, options []string, rest []byte, err error) {
    out, comment, options, rest, err = ssh.ParseAuthorizedKey(in)
    if err != nil {
        out, comment, options, rest, err = ParseSM2AuthorizedKey(in)
    }

    return
}

func ParsePublicKey(in []byte) (out ssh.PublicKey, err error) {
    out, err = ssh.ParsePublicKey(in)
    if err != nil {
        out, err = ParseSM2PublicKey(in)
    }

    return
}

func NewSignerFromKey(key any) (out ssh.Signer, err error) {
    switch k := key.(type) {
        case *sm2.PrivateKey:
            return NewSM2PrivateKey(k), nil
    }

    return ssh.NewSignerFromKey(key)
}

func ParsePrivateKey(pemBytes []byte) (ssh.Signer, error) {
    key, err := ParseRawPrivateKey(pemBytes)
    if err != nil {
        return nil, err
    }

    return NewSignerFromKey(key)
}

func ParsePrivateKeyWithPassphrase(pemBytes, passphrase []byte) (ssh.Signer, error) {
    key, err := ParseRawPrivateKeyWithPassphrase(pemBytes, passphrase)
    if err != nil {
        return nil, err
    }

    return NewSignerFromKey(key)
}

func ParseRawPrivateKey(pemBytes []byte) (out any, err error) {
    out, err = ssh.ParseRawPrivateKey(pemBytes)
    if err != nil {
        out, err = ParseSM2RawPrivateKey(pemBytes)
    }

    return
}

func ParseRawPrivateKeyWithPassphrase(pemBytes, passphrase []byte) (out any, err error) {
    out, err = ssh.ParseRawPrivateKeyWithPassphrase(pemBytes, passphrase)
    if err != nil {
        out, err = ParseSM2RawPrivateKeyWithPassphrase(pemBytes, passphrase)
    }

    return
}
