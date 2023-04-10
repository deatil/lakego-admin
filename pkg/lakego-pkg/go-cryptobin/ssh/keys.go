package ssh

import (
    "golang.org/x/crypto/ssh"
    "github.com/tjfoc/gmsm/sm2"
)

var (
    // ParseKnownHosts(in []byte) (marker string, hosts []string, pubKey PublicKey, comment string, rest []byte, err error)
    ParseKnownHosts = ssh.ParseKnownHosts

    // MarshalAuthorizedKey(key PublicKey) []byte
    MarshalAuthorizedKey = ssh.MarshalAuthorizedKey
)

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

func NewPublicKey(key any) (out ssh.PublicKey, err error) {
    switch k := key.(type) {
        case *sm2.PublicKey:
            return NewSM2PublicKey(k), nil
    }

    return ssh.NewPublicKey(key)
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
