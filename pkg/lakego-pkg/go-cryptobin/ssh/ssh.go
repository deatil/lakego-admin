package ssh

import (
    "crypto"
    "crypto/rand"
    "encoding/pem"
    "encoding/binary"

    "github.com/pkg/errors"
    "golang.org/x/crypto/ssh"
)

const (
    sshMagic = "openssh-key-v1\x00"
)

// 配置
type Opts struct {
    Cipher  Cipher
    KDFOpts KDFOpts
}

// 默认配置
var DefaultOpts = Opts{
    Cipher:  AES256CTR,
    KDFOpts: BcryptOpts{
        SaltSize: 16,
        Rounds:   16,
    },
}

type openSSHPrivateKey struct {
    CipherName   string
    KdfName      string
    KdfOpts      string
    NumKeys      uint32
    PubKey       []byte
    PrivKeyBlock []byte
}

type openSSHPrivateKeyBlock struct {
    Check1  uint32
    Check2  uint32
    Keytype string
    Rest    []byte `ssh:"rest"`
}

// 解析
func ParseOpenSSHPrivateKey(key []byte) (crypto.PrivateKey, string, error) {
    return ParseOpenSSHPrivateKeyWithPassword(key, nil)
}

// 解析带密码
func ParseOpenSSHPrivateKeyWithPassword(key []byte, password []byte) (crypto.PrivateKey, string, error) {
    if len(key) < len(sshMagic) || string(key[:len(sshMagic)]) != sshMagic {
        return nil, "", errors.New("invalid openssh private key format")
    }

    remaining := key[len(sshMagic):]

    var w openSSHPrivateKey
    if err := ssh.Unmarshal(remaining, &w); err != nil {
        return nil, "", err
    }

    if w.KdfName != "none" || w.CipherName != "none" {
        newCipher, err := ParseCipher(w.CipherName)
        if err != nil {
            return nil, "", err
        }

        newKdf, err := ParsePbkdf(w.KdfName)
        if err != nil {
            return nil, "", err
        }

        size := newCipher.KeySize() + newCipher.BlockSize()

        k, err := newKdf.DeriveKey(password, w.KdfOpts, size)
        if err != nil {
            return nil, "", errors.Wrap(err, "error deriving password")
        }

        dst, err := newCipher.Decrypt(k, w.PrivKeyBlock)
        if err != nil {
            return nil, "", err
        }

        w.PrivKeyBlock = dst
    }

    var pk1 openSSHPrivateKeyBlock
    if err := ssh.Unmarshal(w.PrivKeyBlock, &pk1); err != nil {
        if w.KdfName != "none" || w.CipherName != "none" {
            return nil, "", errors.New("incorrect passphrase supplied")
        }

        return nil, "", err
    }

    if pk1.Check1 != pk1.Check2 {
        if w.KdfName != "none" || w.CipherName != "none" {
            return nil, "", errors.New("incorrect passphrase supplied")
        }

        return nil, "", errors.New("error decoding key: check mismatch")
    }

    newKey, err := ParseKeytype(pk1.Keytype)
    if err != nil {
        return nil, "", err
    }

    parsedKey, comment, err := newKey.Parse(pk1.Rest)
    if err != nil {
        return nil, "", err
    }

    return parsedKey, comment, nil
}

// 编码
func MarshalOpenSSHPrivateKey(key crypto.PrivateKey, comment string) (*pem.Block, error) {
    return MarshalOpenSSHPrivateKeyWithPassword(key, comment, nil)
}

// 编码
func MarshalOpenSSHPrivateKeyWithPassword(key crypto.PrivateKey, comment string, password []byte, opts ...Opts) (*pem.Block, error) {
    var check uint32
    if err := binary.Read(rand.Reader, binary.BigEndian, &check); err != nil {
        return nil, errors.Wrap(err, "error generating random check ")
    }

    w := openSSHPrivateKey{
        NumKeys: 1,
    }
    pk1 := openSSHPrivateKeyBlock{
        Check1: check,
        Check2: check,
    }

    opt := DefaultOpts
    if len(opts) > 0 {
        opt = opts[0]
    }

    if password == nil {
        w.CipherName = "none"
        w.KdfName = "none"
    } else {
        if opt.Cipher == nil {
            return nil, errors.New("error opt Cipher is nil")
        }
        if opt.KDFOpts == nil {
            return nil, errors.New("error opt KDFOpts is nil")
        }

        w.CipherName = opt.Cipher.Name()
        w.KdfName = opt.KDFOpts.Name()
    }

    parsedKey, err := ParseKeytype(GetStructName(key))
    if err != nil {
        return nil, err
    }

    keyType, pubKey, rest, err := parsedKey.Marshal(key, comment)
    if err != nil {
        return nil, err
    }

    w.PubKey = pubKey

    pk1.Keytype = keyType
    pk1.Rest = rest

    w.PrivKeyBlock = ssh.Marshal(pk1)

    if password != nil {
        newCipher := opt.Cipher
        newKdf := opt.KDFOpts

        size := newCipher.KeySize() + newCipher.BlockSize()

        k, kdfOpts, err := newKdf.DeriveKey(password, size)
        if err != nil {
            return nil, errors.Wrap(err, "error deriving decryption key")
        }

        w.KdfOpts = kdfOpts

        dst, err := newCipher.Encrypt(k, w.PrivKeyBlock)
        if err != nil {
            return nil, err
        }

        w.PrivKeyBlock = dst
    }

    b := ssh.Marshal(w)
    block := &pem.Block{
        Type:  "OPENSSH PRIVATE KEY",
        Bytes: append([]byte(sshMagic), b...),
    }

    return block, nil
}
