package ssh

import (
    "io"
    "fmt"
    "bytes"
    "errors"
    "strings"
    "crypto"
    "crypto/elliptic"
    "encoding/pem"
    "encoding/binary"
    "encoding/base64"

    "golang.org/x/crypto/ssh"

    "github.com/tjfoc/gmsm/sm2"
    "github.com/tjfoc/gmsm/x509"
)

func NewSM2PublicKey(key *sm2.PublicKey) ssh.PublicKey {
    return (*sm2PublicKey)(key)
}

type sm2PublicKey sm2.PublicKey

func (r *sm2PublicKey) Type() string {
    return "ssh-sm2"
}

func parseSM2(in []byte) (out ssh.PublicKey, rest []byte, err error) {
    var w struct {
        Pub  []byte
        Rest []byte `ssh:"rest"`
    }
    if err := ssh.Unmarshal(in, &w); err != nil {
        return nil, nil, err
    }

    curve := sm2.P256Sm2()

    X, Y := elliptic.Unmarshal(curve, w.Pub)
    if X == nil || Y == nil {
        return nil, nil, errors.New("error decoding key: failed to unmarshal public key")
    }

    key := &sm2PublicKey{
        Curve: curve,
        X:     X,
        Y:     Y,
    }

    return key, w.Rest, nil
}

func (r *sm2PublicKey) Marshal() []byte {
    keyType := KeyAlgoSM2

    pub := elliptic.Marshal(r.Curve, r.X, r.Y)

    wirekey := struct {
        KeyType string
        Pub     []byte
    }{
        keyType, pub,
    }

    return ssh.Marshal(&wirekey)
}

func (r *sm2PublicKey) Verify(data []byte, sig *ssh.Signature) error {
    pubkey := (*sm2.PublicKey)(r)

    if !pubkey.Verify(data, sig.Blob) {
        return fmt.Errorf("ssh: signature verify fail")
    }

    return nil
}

func (r *sm2PublicKey) CryptoPublicKey() crypto.PublicKey {
    return (*sm2.PublicKey)(r)
}

// =============

func NewSM2PrivateKey(key *sm2.PrivateKey) ssh.Signer {
    return &sm2PrivateKey{key}
}

type sm2PrivateKey struct {
    *sm2.PrivateKey
}

func (k *sm2PrivateKey) PublicKey() ssh.PublicKey {
    return (*sm2PublicKey)(&k.PrivateKey.PublicKey)
}

func (k *sm2PrivateKey) Sign(rand io.Reader, data []byte) (*ssh.Signature, error) {
    return k.SignWithAlgorithm(rand, data, k.PublicKey().Type())
}

func (k *sm2PrivateKey) SignWithAlgorithm(rand io.Reader, data []byte, algorithm string) (*ssh.Signature, error) {
    if algorithm != "" && algorithm != k.PublicKey().Type() {
        return nil, fmt.Errorf("ssh: unsupported signature algorithm %s", algorithm)
    }

    sig, err := k.PrivateKey.Sign(rand, data, nil)
    if err != nil {
        return nil, err
    }

    return &ssh.Signature{
        Format: k.PublicKey().Type(),
        Blob:   sig,
    }, nil
}

// =============

func encryptedBlock(block *pem.Block) bool {
    return strings.Contains(block.Headers["Proc-Type"], "ENCRYPTED")
}

func ParseSM2RawPrivateKey(pemBytes []byte) (any, error) {
    block, _ := pem.Decode(pemBytes)
    if block == nil {
        return nil, errors.New("ssh: no key found")
    }

    if encryptedBlock(block) {
        return nil, errors.New("ssh: this private key is passphrase protected")
    }

    switch block.Type {
        case "PRIVATE KEY":
            return x509.ReadPrivateKeyFromPem(block.Bytes, nil)
        case "OPENSSH PRIVATE KEY":
            key, _, err := ParseOpenSSHPrivateKey(block.Bytes)

            return key, err
        default:
            return nil, fmt.Errorf("ssh: unsupported key type %q", block.Type)
    }
}

func ParseSM2RawPrivateKeyWithPassphrase(pemBytes, passphrase []byte) (any, error) {
    block, _ := pem.Decode(pemBytes)
    if block == nil {
        return nil, errors.New("ssh: no key found")
    }

    if block.Type == "OPENSSH PRIVATE KEY" {
        key, _, err := ParseOpenSSHPrivateKeyWithPassword(block.Bytes, passphrase)

        return key, err
    }

    if !encryptedBlock(block) {
        return nil, errors.New("ssh: not an encrypted key")
    }

    key, err := x509.ReadPrivateKeyFromPem(block.Bytes, passphrase)
    if err != nil {
        return nil, fmt.Errorf("ssh: cannot decode encrypted private keys: %v", err)
    }

    return key, nil
}

// =============

func parseSM2PubKey(in []byte, algo string) (pubKey ssh.PublicKey, rest []byte, err error) {
    switch algo {
        case KeyAlgoSM2:
            return parseSM2(in)
    }

    return nil, nil, fmt.Errorf("ssh: unknown key algorithm: %v", algo)
}

func parseString(in []byte) (out, rest []byte, ok bool) {
    if len(in) < 4 {
        return
    }

    length := binary.BigEndian.Uint32(in)
    in = in[4:]
    if uint32(len(in)) < length {
        return
    }

    out = in[:length]
    rest = in[length:]
    ok = true

    return
}

func ParseSM2PublicKey(in []byte) (out ssh.PublicKey, err error) {
    algo, in, ok := parseString(in)
    if !ok {
        return nil, errors.New("ssh: short read")
    }

    var rest []byte
    out, rest, err = parseSM2PubKey(in, string(algo))
    if len(rest) > 0 {
        return nil, errors.New("ssh: trailing junk in public key")
    }

    return out, err
}

func parseSM2AuthorizedKey(in []byte) (out ssh.PublicKey, comment string, err error) {
    in = bytes.TrimSpace(in)

    i := bytes.IndexAny(in, " \t")
    if i == -1 {
        i = len(in)
    }

    base64Key := in[:i]

    key := make([]byte, base64.StdEncoding.DecodedLen(len(base64Key)))
    n, err := base64.StdEncoding.Decode(key, base64Key)
    if err != nil {
        return nil, "", err
    }

    key = key[:n]
    out, err = ParseSM2PublicKey(key)
    if err != nil {
        return nil, "", err
    }

    comment = string(bytes.TrimSpace(in[i:]))
    return out, comment, nil
}

func ParseSM2AuthorizedKey(in []byte) (out ssh.PublicKey, comment string, options []string, rest []byte, err error) {
    for len(in) > 0 {
        end := bytes.IndexByte(in, '\n')
        if end != -1 {
            rest = in[end+1:]
            in = in[:end]
        } else {
            rest = nil
        }

        end = bytes.IndexByte(in, '\r')
        if end != -1 {
            in = in[:end]
        }

        in = bytes.TrimSpace(in)
        if len(in) == 0 || in[0] == '#' {
            in = rest
            continue
        }

        i := bytes.IndexAny(in, " \t")
        if i == -1 {
            in = rest
            continue
        }

        if out, comment, err = parseSM2AuthorizedKey(in[i:]); err == nil {
            return out, comment, options, rest, nil
        }

        // No key type recognised. Maybe there's an options field at
        // the beginning.
        var b byte
        inQuote := false
        var candidateOptions []string
        optionStart := 0
        for i, b = range in {
            isEnd := !inQuote && (b == ' ' || b == '\t')
            if (b == ',' && !inQuote) || isEnd {
                if i-optionStart > 0 {
                    candidateOptions = append(candidateOptions, string(in[optionStart:i]))
                }
                optionStart = i + 1
            }
            if isEnd {
                break
            }
            if b == '"' && (i == 0 || (i > 0 && in[i-1] != '\\')) {
                inQuote = !inQuote
            }
        }
        for i < len(in) && (in[i] == ' ' || in[i] == '\t') {
            i++
        }
        if i == len(in) {
            // Invalid line: unmatched quote
            in = rest
            continue
        }

        in = in[i:]
        i = bytes.IndexAny(in, " \t")
        if i == -1 {
            in = rest
            continue
        }

        if out, comment, err = parseSM2AuthorizedKey(in[i:]); err == nil {
            options = candidateOptions
            return out, comment, options, rest, nil
        }

        in = rest
        continue
    }

    return nil, "", nil, nil, errors.New("ssh: no key found")
}
