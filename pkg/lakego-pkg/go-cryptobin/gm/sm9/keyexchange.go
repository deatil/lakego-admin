package sm9

import (
    "io"
    "errors"
    "math/big"
    "crypto/subtle"

    "github.com/deatil/go-cryptobin/hash/sm3"
    "github.com/deatil/go-cryptobin/kdf/smkdf"
    "github.com/deatil/go-cryptobin/gm/sm9/sm9curve"
)

// KeyExchange represents key exchange struct, include internal stat in whole key exchange flow.
// Initiator's flow will be: NewKeyExchange -> InitKeyExchange -> transmission -> ConfirmResponder
// Responder's flow will be: NewKeyExchange -> waiting ... -> Repond -> transmission -> ConfirmInitiator
type KeyExchange struct {
    genSignature bool               // control the optional sign/verify step triggered by responsder
    keyLength    int                // key length
    privateKey   *EncryptPrivateKey // owner's encryption private key
    uid          []byte             // owner uid
    peerUID      []byte             // peer uid
    r            *big.Int           // random which will be used to compute secret
    secret       *sm9curve.G1       // generated secret which will be passed to peer
    peerSecret   *sm9curve.G1       // received peer's secret
    g1           *sm9curve.GT       // internal state which will be used when compute the key and signature
    g2           *sm9curve.GT       // internal state which will be used when compute the key and signature
    g3           *sm9curve.GT       // internal state which will be used when compute the key and signature
}

// NewKeyExchange creates one new KeyExchange object
func NewKeyExchange(priv *EncryptPrivateKey, uid, peerUID []byte, keyLen int, genSignature bool) *KeyExchange {
    ke := &KeyExchange{}
    ke.genSignature = genSignature
    ke.keyLength = keyLen
    ke.privateKey = priv
    ke.uid = uid
    ke.peerUID = peerUID

    return ke
}

// Init generates random with responder uid, for initiator's step A1-A4
func (ke *KeyExchange) Init(rand io.Reader, hid byte) (*sm9curve.G1, error) {
    r, err := randFieldElement(rand, sm9curve.Order)
    if err != nil {
        return nil, err
    }

    err = ke.init(hid, r)
    if err != nil {
        return nil, err
    }

    return ke.secret, nil
}

func (ke *KeyExchange) init(hid byte, r *big.Int) error {
    pubB, err := ke.privateKey.GenerateUserPublicKey(ke.peerUID, hid)
    if err != nil {
        return err
    }

    ke.r = r

    rA, err := new(sm9curve.G1).ScalarMult(pubB, sm9curve.NormalizeScalar(ke.r.Bytes()))
    if err != nil {
        return err
    }

    ke.secret = rA

    return nil
}

// Reset clears all internal state and Ephemeral private/public keys
func (ke *KeyExchange) Reset() {
    if ke.r != nil {
        ke.r.SetBytes([]byte{0})
    }

    if ke.g1 != nil {
        ke.g1.SetOne()
    }

    if ke.g2 != nil {
        ke.g2.SetOne()
    }

    if ke.g3 != nil {
        ke.g3.SetOne()
    }
}

func (ke *KeyExchange) sign(isResponder bool, prefix byte) []byte {
    var buffer []byte

    hash := sm3.New()
    hash.Write(ke.g2.Marshal())
    hash.Write(ke.g3.Marshal())

    if isResponder {
        hash.Write(ke.peerUID)
        hash.Write(ke.uid)
        hash.Write(ke.peerSecret.Marshal())
        hash.Write(ke.secret.Marshal())
    } else {
        hash.Write(ke.uid)
        hash.Write(ke.peerUID)
        hash.Write(ke.secret.Marshal())
        hash.Write(ke.peerSecret.Marshal())
    }

    buffer = hash.Sum(nil)

    hash.Reset()
    hash.Write([]byte{prefix})
    hash.Write(ke.g1.Marshal())
    hash.Write(buffer)

    return hash.Sum(nil)
}

func (ke *KeyExchange) generateSharedKey(isResponder bool) ([]byte, error) {
    var buffer []byte

    if isResponder {
        buffer = append(buffer, ke.peerUID...)
        buffer = append(buffer, ke.uid...)
        buffer = append(buffer, ke.peerSecret.Marshal()...)
        buffer = append(buffer, ke.secret.Marshal()...)
    } else {
        buffer = append(buffer, ke.uid...)
        buffer = append(buffer, ke.peerUID...)
        buffer = append(buffer, ke.secret.Marshal()...)
        buffer = append(buffer, ke.peerSecret.Marshal()...)
    }

    buffer = append(buffer, ke.g1.Marshal()...)
    buffer = append(buffer, ke.g2.Marshal()...)
    buffer = append(buffer, ke.g3.Marshal()...)

    return smkdf.Key(sm3.New, buffer, ke.keyLength), nil
}

// Repond when responder receive rA, for responder's step B1-B7
func (ke *KeyExchange) Repond(rand io.Reader, hid byte, rA *sm9curve.G1) (*sm9curve.G1, []byte, error) {
    r, err := randFieldElement(rand, sm9curve.Order)
    if err != nil {
        return nil, nil, err
    }

    return ke.respond(hid, r, rA)
}

func (ke *KeyExchange) respond(hid byte, r *big.Int, rA *sm9curve.G1) (*sm9curve.G1, []byte, error) {
    if !rA.IsOnCurve() {
        return nil, nil, errors.New("go-cryptobin/sm9: invalid initiator's ephemeral public key")
    }

    ke.peerSecret = rA

    pubA, err := ke.privateKey.GenerateUserPublicKey(ke.peerUID, hid)
    if err != nil {
        return nil, nil, err
    }

    ke.r = r
    rBytes := sm9curve.NormalizeScalar(r.Bytes())

    rB, err := new(sm9curve.G1).ScalarMult(pubA, rBytes)
    if err != nil {
        return nil, nil, err
    }

    ke.secret = rB

    ke.g1 = sm9curve.Pair(ke.peerSecret, ke.privateKey.Sk)

    g3, err := sm9curve.ScalarMultGT(ke.g1, rBytes)
    if err != nil {
        return nil, nil, err
    }
    ke.g3 = g3

    g2Pair := sm9curve.Pair(ke.privateKey.Mpk, sm9curve.Gen2)
    g2, err := sm9curve.ScalarMultGT(g2Pair, rBytes)
    if err != nil {
        return nil, nil, err
    }
    ke.g2 = g2

    if !ke.genSignature {
        return ke.secret, nil, nil
    }

    return ke.secret, ke.sign(true, 0x82), nil
}

// ConfirmResponder for initiator's step A5-A7
func (ke *KeyExchange) ConfirmResponder(rB *sm9curve.G1, sB []byte) ([]byte, []byte, error) {
    if !rB.IsOnCurve() {
        return nil, nil, errors.New("go-cryptobin/sm9: invalid responder's ephemeral public key")
    }

    // step 5
    ke.peerSecret = rB

    g1Pair := sm9curve.Pair(ke.privateKey.Mpk, sm9curve.Gen2)
    g1, err := sm9curve.ScalarMultGT(g1Pair, sm9curve.NormalizeScalar(ke.r.Bytes()))
    if err != nil {
        return nil, nil, err
    }

    ke.g1 = g1
    ke.g2 = sm9curve.Pair(ke.peerSecret, ke.privateKey.Sk)

    g3, err := sm9curve.ScalarMultGT(ke.g2, sm9curve.NormalizeScalar(ke.r.Bytes()))
    if err != nil {
        return nil, nil, err
    }
    ke.g3 = g3

    // step 6, verify signature
    if len(sB) > 0 {
        signature := ke.sign(false, 0x82)
        if subtle.ConstantTimeCompare(signature, sB) != 1 {
            return nil, nil, errors.New("go-cryptobin/sm9: invalid responder's signature")
        }
    }

    key, err := ke.generateSharedKey(false)
    if err != nil {
        return nil, nil, err
    }

    if !ke.genSignature {
        return key, nil, nil
    }

    return key, ke.sign(false, 0x83), nil
}

// ConfirmInitiator for responder's step B8
func (ke *KeyExchange) ConfirmInitiator(s1 []byte) ([]byte, error) {
    if s1 != nil {
        buffer := ke.sign(true, 0x83)

        if subtle.ConstantTimeCompare(buffer, s1) != 1 {
            return nil, errors.New("go-cryptobin/sm9: invalid initiator's signature")
        }
    }

    return ke.generateSharedKey(true)
}
