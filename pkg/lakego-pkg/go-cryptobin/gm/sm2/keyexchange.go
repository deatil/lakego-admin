package sm2

import (
    "io"
    "errors"
    "math/big"
    "crypto/subtle"

    "github.com/deatil/go-cryptobin/hash/sm3"
    "github.com/deatil/go-cryptobin/kdf/smkdf"
)

// KeyExchange key exchange struct, include internal stat in whole key exchange flow.
// Initiator's flow will be: NewKeyExchange -> Init -> transmission -> ConfirmResponder
// Responder's flow will be: NewKeyExchange -> waiting ... -> Repond -> transmission -> ConfirmInitiator
type KeyExchange struct {
    genSignature bool        // control the optional sign/verify step triggered by responsder
    keyLength    int         // key length
    privateKey   *PrivateKey // owner's encryption private key
    z            []byte      // owner identifiable id
    peerPub      *PublicKey  // peer public key
    peerZ        []byte      // peer identifiable id
    r            *big.Int    // Ephemeral Private Key, random which will be used to compute secret
    secret       *PublicKey  // Ephemeral Public Key, generated secret which will be passed to peer
    peerSecret   *PublicKey  // received peer's secret, Ephemeral Public Key
    w2           *big.Int    // internal state which will be used when compute the key and signature, 2^w
    w2Minus1     *big.Int    // internal state which will be used when compute the key and signature, 2^w – 1
    v            *PublicKey  // internal state which will be used when compute the key and signature, u/v
}

// NewKeyExchange create one new KeyExchange object
func NewKeyExchange(priv *PrivateKey, peerPub *PublicKey, uid, peerUID []byte, keyLen int, genSignature bool) (ke *KeyExchange, err error) {
    ke = &KeyExchange{}
    ke.genSignature = genSignature

    ke.keyLength = keyLen
    ke.privateKey = priv

    one := big.NewInt(1)
    /* compute w = [log2(n)/2 - 1] = 127 */
    w := (priv.Params().N.BitLen()+1)/2 - 1

    /* w2 = 2^w = 0x80000000000000000000000000000000 */
    ke.w2 = new(big.Int).Lsh(one, uint(w))
    /* x2minus1 = 2^w - 1 = 0x7fffffffffffffffffffffffffffffff */
    ke.w2Minus1 = (&big.Int{}).Sub(ke.w2, one)

    if len(uid) == 0 {
        uid = defaultUID
    }
    ke.z, err = CalculateZA(&ke.privateKey.PublicKey, uid)
    if err != nil {
        return nil, err
    }

    err = ke.SetPeerParameters(peerPub, peerUID)
    if err != nil {
        return nil, err
    }

    ke.secret = &PublicKey{}
    ke.secret.Curve = priv.PublicKey.Curve

    ke.v = &PublicKey{}
    ke.v.Curve = priv.PublicKey.Curve

    return
}

// Init is for initiator's step A1-A3,
// returns generated Ephemeral Public Key which will be passed to Reponder.
func (ke *KeyExchange) Init(random io.Reader) (*PublicKey, error) {
    r, err := randFieldElement(random, ke.privateKey)
    if err != nil {
        return nil, err
    }

    ke.init(r)

    return ke.secret, nil
}

func (ke *KeyExchange) init(r *big.Int) {
    ke.secret.X, ke.secret.Y = ke.privateKey.ScalarBaseMult(r.Bytes())
    ke.r = r
}

// Reset clear all internal state and Ephemeral private/public keys.
func (ke *KeyExchange) Reset() {
    destroyBytes(ke.z)
    destroyBytes(ke.peerZ)
    destroyBigInt(ke.r)
    destroyPublicKey(ke.v)
}

// SetPeerParameters when need other param
func (ke *KeyExchange) SetPeerParameters(peerPub *PublicKey, peerUID []byte) error {
    if peerPub == nil {
        return nil
    }
    if len(peerUID) == 0 {
        peerUID = defaultUID
    }

    if ke.peerPub != nil {
        return errors.New("sm2: 'peerPub' already exists, please do not set it")
    }

    if peerPub.Curve != ke.privateKey.Curve {
        return errors.New("sm2: peer public key is not expected/supported")
    }

    var err error
    ke.peerPub = peerPub
    ke.peerZ, err = CalculateZA(ke.peerPub, peerUID)
    if err != nil {
        return err
    }

    ke.peerSecret = &PublicKey{}
    ke.peerSecret.Curve = peerPub.Curve
    return nil
}

func (ke *KeyExchange) sign(isResponder bool, prefix byte) []byte {
    hash := sm3.New()
    hash.Write(bigIntToBytes(ke.privateKey.Curve, ke.v.X))

    if isResponder {
        hash.Write(ke.peerZ)
        hash.Write(ke.z)
        hash.Write(bigIntToBytes(ke.privateKey.Curve, ke.peerSecret.X))
        hash.Write(bigIntToBytes(ke.privateKey.Curve, ke.peerSecret.Y))
        hash.Write(bigIntToBytes(ke.privateKey.Curve, ke.secret.X))
        hash.Write(bigIntToBytes(ke.privateKey.Curve, ke.secret.Y))
    } else {
        hash.Write(ke.z)
        hash.Write(ke.peerZ)
        hash.Write(bigIntToBytes(ke.privateKey.Curve, ke.secret.X))
        hash.Write(bigIntToBytes(ke.privateKey.Curve, ke.secret.Y))
        hash.Write(bigIntToBytes(ke.privateKey.Curve, ke.peerSecret.X))
        hash.Write(bigIntToBytes(ke.privateKey.Curve, ke.peerSecret.Y))
    }

    buffer := hash.Sum(nil)

    hash.Reset()
    hash.Write([]byte{prefix})
    hash.Write(bigIntToBytes(ke.privateKey.Curve, ke.v.Y))
    hash.Write(buffer)

    return hash.Sum(nil)
}

func (ke *KeyExchange) generateSharedKey(isResponder bool) ([]byte, error) {
    var buffer []byte

    buffer = append(buffer, bigIntToBytes(ke.privateKey.Curve, ke.v.X)...)
    buffer = append(buffer, bigIntToBytes(ke.privateKey.Curve, ke.v.Y)...)

    if isResponder {
        buffer = append(buffer, ke.peerZ...)
        buffer = append(buffer, ke.z...)
    } else {
        buffer = append(buffer, ke.z...)
        buffer = append(buffer, ke.peerZ...)
    }

    return smkdf.Key(sm3.New, buffer, ke.keyLength), nil
}

// avf is the associative value function.
func (ke *KeyExchange) avf(x *big.Int) *big.Int {
    t := new(big.Int).And(ke.w2Minus1, x)
    t.Add(ke.w2, t)
    return t
}

// mqv implements SM2-MQV procedure
func (ke *KeyExchange) mqv() {
    // implicitSig: (sPriv + avf(ePub) * ePriv) mod N
    // Calculate x2`
    t := ke.avf(ke.secret.X)

    // Calculate tB
    t.Mul(t, ke.r)
    t.Add(t, ke.privateKey.D)
    t.Mod(t, ke.privateKey.Params().N)

    // new base point: peerPub + [x1](peerSecret)
    // x1` = 2^w + (x & (2^w – 1))
    x1 := ke.avf(ke.peerSecret.X)
    // Point(x, y) = peerPub + [x1](peerSecret)
    x, y := ke.privateKey.ScalarMult(ke.peerSecret.X, ke.peerSecret.Y, x1.Bytes())
    x, y = ke.privateKey.Add(ke.peerPub.X, ke.peerPub.Y, x, y)

    ke.v.X, ke.v.Y = ke.privateKey.ScalarMult(x, y, t.Bytes())
}

// Repond is for responder's step B1-B8,
// returns generated Ephemeral Public Key and optional signature
// depends on KeyExchange.genSignature value.
//
// It will check if there are peer's public key and validate the peer's Ephemeral Public Key.
func (ke *KeyExchange) Repond(random io.Reader, rA *PublicKey) (*PublicKey, []byte, error) {
    r, err := randFieldElement(random, ke.privateKey)
    if err != nil {
        return nil, nil, err
    }

    return ke.respond(rA, r)
}

func (ke *KeyExchange) respond(rA *PublicKey, r *big.Int) (*PublicKey, []byte, error) {
    if ke.peerPub == nil {
        return nil, nil, errors.New("sm2: no peer public key given")
    }
    if !ke.privateKey.IsOnCurve(rA.X, rA.Y) {
        return nil, nil, errors.New("sm2: invalid initiator's ephemeral public key")
    }

    ke.peerSecret = rA
    // secret = RB = [r]G
    ke.secret.X, ke.secret.Y = ke.privateKey.ScalarBaseMult(r.Bytes())
    ke.r = r

    ke.mqv()
    if ke.v.X.Sign() == 0 && ke.v.Y.Sign() == 0 {
        return nil, nil, errors.New("sm2: key exchange failed, V is infinity point")
    }

    if !ke.genSignature {
        return ke.secret, nil, nil
    }

    return ke.secret, ke.sign(true, 0x02), nil
}

// ConfirmResponder for initiator's step A4-A10, returns keying data and optional signature.
//
// It will check if there are peer's public key and validate the peer's Ephemeral Public Key.
//
// If the peer's signature is not empty, then it will also validate the peer's
// signature and return generated signature depends on KeyExchange.genSignature value.
func (ke *KeyExchange) ConfirmResponder(rB *PublicKey, sB []byte) ([]byte, []byte, error) {
    if ke.peerPub == nil {
        return nil, nil, errors.New("sm2: no peer public key given")
    }
    if !ke.privateKey.IsOnCurve(rB.X, rB.Y) {
        return nil, nil, errors.New("sm2: invalid responder's ephemeral public key")
    }

    ke.peerSecret = rB

    ke.mqv()
    if ke.v.X.Sign() == 0 && ke.v.Y.Sign() == 0 {
        return nil, nil, errors.New("sm2: key exchange failed, U is infinity point")
    }

    if len(sB) > 0 {
        buffer := ke.sign(false, 0x02)
        if subtle.ConstantTimeCompare(buffer, sB) != 1 {
            return nil, nil, errors.New("sm2: invalid responder's signature")
        }
    }

    key, err := ke.generateSharedKey(false)
    if err != nil {
        return nil, nil, err
    }

    if !ke.genSignature {
        return key, nil, nil
    }

    return key, ke.sign(false, 0x03), nil
}

// ConfirmInitiator for responder's step B10
func (ke *KeyExchange) ConfirmInitiator(s1 []byte) ([]byte, error) {
    if s1 != nil {
        buffer := ke.sign(true, 0x03)
        if subtle.ConstantTimeCompare(buffer, s1) != 1 {
            return nil, errors.New("sm2: invalid initiator's signature")
        }
    }

    return ke.generateSharedKey(true)
}

func destroyBigInt(n *big.Int) {
    if n != nil {
        n.SetInt64(0)
    }
}

func destroyPublicKey(pub *PublicKey) {
    if pub != nil {
        destroyBigInt(pub.X)
        destroyBigInt(pub.Y)
    }
}

func destroyBytes(bytes []byte) {
    for v := range bytes {
        bytes[v] = 0
    }
}
