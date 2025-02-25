package sm2

import (
    "errors"
    "crypto/rand"

    "github.com/golang-jwt/jwt/v4"
    "github.com/deatil/go-cryptobin/gm/sm2"
)

var (
    ErrSM2InvalidKey     = errors.New("key is invalid")
    ErrSM2InvalidKeyType = errors.New("key is of invalid type")
    ErrSM2Verification   = errors.New("sm2: verification error")
)

var (
    SigningMethodGmSM2 *SigningMethodSM2
)

func init() {
    SigningMethodGmSM2 = &SigningMethodSM2{}
    jwt.RegisterSigningMethod(SigningMethodGmSM2.Alg(), func() jwt.SigningMethod {
        return SigningMethodGmSM2
    })
}

/**
 * 国密 SM2 签名验证
 *
 * @create 2022-4-16
 * @author deatil
 */
type SigningMethodSM2 struct{}

// 标识
func (this *SigningMethodSM2) Alg() string {
    return "GmSM2"
}

// 公钥验证
func (this *SigningMethodSM2) Verify(signingString, signature string, key any) error {
    var err error
    var sm2Key *sm2.PublicKey
    var ok bool

    if sm2Key, ok = key.(*sm2.PublicKey); !ok {
        return ErrSM2InvalidKeyType
    }

    var sig []byte
    if sig, err = jwt.DecodeSegment(signature); err != nil {
        return err
    }

    // Verify the signature
    if !sm2Key.Verify([]byte(signingString), sig, nil) {
        return ErrSM2Verification
    }

    return nil
}

// 私钥签名
func (this *SigningMethodSM2) Sign(signingString string, key any) (string, error) {
    var sm2Key *sm2.PrivateKey
    var ok bool

    if sm2Key, ok = key.(*sm2.PrivateKey); !ok {
        return "", ErrSM2InvalidKeyType
    }

    // 签名
    sig, err := sm2Key.Sign(rand.Reader, []byte(signingString), nil)
    if err != nil {
        return "", err
    }

    return jwt.EncodeSegment(sig), nil
}
