package sm9

import (
    "testing"
    "crypto/rand"
    // "encoding/base64"
)

func Test_Sign(t *testing.T) {
    mk, err := GenerateSignMasterPrivateKey(rand.Reader)
    if err != nil {
        t.Errorf("mk gen failed:%s", err)
        return
    }

    var hid byte = 1

    var uid = []byte("Alice")

    uk, err := GenerateSignPrivateKey(mk, uid, hid)
    if err != nil {
        t.Errorf("uk gen failed:%s", err)
        return
    }

    msg := []byte("message")

    mpk := &mk.SignMasterPublicKey

    h, s, err := Sign(rand.Reader, uk, msg)
    if err != nil {
        t.Errorf("sm9 sign failed:%s", err)
        return
    }

    if !Verify(mpk, uid, hid, msg, h, s) {
        t.Error("sm9 sig is invalid")
        return
    }
}

func Test_NewSign(t *testing.T) {
    mk, err := GenerateSignMasterPrivateKey(rand.Reader)
    if err != nil {
        t.Errorf("mk gen failed:%s", err)
        return
    }

    mpk := &mk.SignMasterPublicKey

    var hid byte = 1
    var uid = []byte("Alice")

    uk, err := GenerateSignPrivateKey(mk, uid, hid)
    if err != nil {
        t.Errorf("uk gen failed:%s", err)
        return
    }

    mkStr := ToSignMasterPrivateKey(mk)
    mk2, err := NewSignMasterPrivateKey(mkStr)
    if err != nil {
        t.Error("sm9 NewSignMasterPrivateKey is invalid")
        return
    }
    if !mk2.Equal(mk) {
        t.Error("sm9 NewSignMasterPrivateKey Equal is invalid")
        return
    }

    mpkStr := ToSignMasterPublicKey(mpk)
    mpk2, err := NewSignMasterPublicKey(mpkStr)
    if err != nil {
        t.Error("sm9 NewSignMasterPublicKey is invalid")
        return
    }
    if !mpk2.Equal(mpk) {
        t.Error("sm9 NewSignMasterPublicKey Equal is invalid")
        return
    }

    ukStr := ToSignPrivateKey(uk)
    uk2, err := NewSignPrivateKey(ukStr)
    if err != nil {
        t.Error("sm9 NewSignPrivateKey is invalid")
        return
    }
    if !uk2.Equal(uk) {
        t.Error("sm9 NewSignPrivateKey Equal is invalid")
        return
    }
}

func Test_SignASN1(t *testing.T) {
    mk, err := GenerateSignMasterPrivateKey(rand.Reader)
    if err != nil {
        t.Errorf("mk gen failed:%s", err)
        return
    }

    var hid byte = 1

    var uid = []byte("Alice")

    uk, err := GenerateSignPrivateKey(mk, uid, hid)
    if err != nil {
        t.Errorf("uk gen failed:%s", err)
        return
    }

    msg := []byte("message")

    mpk := &mk.SignMasterPublicKey

    r, err := SignASN1(rand.Reader, uk, msg)
    if err != nil {
        t.Errorf("sm9 sign failed:%s", err)
        return
    }

    // eg:
    // MGYEIHgj7GiwSbr2F1B2kSE3E/VSIRA60w6LL0e8SZoIyTUnA0IABBe24EjvFykzrxzPEG9ca6ZfDZNSiJl1i+jRXCwVvzbQT3YsQghpM8TYSI0pQ6V9Lwnyn8kf6NmYGkeg7rYQfOk=
    // t.Errorf("%s", base64.StdEncoding.EncodeToString(r))

    if !VerifyASN1(mpk, uid, hid, msg, r) {
        t.Error("sm9 sig is invalid")
        return
    }
}
