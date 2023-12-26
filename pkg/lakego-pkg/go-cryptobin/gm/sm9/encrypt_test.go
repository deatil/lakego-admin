package sm9

import (
    "testing"
    "crypto/rand"
    "encoding/hex"

    cryptobin_test "github.com/deatil/go-cryptobin/tool/test"
)

func Test_Encrypt(t *testing.T) {
    assert := cryptobin_test.AssertEqualT(t)

    mk, err := GenerateEncryptMasterPrivateKey(rand.Reader)
    if err != nil {
        t.Errorf("mk gen failed:%s", err)
        return
    }

    var hid byte = 1

    var uid = []byte("Alice")

    uk, err := GenerateEncryptPrivateKey(mk, uid, hid)
    if err != nil {
        t.Errorf("uk gen failed:%s", err)
        return
    }

    msg := []byte("message")

    mpk := mk.PublicKey()

    endata, err := Encrypt(rand.Reader, mpk, uid, hid, msg, DefaultOpts)
    if err != nil {
        t.Errorf("sm9 Encrypt failed:%s", err)
        return
    }

    newMsg, err := Decrypt(uk, uid, endata, DefaultOpts)
    if err != nil {
        t.Errorf("sm9 Decrypt failed:%s", err)
        return
    }

    assert(newMsg, msg, "sm9 Decrypt failed")
}

func Test_NewEncrypt(t *testing.T) {
    mk, err := GenerateEncryptMasterPrivateKey(rand.Reader)
    if err != nil {
        t.Errorf("mk gen failed:%s", err)
        return
    }

    mpk := mk.PublicKey()

    var hid byte = 1
    var uid = []byte("Alice")

    uk, err := GenerateEncryptPrivateKey(mk, uid, hid)
    if err != nil {
        t.Errorf("uk gen failed:%s", err)
        return
    }

    mkStr := ToEncryptMasterPrivateKey(mk)
    mk2, err := NewEncryptMasterPrivateKey(mkStr)
    if err != nil {
        t.Error("sm9 NewEncryptMasterPrivateKey is invalid:" + err.Error())
        return
    }
    if !mk2.Equal(mk) {
        t.Error("sm9 NewEncryptMasterPrivateKey Equal is invalid")
        return
    }

    mpkStr := ToEncryptMasterPublicKey(mpk)
    mpk2, err := NewEncryptMasterPublicKey(mpkStr)
    if err != nil {
        t.Error("sm9 NewEncryptMasterPublicKey is invalid " + err.Error())
        return
    }
    if !mpk2.Equal(mpk) {
        t.Error("sm9 NewEncryptMasterPublicKey Equal is invalid")
        return
    }

    ukStr := ToEncryptPrivateKey(uk)
    uk2, err := NewEncryptPrivateKey(ukStr)
    if err != nil {
        t.Error("sm9 NewEncryptPrivateKey is invalid")
        return
    }
    if !uk2.Equal(uk) {
        t.Error("sm9 NewEncryptPrivateKey Equal is invalid")
        return
    }

}

func Test_EncryptASN1(t *testing.T) {
    assert := cryptobin_test.AssertEqualT(t)

    var hid byte = 1
    var uid = []byte("Alice")

    msg := []byte("message")

    mk, err := GenerateEncryptMasterPrivateKey(rand.Reader)
    if err != nil {
        t.Errorf("mk gen failed:%s", err)
        return
    }

    uk, err := GenerateEncryptPrivateKey(mk, uid, hid)
    if err != nil {
        t.Errorf("uk gen failed:%s", err)
        return
    }

    mpk := mk.PublicKey()

    endata, err := EncryptASN1(rand.Reader, mpk, uid, hid, msg, nil)
    if err != nil {
        t.Errorf("sm9 EncryptASN1 failed:%s", err)
        return
    }

    newMsg, err := DecryptASN1(uk, uid, endata, nil)
    if err != nil {
        t.Errorf("sm9 DecryptASN1 failed:%s", err)
        return
    }

    assert(newMsg, msg, "sm9 DecryptASN1 failed")
}

func Test_WrapKey(t *testing.T) {
    masterKey, err := GenerateEncryptMasterPrivateKey(rand.Reader)

    hid := byte(0x01)
    uid := []byte("test-user")

    if err != nil {
        t.Fatal(err)
    }

    userKey, err := GenerateEncryptPrivateKey(masterKey, uid, hid)
    if err != nil {
        t.Fatal(err)
    }

    key, cipher, err := WrapKey(rand.Reader, masterKey.PublicKey(), uid, hid, 16)
    if err != nil {
        t.Fatal(err)
    }

    key2, err := UnwrapKey(userKey, uid, cipher, 16)
    if err != nil {
        t.Fatal(err)
    }

    if hex.EncodeToString(key) != hex.EncodeToString(key2) {
        t.Errorf("expected %x, got %x\n", key, key2)
    }
}

func Test_EncryptMasterPublicKey_Compress(t *testing.T) {
    mk, err := GenerateEncryptMasterPrivateKey(rand.Reader)
    if err != nil {
        t.Errorf("mk gen failed:%s", err)
        return
    }

    mpk := mk.PublicKey()

    pubBytes := mpk.MarshalCompress()

    newPub := new(EncryptMasterPublicKey)
    err = newPub.UnmarshalCompress(pubBytes)
    if err != nil {
        t.Errorf("Encrypt UnmarshalCompress failed:%s", err)
        return
    }

    if !newPub.Equal(mpk) {
        t.Error("sm9 Encrypt MarshalCompress Equal is invalid")
        return
    }
}
