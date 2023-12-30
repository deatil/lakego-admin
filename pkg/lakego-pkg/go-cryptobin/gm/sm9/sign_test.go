package sm9

import (
    "testing"
    "crypto/rand"
    "encoding/hex"
    // "encoding/base64"

    "github.com/deatil/go-cryptobin/gm/sm9/sm9curve"
)

func Test_Sign(t *testing.T) {
    mk, err := GenerateSignMasterKey(rand.Reader)
    if err != nil {
        t.Errorf("mk gen failed:%s", err)
        return
    }

    var hid byte = 1

    var uid = []byte("Alice")

    uk, err := GenerateSignUserKey(mk, uid, hid)
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
    mk, err := GenerateSignMasterKey(rand.Reader)
    if err != nil {
        t.Errorf("mk gen failed:%s", err)
        return
    }

    mpk := &mk.SignMasterPublicKey

    var hid byte = 1
    var uid = []byte("Alice")

    uk, err := GenerateSignUserKey(mk, uid, hid)
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
    mk, err := GenerateSignMasterKey(rand.Reader)
    if err != nil {
        t.Errorf("mk gen failed:%s", err)
        return
    }

    var hid byte = 1

    var uid = []byte("Alice")

    uk, err := GenerateSignUserKey(mk, uid, hid)
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

func Test_HashH1(t *testing.T) {
    n := sm9curve.Order

    expected := "2acc468c3926b0bdb2767e99ff26e084de9ced8dbc7d5fbf418027b667862fab"
    h := hash([]byte{0x41, 0x6c, 0x69, 0x63, 0x65, 0x01}, n, H1)

    res := h.Bytes()

    if hex.EncodeToString(res) != expected {
        t.Errorf("got %x, want %s", res, expected)
    }
}

func Test_HashH2(t *testing.T) {
    n := sm9curve.Order

    expected := "823c4b21e4bd2dfe1ed92c606653e996668563152fc33f55d7bfbb9bd9705adb"
    zStr := "4368696E65736520494253207374616E6461726481377B8FDBC2839B4FA2D0E0F8AA6853BBBE9E9C4099608F8612C6078ACD7563815AEBA217AD502DA0F48704CC73CABB3C06209BD87142E14CBD99E8BCA1680F30DADC5CD9E207AEE32209F6C3CA3EC0D800A1A42D33C73153DED47C70A39D2E8EAF5D179A1836B359A9D1D9BFC19F2EFCDB829328620962BD3FDF15F2567F58A543D25609AE943920679194ED30328BB33FD15660BDE485C6B79A7B32B013983F012DB04BA59FE88DB889321CC2373D4C0C35E84F7AB1FF33679BCA575D67654F8624EB435B838CCA77B2D0347E65D5E46964412A096F4150D8C5EDE5440DDF0656FCB663D24731E80292188A2471B8B68AA993899268499D23C89755A1A89744643CEAD40F0965F28E1CD2895C3D118E4F65C9A0E3E741B6DD52C0EE2D25F5898D60848026B7EFB8FCC1B2442ECF0795F8A81CEE99A6248F294C82C90D26BD6A814AAF475F128AEF43A128E37F80154AE6CB92CAD7D1501BAE30F750B3A9BD1F96B08E97997363911314705BFB9A9DBB97F75553EC90FBB2DDAE53C8F68E42"

    z, err := hex.DecodeString(zStr)
    if err != nil {
        t.Fatal(err)
    }

    h := hash(z, n, H2)

    res := h.Bytes()

    if hex.EncodeToString(res) != expected {
        t.Errorf("got %x, expected %s", res, expected)
    }
}

func Test_SignMasterPublicKey_Compress(t *testing.T) {
    mk, err := GenerateSignMasterKey(rand.Reader)
    if err != nil {
        t.Errorf("mk gen failed:%s", err)
        return
    }

    mpk := mk.PublicKey()

    pubBytes := mpk.MarshalCompress()

    newPub := new(SignMasterPublicKey)
    err = newPub.UnmarshalCompress(pubBytes)
    if err != nil {
        t.Errorf("Sign UnmarshalCompress failed:%s", err)
        return
    }

    if !newPub.Equal(mpk) {
        t.Error("sm9 Sign MarshalCompress Equal is invalid")
        return
    }
}
