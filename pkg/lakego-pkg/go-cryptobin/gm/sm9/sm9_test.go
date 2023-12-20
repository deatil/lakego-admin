package sm9

import (
    "testing"
    "crypto/rand"
)

func Test_Sign(t *testing.T) {
    mk, err := MasterKeyGen(rand.Reader)
    if err != nil {
        t.Errorf("mk gen failed:%s", err)
        return
    }

    var hid byte = 1

    var uid = []byte("Alice")

    uk, err := UserKeyGen(mk, uid, hid)
    if err != nil {
        t.Errorf("uk gen failed:%s", err)
        return
    }

    msg := []byte("message")

    sig, err := Sign(uk, &mk.MasterPubKey, msg)
    if err != nil {
        t.Errorf("sm9 sign failed:%s", err)
        return
    }

    if !Verify(&mk.MasterPubKey, sig, msg, uid, hid) {
        t.Error("sm9 sig is invalid")
        return
    }
}

func BenchmarkMasterKeyGen(b *testing.B) {
    for i := 0; i < b.N; i++ {
        _, _ = MasterKeyGen(rand.Reader)
    }
}

func BenchmarkUserKeyGen(b *testing.B) {
    mk, _ := MasterKeyGen(rand.Reader)
    id := []byte("Alice")
    hid := 3
    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        _, _ = UserKeyGen(mk, id, byte(hid))
    }
}

func BenchmarkSign(b *testing.B) {
    mk, _ := MasterKeyGen(rand.Reader)
    id := []byte("Alice")
    hid := 3
    uk, _ := UserKeyGen(mk, id, byte(hid))

    var msg = []byte("message")

    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        _, _ = Sign(uk, &mk.MasterPubKey, msg)
    }
}

func BenchmarkVerify(b *testing.B) {
    mk, _ := MasterKeyGen(rand.Reader)
    id := []byte("Alice")
    hid := 3
    uk, _ := UserKeyGen(mk, id, byte(hid))

    var msg = []byte("message")

    sig, _ := Sign(uk, &mk.MasterPubKey, msg)

    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        _ = Verify(&mk.MasterPubKey, sig, msg, id, byte(hid))
    }
}
