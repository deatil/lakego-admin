package sm9

import (
    "errors"
    "testing"
    "math/big"
    "crypto/rand"
    "encoding/hex"
)

func Test_KeyExchange(t *testing.T) {
    hid := byte(0x02)
    userA := []byte("Alice")
    userB := []byte("Bob")

    masterKey, err := GenerateEncryptMasterKey(rand.Reader)
    if err != nil {
        t.Fatal(err)
    }

    userKey, err := GenerateEncryptUserKey(masterKey, userA, hid)
    if err != nil {
        t.Fatal(err)
    }

    initiator := NewKeyExchange(userKey, userA, userB, 16, true)

    userKey, err = GenerateEncryptUserKey(masterKey, userB, hid)
    if err != nil {
        t.Fatal(err)
    }

    responder := NewKeyExchange(userKey, userB, userA, 16, true)
    defer func() {
        initiator.Reset()
        responder.Reset()
    }()

    // A1-A4
    rA, err := initiator.InitKeyExchange(rand.Reader, hid)
    if err != nil {
        t.Fatal(err)
    }

    // B1 - B7
    rB, sigB, err := responder.RepondKeyExchange(rand.Reader, hid, rA)
    if err != nil {
        t.Fatal(err)
    }

    // A5 -A8
    key1, sigA, err := initiator.ConfirmResponder(rB, sigB)
    if err != nil {
        t.Fatal(err)
    }

    // B8
    key2, err := responder.ConfirmInitiator(sigA)
    if err != nil {
        t.Fatal(err)
    }

    if hex.EncodeToString(key1) != hex.EncodeToString(key2) {
        t.Errorf("got different key")
    }
}

func Test_KeyExchangeWithoutSignature(t *testing.T) {
    hid := byte(0x02)
    userA := []byte("Alice")
    userB := []byte("Bob")

    masterKey, err := GenerateEncryptMasterKey(rand.Reader)
    if err != nil {
        t.Fatal(err)
    }

    userKey, err := GenerateEncryptUserKey(masterKey, userA, hid)
    if err != nil {
        t.Fatal(err)
    }

    initiator := NewKeyExchange(userKey, userA, userB, 16, false)

    userKey, err = GenerateEncryptUserKey(masterKey, userB, hid)
    if err != nil {
        t.Fatal(err)
    }

    responder := NewKeyExchange(userKey, userB, userA, 16, false)
    defer func() {
        initiator.Reset()
        responder.Reset()
    }()

    // A1-A4
    rA, err := initiator.InitKeyExchange(rand.Reader, hid)
    if err != nil {
        t.Fatal(err)
    }

    // B1 - B7
    rB, sigB, err := responder.RepondKeyExchange(rand.Reader, hid, rA)
    if err != nil {
        t.Fatal(err)
    }
    if len(sigB) != 0 {
        t.Errorf("should no signature")
    }

    // A5 -A8
    key1, sigA, err := initiator.ConfirmResponder(rB, sigB)
    if err != nil {
        t.Fatal(err)
    }
    if len(sigA) != 0 {
        t.Errorf("should no signature")
    }

    key2, err := responder.ConfirmInitiator(nil)
    if err != nil {
        t.Fatal(err)
    }

    if hex.EncodeToString(key1) != hex.EncodeToString(key2) {
        t.Errorf("got different key")
    }
}

func bigFromHex(s string) (*big.Int, error) {
    b, ok := new(big.Int).SetString(s, 16)
    if !ok {
        return nil, errors.New("de hex error")
    }

    return b, nil
}

func encryptMasterPrivateKeyFromHex(s string) (*EncryptMasterPrivateKey, error) {
    kb, err := hex.DecodeString(s)
    if err != nil {
        return nil, err
    }

    return NewEncryptMasterPrivateKey(kb)
}

// SM9 Appendix B
func Test_KeyExchangeSample(t *testing.T) {
    hid := byte(0x02)
    expectedPube := "9174542668e8f14ab273c0945c3690c66e5dd09678b86f734c4350567ed0628354e598c6bf749a3dacc9fffedd9db6866c50457cfc7aa2a4ad65c3168ff74210"
    expectedKey := "c5c13a8f59a97cdeae64f16a2272a9e7"
    expectedSignatureB := "3bb4bcee8139c960b4d6566db1e0d5f0b2767680e5e1bf934103e6c66e40ffee"
    expectedSignatureA := "195d1b7256ba7e0e67c71202a25f8c94ff8241702c2f55d613ae1c6b98215172"

    masterKey, err := encryptMasterPrivateKeyFromHex("02E65B0762D042F51F0D23542B13ED8CFA2E9A0E7206361E013A283905E31F")
    if err != nil {
        t.Fatal(err)
    }

    if hex.EncodeToString(masterKey.Mpk.Marshal()) != expectedPube {
        t.Errorf("not expected master public key")
    }

    userA := []byte("Alice")
    userB := []byte("Bob")

    userKey, err := GenerateEncryptUserKey(masterKey, userA, hid)
    if err != nil {
        t.Fatal(err)
    }
    initiator := NewKeyExchange(userKey, userA, userB, 16, true)

    userKey, err = GenerateEncryptUserKey(masterKey, userB, hid)
    if err != nil {
        t.Fatal(err)
    }

    responder := NewKeyExchange(userKey, userB, userA, 16, true)
    defer func() {
        initiator.Reset()
        responder.Reset()
    }()

    // A1-A4
    k, err := bigFromHex("5879DD1D51E175946F23B1B41E93BA31C584AE59A426EC1046A4D03B06C8")
    initiator.initKeyExchange(hid, k)

    if hex.EncodeToString(initiator.secret.Marshal()) != "7cba5b19069ee66aa79d490413d11846b9ba76dd22567f809cf23b6d964bb265a9760c99cb6f706343fed05637085864958d6c90902aba7d405fbedf7b781599" {
        t.Fatal("not same")
    }

    // B1 - B7
    k, err = bigFromHex("018B98C44BEF9F8537FB7D071B2C928B3BC65BD3D69E1EEE213564905634FE")
    if err != nil {
        t.Fatal(err)
    }

    rB, sigB, err := responder.respondKeyExchange(hid, k, initiator.secret)
    if err != nil {
        t.Fatal(err)
    }

    if hex.EncodeToString(sigB) != expectedSignatureB {
        t.Errorf("not expected signature B")
    }

    // A5 -A8
    key1, sigA, err := initiator.ConfirmResponder(rB, sigB)
    if err != nil {
        t.Fatal(err)
    }
    if hex.EncodeToString(key1) != expectedKey {
        t.Errorf("not expected key %v\n", hex.EncodeToString(key1))
    }
    if hex.EncodeToString(sigA) != expectedSignatureA {
        t.Errorf("not expected signature A")
    }

    // B8
    key2, err := responder.ConfirmInitiator(sigA)
    if err != nil {
        t.Fatal(err)
    }

    if hex.EncodeToString(key2) != expectedKey {
        t.Errorf("not expected key %v\n", hex.EncodeToString(key2))
    }
}
