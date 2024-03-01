package gost

import (
    "bytes"
    "crypto/rand"
    "testing"
    "testing/quick"
)

// default ukm bytes
var defaultUkm = []byte("12345678")

func Test_KEK(t *testing.T) {
    c := CurveIdGostR34102001TestParamSet()

    priv1, err := GenerateKey(rand.Reader, c)
    if err != nil {
        t.Fatal(err)
    }
    pub1 := &priv1.PublicKey

    priv2, err := GenerateKey(rand.Reader, c)
    if err != nil {
        t.Fatal(err)
    }
    pub2 := &priv2.PublicKey

    key1, _ := KEK(priv1, pub2, NewUKM(defaultUkm))
    key2, _ := KEK(priv2, pub1, NewUKM(defaultUkm))

    if !bytes.Equal(key1, key2) {
        t.Error("key1 is not equal key2")
    }
}

func Test_KEK_Bad(t *testing.T) {
    c := CurveIdGostR34102001TestParamSet()
    c2 := CurveGostR34102001ParamSetcc()

    priv1, err := GenerateKey(rand.Reader, c)
    if err != nil {
        t.Fatal(err)
    }

    priv2, err := GenerateKey(rand.Reader, c2)
    if err != nil {
        t.Fatal(err)
    }
    pub2 := &priv2.PublicKey

    _, err = KEK(priv1, pub2, NewUKM(defaultUkm))
    if err == nil {
        t.Error("KEK should return error")
    }
}

func Test_VKO2001(t *testing.T) {
    c := CurveIdGostR34102001TestParamSet()

    ukmRaw := decodeHex("5172be25f852a233")
    ukm := NewUKM(ukmRaw)

    prv1 := decodeHex("1df129e43dab345b68f6a852f4162dc69f36b2f84717d08755cc5c44150bf928")
    priv1, err := NewPrivateKey(c, prv1)
    if err != nil {
        t.Fatal(err)
    }

    prv2 := decodeHex("5b9356c6474f913f1e83885ea0edd5df1a43fd9d799d219093241157ac9ed473")
    priv2, err := NewPrivateKey(c, prv2)
    if err != nil {
        t.Fatal(err)
    }

    kek := decodeHex("ee4618a0dbb10cb31777b4b86a53d9e7ef6cb3e400101410f0c0f2af46c494a6")

    pub1 := &priv1.PublicKey
    pub2 := &priv2.PublicKey

    key1, _ := KEK2001(priv1, pub2, ukm)
    key2, _ := KEK2001(priv2, pub1, ukm)

    if !bytes.Equal(key1, key2) {
        t.Error("key1 is not equal key2")
    }

    if !bytes.Equal(key1, kek) {
        t.Errorf("key1 is not equal kek, got %x, want %x", key1, kek)
    }
}

func Test_VKO2012256(t *testing.T) {
    c := CurveIdtc26gost341012512paramSetA()
    ukmRaw := decodeHex("1d80603c8544c727")
    ukm := NewUKM(ukmRaw)

    prvRawA := decodeHex("c990ecd972fce84ec4db022778f50fcac726f46708384b8d458304962d7147f8c2db41cef22c90b102f2968404f9b9be6d47c79692d81826b32b8daca43cb667")
    pubRawA := decodeHex("aab0eda4abff21208d18799fb9a8556654ba783070eba10cb9abb253ec56dcf5d3ccba6192e464e6e5bcb6dea137792f2431f6c897eb1b3c0cc14327b1adc0a7914613a3074e363aedb204d38d3563971bd8758e878c9db11403721b48002d38461f92472d40ea92f9958c0ffa4c93756401b97f89fdbe0b5e46e4a4631cdb5a")
    prvRawB := decodeHex("48c859f7b6f11585887cc05ec6ef1390cfea739b1a18c0d4662293ef63b79e3b8014070b44918590b4b996acfea4edfbbbcccc8c06edd8bf5bda92a51392d0db")
    pubRawB := decodeHex("192fe183b9713a077253c72c8735de2ea42a3dbc66ea317838b65fa32523cd5efca974eda7c863f4954d1147f1f2b25c395fce1c129175e876d132e94ed5a65104883b414c9b592ec4dc84826f07d0b6d9006dda176ce48c391e3f97d102e03bb598bf132a228a45f7201aba08fc524a2d77e43a362ab022ad4028f75bde3b79")

    pubA, _ := NewPublicKey(c, pubRawA)
    pubB, _ := NewPublicKey(c, pubRawB)

    kek := decodeHex("c9a9a77320e2cc559ed72dce6f47e2192ccea95fa648670582c054c0ef36c221")

    prvA, err := NewPrivateKey(c, prvRawA)
    if err != nil {
        t.Fatal(err)
    }
    prvB, err := NewPrivateKey(c, prvRawB)
    if err != nil {
        t.Fatal(err)
    }

    kekA, _ := prvA.KEK2012256(pubB, ukm)
    kekB, _ := prvB.KEK2012256(pubA, ukm)
    if !bytes.Equal(kekA, kekB) {
        t.Error("kekA is not equal kekB")
    }
    if !bytes.Equal(kekA, kek) {
        t.Errorf("kekA is not equal kek, got %x, want %x", kekA, kek)
    }
}

func test_RandomVKO2012256(t *testing.T) {
    c := CurveIdtc26gost341012512paramSetA()
    f := func(prvRaw1 [64]byte, prvRaw2 [64]byte, ukmRaw [8]byte) bool {
        prv1, err := NewPrivateKey(c, prvRaw1[:])
        if err != nil {
            return false
        }
        prv2, err := NewPrivateKey(c, prvRaw2[:])
        if err != nil {
            return false
        }

        pub1 := &prv1.PublicKey
        pub2 := &prv2.PublicKey

        ukm := NewUKM(ukmRaw[:])

        kek1, _ := prv1.KEK2012256(pub2, ukm)
        kek2, _ := prv2.KEK2012256(pub1, ukm)
        return bytes.Equal(kek1, kek2)
    }
    if err := quick.Check(f, nil); err != nil {
        t.Error(err)
    }
}

func Test_VKO2012512(t *testing.T) {
    c := CurveIdtc26gost341012512paramSetA()

    ukmRaw := decodeHex("1d80603c8544c727")
    ukm := NewUKM(ukmRaw)

    prvRawA := decodeHex("c990ecd972fce84ec4db022778f50fcac726f46708384b8d458304962d7147f8c2db41cef22c90b102f2968404f9b9be6d47c79692d81826b32b8daca43cb667")
    pubRawA := decodeHex("aab0eda4abff21208d18799fb9a8556654ba783070eba10cb9abb253ec56dcf5d3ccba6192e464e6e5bcb6dea137792f2431f6c897eb1b3c0cc14327b1adc0a7914613a3074e363aedb204d38d3563971bd8758e878c9db11403721b48002d38461f92472d40ea92f9958c0ffa4c93756401b97f89fdbe0b5e46e4a4631cdb5a")
    prvRawB := decodeHex("48c859f7b6f11585887cc05ec6ef1390cfea739b1a18c0d4662293ef63b79e3b8014070b44918590b4b996acfea4edfbbbcccc8c06edd8bf5bda92a51392d0db")
    pubRawB := decodeHex("192fe183b9713a077253c72c8735de2ea42a3dbc66ea317838b65fa32523cd5efca974eda7c863f4954d1147f1f2b25c395fce1c129175e876d132e94ed5a65104883b414c9b592ec4dc84826f07d0b6d9006dda176ce48c391e3f97d102e03bb598bf132a228a45f7201aba08fc524a2d77e43a362ab022ad4028f75bde3b79")

    pubA, _ := NewPublicKey(c, pubRawA)
    pubB, _ := NewPublicKey(c, pubRawB)

    kek := decodeHex("79f002a96940ce7bde3259a52e015297adaad84597a0d205b50e3e1719f97bfa7ee1d2661fa9979a5aa235b558a7e6d9f88f982dd63fc35a8ec0dd5e242d3bdf")

    prvA, err := NewPrivateKey(c, prvRawA)
    if err != nil {
        t.Fatal(err)
    }
    prvB, err := NewPrivateKey(c, prvRawB)
    if err != nil {
        t.Fatal(err)
    }

    kekA, _ := prvA.KEK2012512(pubB, ukm)
    kekB, _ := prvB.KEK2012512(pubA, ukm)

    if !bytes.Equal(kekA, kekB) {
        t.Error("kekA is not equal kekB")
    }
    if !bytes.Equal(kekA, kek) {
        t.Errorf("kekA is not equal kek, got %x, want %x", kekA, kek)
    }
}

func test_RandomVKO2012512(t *testing.T) {
    c := CurveIdtc26gost341012512paramSetA()
    f := func(prvRaw1 [64]byte, prvRaw2 [64]byte, ukmRaw [8]byte) bool {
        prv1, err := NewPrivateKey(c, prvRaw1[:])
        if err != nil {
            return false
        }
        prv2, err := NewPrivateKey(c, prvRaw2[:])
        if err != nil {
            return false
        }

        pub1 := &prv1.PublicKey
        pub2 := &prv2.PublicKey

        ukm := NewUKM(ukmRaw[:])

        kek1, _ := prv1.KEK2012512(pub2, ukm)
        kek2, _ := prv2.KEK2012512(pub1, ukm)
        return bytes.Equal(kek1, kek2)
    }
    if err := quick.Check(f, nil); err != nil {
        t.Error(err)
    }
}
