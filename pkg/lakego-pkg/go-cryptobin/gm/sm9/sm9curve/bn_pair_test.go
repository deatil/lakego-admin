package sm9curve

import (
    "math/big"
    "testing"
)

var expected1 = &gfP12{}
var expected_b2 = &gfP12{}
var expected_b2_2 = &gfP12{}

func init() {
    expected1.x.x.x = *fromBigInt(bigFromHex("4e378fb5561cd0668f906b731ac58fee25738edf09cadc7a29c0abc0177aea6d"))
    expected1.x.x.y = *fromBigInt(bigFromHex("28b3404a61908f5d6198815c99af1990c8af38655930058c28c21bb539ce0000"))
    expected1.x.y.x = *fromBigInt(bigFromHex("b3129a75d31d17194675a1bc56947920898fbf390a5bf5d931ce6cbb3340f66d"))
    expected1.x.y.y = *fromBigInt(bigFromHex("4c744e69c4a2e1c8ed72f796d151a17ce2325b943260fc460b9f73cb57c9014b"))
    expected1.x.z.x = *fromBigInt(bigFromHex("1604a3fcfa9783e667ce9fcb1062c2a5c6685c316dda62de0548baa6ba30038b"))
    expected1.x.z.y = *fromBigInt(bigFromHex("93634f44fa13af76169f3cc8fbea880adaff8475d5fd28a75deb83c44362b439"))
    expected1.y.x.x = *fromBigInt(bigFromHex("67e0e0c2eed7a6993dce28fe9aa2ef56834307860839677f96685f2b44d0911f"))
    expected1.y.x.y = *fromBigInt(bigFromHex("5a1ae172102efd95df7338dbc577c66d8d6c15e0a0158c7507228efb078f42a6"))
    expected1.y.y.x = *fromBigInt(bigFromHex("38bffe40a22d529a0c66124b2c308dac9229912656f62b4facfced408e02380f"))
    expected1.y.y.y = *fromBigInt(bigFromHex("a01f2c8bee81769609462c69c96aa923fd863e209d3ce26dd889b55e2e3873db"))
    expected1.y.z.x = *fromBigInt(bigFromHex("84b87422330d7936eaba1109fa5a7a7181ee16f2438b0aeb2f38fd5f7554e57a"))
    expected1.y.z.y = *fromBigInt(bigFromHex("aab9f06a4eeba4323a7833db202e4e35639d93fa3305af73f0f071d7d284fcfb"))

    expected_b2.x.x.x = *fromBigInt(bigFromHex("28542fb6954c84be6a5f2988a31cb6817ba0781966fa83d9673a9577d3c0c134"))
    expected_b2.x.x.y = *fromBigInt(bigFromHex("5e27c19fc02ed9ae37f5bb7be9c03c2b87de027539ccf03e6b7d36de4ab45cd1"))
    expected_b2.x.y.x = *fromBigInt(bigFromHex("8c8e9d8d905780d50e779067f2c4b1c8f83a8b59d735bb52af35f56730bde5ac"))
    expected_b2.x.y.y = *fromBigInt(bigFromHex("861ccd9978617267ce4ad9789f77739e62f2e57b48c2ff26d2e90a79a1d86b93"))
    expected_b2.x.z.x = *fromBigInt(bigFromHex("73f21693c66fc23724db26380c526223c705daf6ba18b763a68623c86a632b05"))
    expected_b2.x.z.y = *fromBigInt(bigFromHex("0f63a071a6d62ea45b59a1942dff5335d1a232c9c5664fad5d6af54c11418b0d"))
    expected_b2.y.x.x = *fromBigInt(bigFromHex("4fec93472da33a4db6599095c0cf895e3a7b993ee5e4ebe3b9ab7d7d5ff2a3d1"))
    expected_b2.y.x.y = *fromBigInt(bigFromHex("647ba154c3e8e185dfc33657c1f128d480f3f7e3f16801208029e19434c733bb"))
    expected_b2.y.y.x = *fromBigInt(bigFromHex("a1abfcd30c57db0f1a838e3a8f2bf823479c978bd137230506ea6249c891049e"))
    expected_b2.y.y.y = *fromBigInt(bigFromHex("3497477913ab89f5e2960f382b1b5c8ee09de0fa498ba95c4409d630d343da40"))
    expected_b2.y.z.x = *fromBigInt(bigFromHex("9b1ca08f64712e33aeda3f44bd6cb633e0f722211e344d73ec9bbebc92142765"))
    expected_b2.y.z.y = *fromBigInt(bigFromHex("6ba584ce742a2a3ab41c15d3ef94edeb8ef74a2bdcdaaecc09aba567981f6437"))

    expected_b2_2.x.x.x = *fromBigInt(bigFromHex("1052d6e9d13e381909dff7b2b41e13c987d0a9068423b769480dacce6a06f492"))
    expected_b2_2.x.x.y = *fromBigInt(bigFromHex("5ffeb92ad870f97dc0893114da22a44dbc9e7a8b6ca31a0cf0467265a1fb48c7"))
    expected_b2_2.x.y.x = *fromBigInt(bigFromHex("10cc2b561a62b62da36aefd60850714f49170fd94a0010c6d4b651b64f3a3a5e"))
    expected_b2_2.x.y.y = *fromBigInt(bigFromHex("58c9687beddcd9e4fedab16b884d1fe6dfa117b2ab821f74e0bf7acda2269859"))
    expected_b2_2.x.z.x = *fromBigInt(bigFromHex("00dd2b7416baa91172e89d5309d834f78c1e31b4483bb97185931bad7be1b9b5"))
    expected_b2_2.x.z.y = *fromBigInt(bigFromHex("7ebac0349f8544469e60c32f6075fb0468a68147ff013537df792ffce024f857"))
    expected_b2_2.y.x.x = *fromBigInt(bigFromHex("0ae7bf3e1aec0cb67a03440906c7dfb3bcd4b6eeebb7e371f0094ad4a816088d"))
    expected_b2_2.y.x.y = *fromBigInt(bigFromHex("98dbc791d0671caca12236cdf8f39e15aeb96faeb39606d5b04ac581746a663d"))
    expected_b2_2.y.y.x = *fromBigInt(bigFromHex("2c5c3b37e4f2ff83db33d98c0317bcbbbbf4ac6df6b89eca58268b280045e612"))
    expected_b2_2.y.y.y = *fromBigInt(bigFromHex("6ced9e2d7c9cd3d5ad630defab0b831506218037ee0f861cf9b43c78434aec38"))
    expected_b2_2.y.z.x = *fromBigInt(bigFromHex("2a430968f16086061904ce201847934b11ca0f9e9528f5a9d0ce8f015c9aea79"))
    expected_b2_2.y.z.y = *fromBigInt(bigFromHex("934fdda6d3ab48c8571ce2354b79742aa498cb8cdde6bd1fa5946345a1a652f6"))
}

func Test_Pairing_A2(t *testing.T) {
    pk := bigFromHex("0130E78459D78545CB54C587E02CF480CE0B66340F319F348A1D5B1F2DC5F4")
    g2 := &G2{}
    _, err := g2.ScalarBaseMult(NormalizeScalar(pk.Bytes()))
    if err != nil {
        t.Fatal(err)
    }
    ret := pairing(g2.p, curveGen)
    if *ret != *expected1 {
        t.Errorf("not expected")
    }
}

func Test_Pairing_B2(t *testing.T) {
    deB := &twistPoint{}
    deB.x.x = *fromBigInt(bigFromHex("74CCC3AC9C383C60AF083972B96D05C75F12C8907D128A17ADAFBAB8C5A4ACF7"))
    deB.x.y = *fromBigInt(bigFromHex("01092FF4DE89362670C21711B6DBE52DCD5F8E40C6654B3DECE573C2AB3D29B2"))
    deB.y.x = *fromBigInt(bigFromHex("44B0294AA04290E1524FF3E3DA8CFD432BB64DE3A8040B5B88D1B5FC86A4EBC1"))
    deB.y.y = *fromBigInt(bigFromHex("8CFC48FB4FF37F1E27727464F3C34E2153861AD08E972D1625FC1A7BD18D5539"))
    deB.z.SetOne()
    deB.t.SetOne()

    rA := &curvePoint{}
    rA.x = *fromBigInt(bigFromHex("7CBA5B19069EE66AA79D490413D11846B9BA76DD22567F809CF23B6D964BB265"))
    rA.y = *fromBigInt(bigFromHex("A9760C99CB6F706343FED05637085864958D6C90902ABA7D405FBEDF7B781599"))
    rA.z = *one
    rA.t = *one

    ret := pairing(deB, rA)
    if *ret != *expected_b2 {
        t.Errorf("not expected")
    }
}

func Test_Pairing_B2_2(t *testing.T) {
    pubE := &curvePoint{}
    pubE.x = *fromBigInt(bigFromHex("9174542668E8F14AB273C0945C3690C66E5DD09678B86F734C4350567ED06283"))
    pubE.y = *fromBigInt(bigFromHex("54E598C6BF749A3DACC9FFFEDD9DB6866C50457CFC7AA2A4AD65C3168FF74210"))
    pubE.z = *one
    pubE.t = *one

    ret := pairing(twistGen, pubE)
    ret.Exp(ret, bigFromHex("00018B98C44BEF9F8537FB7D071B2C928B3BC65BD3D69E1EEE213564905634FE"))
    if *ret != *expected_b2_2 {
        t.Errorf("not expected")
    }
}

func Test_finalExponentiation(t *testing.T) {
    x := &gfP12{
        p6,
        p6,
    }
    got := finalExponentiation(x)

    exp := new(big.Int).Exp(p, big.NewInt(12), nil)
    exp.Sub(exp, big.NewInt(1))
    exp.Div(exp, Order)
    expected := (&gfP12{}).Exp(x, exp)

    if *got != *expected {
        t.Errorf("got %v, expected %v\n", got, expected)
    }
}

func BenchmarkFinalExponentiation(b *testing.B) {
    x := &gfP12{
        p6,
        p6,
    }
    exp := new(big.Int).Exp(p, big.NewInt(12), nil)
    exp.Sub(exp, big.NewInt(1))
    exp.Div(exp, Order)
    expected := (&gfP12{}).Exp(x, exp)

    b.ReportAllocs()
    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        got := finalExponentiation(x)
        if *got != *expected {
            b.Errorf("got %v, expected %v\n", got, expected)
        }
    }
}

func BenchmarkPairingB4(b *testing.B) {
    pk := bigFromHex("0130E78459D78545CB54C587E02CF480CE0B66340F319F348A1D5B1F2DC5F4")
    g2 := &G2{}
    _, err := g2.ScalarBaseMult(NormalizeScalar(pk.Bytes()))
    if err != nil {
        b.Fatal(err)
    }
    b.ReportAllocs()
    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        ret := pairing(g2.p, curveGen)
        if *ret != *expected1 {
            b.Errorf("not expected")
        }
    }
}
