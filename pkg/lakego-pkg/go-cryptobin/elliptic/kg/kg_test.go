package kg

import (
    "fmt"
    "testing"
    "math/big"
    "crypto/rand"
    "crypto/ecdsa"
    "crypto/elliptic"

    cryptobin_test "github.com/deatil/go-cryptobin/tool/test"
)

func bigintFromHex(s string) *big.Int {
    result, _ := new(big.Int).SetString(s, 16)

    return result
}

func Test_Interface(t *testing.T) {
    var _ elliptic.Curve = (*KGCurve)(nil)
}

func testCurve(t *testing.T, curve *KGCurve) {
    priv, err := ecdsa.GenerateKey(curve, rand.Reader)
    if err != nil {
        t.Fatal(err)
    }

    msg := []byte("test")
    r, s, err := ecdsa.Sign(rand.Reader, priv, msg)
    if err != nil {
        t.Fatal(err)
    }

    if !ecdsa.Verify(&priv.PublicKey, msg, r, s) {
        t.Fatal("signature didn't verify.")
    }
}

type testData struct {
    name  string
    curve *KGCurve
}

func Test_Curve(t *testing.T) {
    tests := []testData{
        {"KG256r1", KG256r1()},
        {"KG384r1", KG384r1()},
    }

    for _, c := range tests {
        t.Run(c.name, func(t *testing.T) {
            testCurve(t, c.curve)
        })
    }
}

func Test_KG256r1_Add(t *testing.T) {
    {
        a1 := bigintFromHex("31d912497c8da31be1c42944737fd652ff63bf08d1e26171042cb1faee3f3c78")
        b1 := bigintFromHex("7634ed1c471d81f523b73f23d00ce9334c51b1a0460b5be6d4fe458502d191f4")
        a2 := bigintFromHex("306cb8769789fa96cc204bccf0b8e9e9014d7d3aa3c35d67ddc0809f971d0f08")
        b2 := bigintFromHex("e8b4742f5c633dd645fb6849ff539ac129113dadd5fe6869e077853e5d701354")

        xx, yy := KG256r1().Add(a1, b1, a2, b2)

        xx2 := fmt.Sprintf("%x", xx.Bytes())
        yy2 := fmt.Sprintf("%x", yy.Bytes())

        xxcheck := "b10a6a2cdb8e1c3a26769cd23549800785f2c574e01114ad9196cac70baea910"
        yycheck := "8c2b60a132ffcaaa9c233bf62e602deb8e8a0746265f378fe3c675c6a6d5c884"

        if xx2 != xxcheck {
            t.Errorf("xx fail, got %s, want %s", xx2, xxcheck)
        }
        if yy2 != yycheck {
            t.Errorf("yy fail, got %s, want %s", yy2, yycheck)
        }
    }

    {
        a1 := bigintFromHex("31d912497c8da31be1c42944737fd652ff63bf08d1e26171042cb1faee3f3c78")
        b1 := bigintFromHex("7634ed1c471d81f523b73f23d00ce9334c51b1a0460b5be6d4fe458502d191f4")

        xx, yy := KG256r1().Add(a1, b1, a1, b1)

        xx2 := fmt.Sprintf("%x", xx.Bytes())
        yy2 := fmt.Sprintf("%x", yy.Bytes())

        xxcheck := "71e26be5fdab949b20e7f01079c1c0d9b6c83e16e61fc71a1a1eca98a354225e"
        yycheck := "94a0c5b1d2820b34ed978d6c76c1d4521f8a63e9793665176d30200ff25ac97a"

        if xx2 != xxcheck {
            t.Errorf("xx fail, got %s, want %s", xx2, xxcheck)
        }
        if yy2 != yycheck {
            t.Errorf("yy fail, got %s, want %s", yy2, yycheck)
        }
    }

    {
        a1 := bigintFromHex("31d912497c8da31be1c42944737fd652ff63bf08d1e26171042cb1faee3f3c78")
        b1 := bigintFromHex("7634ed1c471d81f523b73f23d00ce9334c51b1a0460b5be6d4fe458502d191f4")

        xx, yy := KG256r1().Double(a1, b1)

        xx2 := fmt.Sprintf("%x", xx.Bytes())
        yy2 := fmt.Sprintf("%x", yy.Bytes())

        xxcheck := "71e26be5fdab949b20e7f01079c1c0d9b6c83e16e61fc71a1a1eca98a354225e"
        yycheck := "94a0c5b1d2820b34ed978d6c76c1d4521f8a63e9793665176d30200ff25ac97a"

        if xx2 != xxcheck {
            t.Errorf("xx fail, got %s, want %s", xx2, xxcheck)
        }
        if yy2 != yycheck {
            t.Errorf("yy fail, got %s, want %s", yy2, yycheck)
        }
    }

}

func Test_KG256r1_ScalarMult(t *testing.T) {
    {
        a1 := bigintFromHex("31d912497c8da31be1c42944737fd652ff63bf08d1e26171042cb1faee3f3c78")
        b1 := bigintFromHex("7634ed1c471d81f523b73f23d00ce9334c51b1a0460b5be6d4fe458502d191f4")
        k := bigintFromHex("306cb8769789fa96cc204bccf0b8e9e9014d7d3aa3c35d67ddc0809f971d0f08")

        xx, yy := KG256r1().ScalarMult(a1, b1, k.Bytes())

        xx2 := fmt.Sprintf("%x", xx.Bytes())
        yy2 := fmt.Sprintf("%x", yy.Bytes())

        xxcheck := "3360c80fb6c1381b82f40a38773b7642a35d93d7c4bde1edba99456b9c8757b4"
        yycheck := "51f2a1ae42d926c06acd70fe9a32d06d95bf78f7b98790d1ff508ed1ff77a4d3"

        if xx2 != xxcheck {
            t.Errorf("ScalarMult xx fail, got %s, want %s", xx2, xxcheck)
        }
        if yy2 != yycheck {
            t.Errorf("ScalarMult yy fail, got %s, want %s", yy2, yycheck)
        }
    }

    {
        k := bigintFromHex("306cb8769789fa96cc204bccf0b8e9e9014d7d3aa3c35d67ddc0809f971d0f08")

        xx, yy := KG256r1().ScalarBaseMult(k.Bytes())

        xx2 := fmt.Sprintf("%x", xx.Bytes())
        yy2 := fmt.Sprintf("%x", yy.Bytes())

        xxcheck := "514d5a713a94b4bfe1337d90d4335233f7f9670a85f332311145387b14a8016d"
        yycheck := "1f0ec81e5b7e7622c0081a2ff8a50d15bf4dde578b7854326015d3f59beeaab0"

        if xx2 != xxcheck {
            t.Errorf("ScalarBaseMult xx fail, got %s, want %s", xx2, xxcheck)
        }
        if yy2 != yycheck {
            t.Errorf("ScalarBaseMult yy fail, got %s, want %s", yy2, yycheck)
        }
    }

}

func Test_KG256r1_MarshalCompressed(t *testing.T) {
    a1 := bigintFromHex("31d912497c8da31be1c42944737fd652ff63bf08d1e26171042cb1faee3f3c78")
    b1 := bigintFromHex("7634ed1c471d81f523b73f23d00ce9334c51b1a0460b5be6d4fe458502d191f4")

    m := MarshalCompressed(KG256r1(), a1, b1)

    m2 := fmt.Sprintf("%x", m)
    mcheck := "0231d912497c8da31be1c42944737fd652ff63bf08d1e26171042cb1faee3f3c78"

    cryptobin_test.Equal(t, mcheck, m2)

    mcheck2 := bigintFromHex(mcheck).Bytes()

    x, y := KG256r1().UnmarshalCompressed(mcheck2)
    cryptobin_test.Equal(t, a1, x)
    cryptobin_test.Equal(t, b1, y)
}

func Test_KG384r1_Add(t *testing.T) {
    {
        a1 := bigintFromHex("7e3dce0b0a2cadc6ed7be71e1760429e3f64d2443fad9ffa0817c9233a474bfbbc3e218909afce3826eb0ac6137445aa")
        b1 := bigintFromHex("aa1164ad7e15fbc1a337e1249e2cb244adddf8d406658d35e960cd2260f4b109a735be752d899f6f26e44cc0ad595730")
        a2 := bigintFromHex("c6ff321aa0fa62f2d2e8f4a5220c01ae2636802cd6dd4b1edfbf0e8253c7e4dd14505dc207b41730ac314c5570e0c505")
        b2 := bigintFromHex("60117498d5d441882f3a167ca29abf334d2eb8d75a1f9eae718b6f7e51f8f9c13c44890ad16ce73f2c93e730c3970651")

        xx, yy := KG384r1().Add(a1, b1, a2, b2)

        xx2 := fmt.Sprintf("%x", xx.Bytes())
        yy2 := fmt.Sprintf("%x", yy.Bytes())

        xxcheck := "c34142fe778e7d3aa250a18f61fc5a0db8ae4c23d07ed89296b25cc5b1f66104da27c903a5bb2bc32cbc58165251517e"
        yycheck := "4665be427ede81f02819442e658587c94e4b9ddc28c2e73a1f580b79306e55883ea635348a031036ff8e8ba39d637899"

        if xx2 != xxcheck {
            t.Errorf("xx fail, got %s, want %s", xx2, xxcheck)
        }
        if yy2 != yycheck {
            t.Errorf("yy fail, got %s, want %s", yy2, yycheck)
        }
    }

    {
        a1 := bigintFromHex("7e3dce0b0a2cadc6ed7be71e1760429e3f64d2443fad9ffa0817c9233a474bfbbc3e218909afce3826eb0ac6137445aa")
        b1 := bigintFromHex("aa1164ad7e15fbc1a337e1249e2cb244adddf8d406658d35e960cd2260f4b109a735be752d899f6f26e44cc0ad595730")

        xx, yy := KG384r1().Add(a1, b1, a1, b1)

        xx2 := fmt.Sprintf("%x", xx.Bytes())
        yy2 := fmt.Sprintf("%x", yy.Bytes())

        xxcheck := "3fdb8ec19ccf2cc0d1c8e4d0d19e892f7ef250297bddc80de5168707638fb6a0cf994d1c820f5291f46ed521d09aba34"
        yycheck := "84746ccd33f51146603274207cdf51682bf4baaec8c5d54622f6ad7bcea333896e2fff0502d2f0fa91da9a85fd7a5781"

        if xx2 != xxcheck {
            t.Errorf("xx fail, got %s, want %s", xx2, xxcheck)
        }
        if yy2 != yycheck {
            t.Errorf("yy fail, got %s, want %s", yy2, yycheck)
        }
    }

    {
        a1 := bigintFromHex("7e3dce0b0a2cadc6ed7be71e1760429e3f64d2443fad9ffa0817c9233a474bfbbc3e218909afce3826eb0ac6137445aa")
        b1 := bigintFromHex("aa1164ad7e15fbc1a337e1249e2cb244adddf8d406658d35e960cd2260f4b109a735be752d899f6f26e44cc0ad595730")

        xx, yy := KG384r1().Double(a1, b1)

        xx2 := fmt.Sprintf("%x", xx.Bytes())
        yy2 := fmt.Sprintf("%x", yy.Bytes())

        xxcheck := "3fdb8ec19ccf2cc0d1c8e4d0d19e892f7ef250297bddc80de5168707638fb6a0cf994d1c820f5291f46ed521d09aba34"
        yycheck := "84746ccd33f51146603274207cdf51682bf4baaec8c5d54622f6ad7bcea333896e2fff0502d2f0fa91da9a85fd7a5781"

        if xx2 != xxcheck {
            t.Errorf("xx fail, got %s, want %s", xx2, xxcheck)
        }
        if yy2 != yycheck {
            t.Errorf("yy fail, got %s, want %s", yy2, yycheck)
        }
    }

}

func Test_KG384r1_ScalarMult(t *testing.T) {
    {
        a1 := bigintFromHex("7e3dce0b0a2cadc6ed7be71e1760429e3f64d2443fad9ffa0817c9233a474bfbbc3e218909afce3826eb0ac6137445aa")
        b1 := bigintFromHex("aa1164ad7e15fbc1a337e1249e2cb244adddf8d406658d35e960cd2260f4b109a735be752d899f6f26e44cc0ad595730")
        k := bigintFromHex("c6ff321aa0fa62f2d2e8f4a5220c01ae2636802cd6dd4b1edfbf0e8253c7e4dd14505dc207b41730ac314c5570e0c505")

        xx, yy := KG384r1().ScalarMult(a1, b1, k.Bytes())

        xx2 := fmt.Sprintf("%x", xx.Bytes())
        yy2 := fmt.Sprintf("%x", yy.Bytes())

        xxcheck := "6eca50275d24a10a87ff7551662249d6267fbb02c245bb936aa215393c0462002ecb63b22eb8e6ca211e737e69f6b4bb"
        yycheck := "b26f4cf208eac42990843e013f60c2f36431a2ea975a07b5cb3a91b99eb8bcdd659221e7e55cde306c7c1ace564fabcd"

        if xx2 != xxcheck {
            t.Errorf("ScalarMult xx fail, got %s, want %s", xx2, xxcheck)
        }
        if yy2 != yycheck {
            t.Errorf("ScalarMult yy fail, got %s, want %s", yy2, yycheck)
        }
    }

    {
        k := bigintFromHex("7e3dce0b0a2cadc6ed7be71e1760429e3f64d2443fad9ffa0817c9233a474bfbbc3e218909afce3826eb0ac6137445aa")

        xx, yy := KG384r1().ScalarBaseMult(k.Bytes())

        xx2 := fmt.Sprintf("%x", xx.Bytes())
        yy2 := fmt.Sprintf("%x", yy.Bytes())

        xxcheck := "b4f1d10e2107a6f2a1b7750533ad8c6b507359c69b1e0bc1f67b464320995446ca80ec8f6500d3facde99621f7bdcc5c"
        yycheck := "0451a63ea96b22760bc852db409560aa71b8f914a25f316c1c0e1e1e4e77c49d5520314aa0725ce5834cfce2862ff2e9"

        if xx2 != xxcheck {
            t.Errorf("ScalarBaseMult xx fail, got %s, want %s", xx2, xxcheck)
        }
        if yy2 != yycheck {
            t.Errorf("ScalarBaseMult yy fail, got %s, want %s", yy2, yycheck)
        }
    }

}

func Test_KG384r1_MarshalCompressed(t *testing.T) {
    a1 := bigintFromHex("7e3dce0b0a2cadc6ed7be71e1760429e3f64d2443fad9ffa0817c9233a474bfbbc3e218909afce3826eb0ac6137445aa")
    b1 := bigintFromHex("aa1164ad7e15fbc1a337e1249e2cb244adddf8d406658d35e960cd2260f4b109a735be752d899f6f26e44cc0ad595730")

    m := MarshalCompressed(KG384r1(), a1, b1)

    m2 := fmt.Sprintf("%x", m)
    mcheck := "027e3dce0b0a2cadc6ed7be71e1760429e3f64d2443fad9ffa0817c9233a474bfbbc3e218909afce3826eb0ac6137445aa"

    cryptobin_test.Equal(t, mcheck, m2)

    mcheck2 := bigintFromHex(mcheck).Bytes()

    x, y := KG384r1().UnmarshalCompressed(mcheck2)
    cryptobin_test.Equal(t, a1, x)
    cryptobin_test.Equal(t, b1, y)
}
