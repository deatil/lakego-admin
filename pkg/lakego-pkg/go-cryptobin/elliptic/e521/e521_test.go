package e521

import (
    "fmt"
    "testing"
    "math/big"
    "crypto/elliptic"

    cryptobin_test "github.com/deatil/go-cryptobin/tool/test"
)

func bigintFromHex(s string) *big.Int {
    result, _ := new(big.Int).SetString(s, 16)

    return result
}

func Test_Interface(t *testing.T) {
    var _ elliptic.Curve = (*E521Curve)(nil)
}

func Test_Curve_Add(t *testing.T) {
    {
        a1 := bigintFromHex("135e8ba63870ade80365ee6b6832d971a83c8519310bed795809637bd61e4d54676d0823d7a95d26291be2742994d833b16d306dcea0574b57924aac6b62552ef81")
        b1 := bigintFromHex("d6e622c17fb2723b47ef82f0a704694689c96c5cc12f24b42a735b89283c6bd47fe0596dff8841603414b8b3a5c681d72750e03a807f6668a008738876e2f1fcde")
        a2 := bigintFromHex("10ffba2f442444980490d51fb67b6b29f30a96e00aeebb058fb396f1d56862925f84a403612cf7a32586abe1e8085f44e28426a2f0684c9e7adbfaf99bd2788aad0")
        b2 := bigintFromHex("5d33e51bfe1cbb3c263ad569b213be723a45920ac38070147d8d85c1779b4fe4eaa0912a17765f2d87bb2ac27106fb8d019152c373e9ea060f591c1d85141cc830")

        xx, yy := E521().Add(a1, b1, a2, b2)

        xx2 := fmt.Sprintf("%x", xx.Bytes())
        yy2 := fmt.Sprintf("%x", yy.Bytes())

        xxcheck := "01c48fda4d86a4610f4211f0f7bf4f5fdfe0da463028bd86b4827fd26717404fa8eb0433cdd040611a776a3de97a1f4882dbb5688984ad48739d9d48eaeee413f644"
        yycheck := "01a7c2f2d27327cb4a53894392198c9a5b6563c43c92912f90b0efe86d618770a9d7911573919c0a37942e6a7fc484dd59b917849c6c2e9a400f9bb7c46486fe9c4a"

        if xx2 != xxcheck {
            t.Errorf("xx fail, got %s, want %s", xx2, xxcheck)
        }
        if yy2 != yycheck {
            t.Errorf("yy fail, got %s, want %s", yy2, yycheck)
        }
    }

    {
        a1 := bigintFromHex("135e8ba63870ade80365ee6b6832d971a83c8519310bed795809637bd61e4d54676d0823d7a95d26291be2742994d833b16d306dcea0574b57924aac6b62552ef81")
        b1 := bigintFromHex("d6e622c17fb2723b47ef82f0a704694689c96c5cc12f24b42a735b89283c6bd47fe0596dff8841603414b8b3a5c681d72750e03a807f6668a008738876e2f1fcde")

        xx, yy := E521().Add(a1, b1, a1, b1)

        xx2 := fmt.Sprintf("%x", xx.Bytes())
        yy2 := fmt.Sprintf("%x", yy.Bytes())

        xxcheck := "019f5208229540e4292ac78b021184e00ee1cc5d0c15edf9b9d05d7466fcc93d38c5afa8ab13db1fab07163fe91ad2d0a6aca4377995230e4a685e6d19c1e0457594"
        yycheck := "01fbce936f5787a4a778aeaece860985404b226ad1de63ded30ec88acd2335686022c2622f1abf537a21d8685b7c3d590980fa358640279761e0e50d8eae6ac5e716"

        if xx2 != xxcheck {
            t.Errorf("xx fail, got %s, want %s", xx2, xxcheck)
        }
        if yy2 != yycheck {
            t.Errorf("yy fail, got %s, want %s", yy2, yycheck)
        }
    }

    {
        a1 := bigintFromHex("135e8ba63870ade80365ee6b6832d971a83c8519310bed795809637bd61e4d54676d0823d7a95d26291be2742994d833b16d306dcea0574b57924aac6b62552ef81")
        b1 := bigintFromHex("d6e622c17fb2723b47ef82f0a704694689c96c5cc12f24b42a735b89283c6bd47fe0596dff8841603414b8b3a5c681d72750e03a807f6668a008738876e2f1fcde")

        xx, yy := E521().Double(a1, b1)

        xx2 := fmt.Sprintf("%x", xx.Bytes())
        yy2 := fmt.Sprintf("%x", yy.Bytes())

        xxcheck := "019f5208229540e4292ac78b021184e00ee1cc5d0c15edf9b9d05d7466fcc93d38c5afa8ab13db1fab07163fe91ad2d0a6aca4377995230e4a685e6d19c1e0457594"
        yycheck := "01fbce936f5787a4a778aeaece860985404b226ad1de63ded30ec88acd2335686022c2622f1abf537a21d8685b7c3d590980fa358640279761e0e50d8eae6ac5e716"

        if xx2 != xxcheck {
            t.Errorf("xx fail, got %s, want %s", xx2, xxcheck)
        }
        if yy2 != yycheck {
            t.Errorf("yy fail, got %s, want %s", yy2, yycheck)
        }
    }

}

func Test_Curve_ScalarMult(t *testing.T) {
    {
        a1 := bigintFromHex("135e8ba63870ade80365ee6b6832d971a83c8519310bed795809637bd61e4d54676d0823d7a95d26291be2742994d833b16d306dcea0574b57924aac6b62552ef81")
        b1 := bigintFromHex("d6e622c17fb2723b47ef82f0a704694689c96c5cc12f24b42a735b89283c6bd47fe0596dff8841603414b8b3a5c681d72750e03a807f6668a008738876e2f1fcde")
        k := bigintFromHex("10ffba2f442444980490d51fb67b6b29f30a96e00aeebb058fb396f1d56862925f84a403612cf7a32586abe1e8085f44e28426a2f0684c9e7adbfaf99bd2788aad0")

        xx, yy := E521().ScalarMult(a1, b1, k.Bytes())

        xx2 := fmt.Sprintf("%x", xx.Bytes())
        yy2 := fmt.Sprintf("%x", yy.Bytes())

        xxcheck := "01a98e644ddba5669827421d37c0e61b4d068eec3efa6179ff8707550549203480e024d9c2efa628141bef46cb4e3cbd5dbf000aca18bf1ff4955d9cd5b10962c097"
        yycheck := "0115bd2e2c3c57eeb764e5a0f50cb09e6c373148edca4f538531a82fccd5c4ccce9a1fc95f6f15e4066a31a96fca46f066ca45970eb8f6e716279adc28331d8a15b6"

        if xx2 != xxcheck {
            t.Errorf("ScalarMult xx fail, got %s, want %s", xx2, xxcheck)
        }
        if yy2 != yycheck {
            t.Errorf("ScalarMult yy fail, got %s, want %s", yy2, yycheck)
        }
    }

    {
        k := bigintFromHex("10ffba2f442444980490d51fb67b6b29f30a96e00aeebb058fb396f1d56862925f84a403612cf7a32586abe1e8085f44e28426a2f0684c9e7adbfaf99bd2788aad0")

        xx, yy := E521().ScalarBaseMult(k.Bytes())

        xx2 := fmt.Sprintf("%x", xx.Bytes())
        yy2 := fmt.Sprintf("%x", yy.Bytes())

        xxcheck := "2eb2b005910a542b0ca6fc9fd8b9b89a413f7d020930d20bc1e45c7b5a4f0ed7190095f5e7d0da8ca617c5dd092c080bd1cf594c00ff778271c6551d6b90a6d655"
        yycheck := "013ae58d3fa3eb8a3c8064fb7f27132c4227f7211ca71d0952f70820a3789b63de36b741d7f0568aa4b7d433c7420ca2f31065da9dff4e978f19e590e7ce4ae4c850"

        if xx2 != xxcheck {
            t.Errorf("ScalarBaseMult xx fail, got %s, want %s", xx2, xxcheck)
        }
        if yy2 != yycheck {
            t.Errorf("ScalarBaseMult yy fail, got %s, want %s", yy2, yycheck)
        }
    }

}

func Test_MarshalCompressed(t *testing.T) {
    a1 := bigintFromHex("135e8ba63870ade80365ee6b6832d971a83c8519310bed795809637bd61e4d54676d0823d7a95d26291be2742994d833b16d306dcea0574b57924aac6b62552ef81")
    b1 := bigintFromHex("d6e622c17fb2723b47ef82f0a704694689c96c5cc12f24b42a735b89283c6bd47fe0596dff8841603414b8b3a5c681d72750e03a807f6668a008738876e2f1fcde")

    m := MarshalCompressed(E521(), a1, b1)

    m2 := fmt.Sprintf("%x", m)
    mcheck := "defcf1e276887308a068667f803ae05027d781c6a5b3b81434604188ff6d59e07fd46b3c28895b732ab4242fc15c6cc989466904a7f082ef473b72b27fc122e6d680"

    cryptobin_test.Equal(t, mcheck, m2)

    mcheck2 := bigintFromHex(mcheck).Bytes()

    x, y := UnmarshalCompressed(E521(), mcheck2)
    cryptobin_test.Equal(t, a1, x)
    cryptobin_test.Equal(t, b1, y)
}
