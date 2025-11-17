package s256

import (
    "fmt"
    "testing"
    "math/big"
    "crypto/elliptic"
)

func Test_Interface(t *testing.T) {
    var _ elliptic.Curve = (*S256Curve)(nil)
}

func Test_S256_Curve_Add(t *testing.T) {
    {
        a1 := toBigint("dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659")
        b1 := toBigint("2ce19b946c4ee58546f5251d441a065ea50735606985e5b228788bec4e582898")
        a2 := toBigint("dd308afec5777e13121fa72b9cc1b7cc0139715309b086c960e18fd969774eb8")
        b2 := toBigint("f594bb5f72b37faae396a4259ea64ed5e6fdeb2a51c6467582b275925fab1394")

        xx, yy := S256().Add(a1, b1, a2, b2)

        xx2 := fmt.Sprintf("%x", xx.Bytes())
        yy2 := fmt.Sprintf("%x", yy.Bytes())

        xxcheck := "0b4b8b19e1666914c37647bf3eac2acc4348b02ef8b1f2940c8bf10a381df22c"
        yycheck := "1fbbb6a4be23f0019261e05f4d26114059b001649b998160020c0c4c31000ce5"

        if xx2 != xxcheck {
            t.Errorf("xx fail, got %s, want %s", xx2, xxcheck)
        }
        if yy2 != yycheck {
            t.Errorf("yy fail, got %s, want %s", yy2, yycheck)
        }
    }

    {
        a1 := toBigint("dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659")
        b1 := toBigint("2ce19b946c4ee58546f5251d441a065ea50735606985e5b228788bec4e582898")

        xx, yy := S256().Add(a1, b1, a1, b1)

        xx2 := fmt.Sprintf("%x", xx.Bytes())
        yy2 := fmt.Sprintf("%x", yy.Bytes())

        xxcheck := "768c61d8c3acc2bbbf37dec4e62b9c481802fd817a4dbc7d5542f02375412945"
        yycheck := "e227f7076346296e92364b75508102d997f66170764bcffb2bce80ff0e77be0a"

        if xx2 != xxcheck {
            t.Errorf("xx fail, got %s, want %s", xx2, xxcheck)
        }
        if yy2 != yycheck {
            t.Errorf("yy fail, got %s, want %s", yy2, yycheck)
        }
    }

    {
        a1 := toBigint("dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659")
        b1 := toBigint("2ce19b946c4ee58546f5251d441a065ea50735606985e5b228788bec4e582898")

        xx, yy := S256().Double(a1, b1)

        xx2 := fmt.Sprintf("%x", xx.Bytes())
        yy2 := fmt.Sprintf("%x", yy.Bytes())

        xxcheck := "768c61d8c3acc2bbbf37dec4e62b9c481802fd817a4dbc7d5542f02375412945"
        yycheck := "e227f7076346296e92364b75508102d997f66170764bcffb2bce80ff0e77be0a"

        if xx2 != xxcheck {
            t.Errorf("xx fail, got %s, want %s", xx2, xxcheck)
        }
        if yy2 != yycheck {
            t.Errorf("yy fail, got %s, want %s", yy2, yycheck)
        }
    }

}

func toBigint(s string) *big.Int {
    result, _ := new(big.Int).SetString(s, 16)

    return result
}
