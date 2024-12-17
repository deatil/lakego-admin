package secp

import (
    "bytes"
    "testing"
    "encoding/hex"
    "crypto/rand"
    "crypto/ecdsa"
    "crypto/elliptic"
)

func fromHex(s string) []byte {
    h, _ := hex.DecodeString(s)
    return h
}

func testCurve(t *testing.T, curve elliptic.Curve) {
    priv, err := ecdsa.GenerateKey(curve, rand.Reader)
    if err != nil {
        t.Fatal(err)
    }

    msg := []byte("test-data test-data test-data test-data test-data test-data test-data test-data")

    r, s, err := ecdsa.Sign(rand.Reader, priv, msg)
    if err != nil {
        t.Fatal(err)
    }

    if !ecdsa.Verify(&priv.PublicKey, msg, r, s) {
        t.Fatal("signature didn't verify.")
    }
}

func Test_All(t *testing.T) {
    t.Run("P192", func(t *testing.T) {
        testCurve(t, P192())
    })
    t.Run("P192r1", func(t *testing.T) {
        testCurve(t, P192r1())
    })

    t.Run("P160r1", func(t *testing.T) {
        testCurve(t, P160r1())
    })
    t.Run("P160r2", func(t *testing.T) {
        testCurve(t, P160r2())
    })

    t.Run("P128r1", func(t *testing.T) {
        testCurve(t, P128r1())
    })
    /*
    t.Run("P128r2", func(t *testing.T) {
        testCurve(t, P128r2())
    })
    */

    /*
    t.Run("P112r1", func(t *testing.T) {
        testCurve(t, P112r1())
    })
    t.Run("P112r2", func(t *testing.T) {
        testCurve(t, P112r2())
    })
    */
}

func Test_Add(t *testing.T) {
    for _, td := range testAdds {
        x1 := bigFromHex(td.x1)
        z1 := bigFromHex(td.z1)
        x2 := bigFromHex(td.x2)
        z2 := bigFromHex(td.z2)

        px := fromHex(td.sumX)
        py := fromHex(td.sumZ)

        x, y := P192().Add(x1, z1, x2, z2)

        xx := x.Bytes()
        yy := y.Bytes()

        if !bytes.Equal(xx, px) {
            t.Errorf("make x fail, got %x, want %x", xx, px)
        }
        if !bytes.Equal(yy, py) {
            t.Errorf("make y fail, got %x, want %x", yy, py)
        }
    }
}

type testAdd struct {
    x1 string
    z1 string
    x2 string
    z2 string
    sumX string
    sumZ string
}

var testAdds = []testAdd{
    {
        "188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012",
        "07192B95FFC8DA78631011ED6B24CDD573F977A11E794811",
        "DAFEBF5828783F2AD35534631588A3F629A70FB16982A888",
        "DD6BDA0D993DA0FA46B27BBC141B868F59331AFA5C7E93AB",
        "76E32A2557599E6EDCD283201FB2B9AADFD0D359CBB263DA",
        "782C37E372BA4520AA62E0FED121D49EF3B543660CFD05FD",
    },
    {
        "188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012",
        "07192B95FFC8DA78631011ED6B24CDD573F977A11E794811",
        "188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012",
        "07192B95FFC8DA78631011ED6B24CDD573F977A11E794811",
        "DAFEBF5828783F2AD35534631588A3F629A70FB16982A888",
        "DD6BDA0D993DA0FA46B27BBC141B868F59331AFA5C7E93AB",
    },
    {
        "188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012",
        "07192B95FFC8DA78631011ED6B24CDD573F977A11E794811",
        "00",
        "00",
        "188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012",
        "07192B95FFC8DA78631011ED6B24CDD573F977A11E794811",
    },
}

func Test_ScalarBaseMult1(t *testing.T) {
    for _, td := range testKeys {
        d := fromHex(td.d)
        x1 := bigFromHex(td.x1)
        y1 := bigFromHex(td.y1)

        px := fromHex(td.sumX)
        py := fromHex(td.sumZ)

        x, y := P192().ScalarMult(x1, y1, d)

        xx := x.Bytes()
        yy := y.Bytes()

        if !bytes.Equal(xx, px) {
            t.Errorf("make x fail, got %x, want %x", xx, px)
        }
        if !bytes.Equal(yy, py) {
            t.Errorf("make y fail, got %x, want %x", yy, py)
        }
    }
}

type testKey struct {
    d string
    x1 string
    y1 string
    sumX string
    sumZ string
}

var testKeys = []testKey{
    {
        "02",
        "DAFEBF5828783F2AD35534631588A3F629A70FB16982A888",
        "DD6BDA0D993DA0FA46B27BBC141B868F59331AFA5C7E93AB",
        "35433907297CC378B0015703374729D7A4FE46647084E4BA",
        "A2649984F2135C301EA3ACB0776CD4F125389B311DB3BE32",
    },
    {
        "03",
        "188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012",
        "7192B95FFC8DA78631011ED6B24CDD573F977A11E794811",
        "76E32A2557599E6EDCD283201FB2B9AADFD0D359CBB263DA",
        "782C37E372BA4520AA62E0FED121D49EF3B543660CFD05FD",
    },
    {
        "04",
        "188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012",
        "7192B95FFC8DA78631011ED6B24CDD573F977A11E794811",
        "35433907297CC378B0015703374729D7A4FE46647084E4BA",
        "A2649984F2135C301EA3ACB0776CD4F125389B311DB3BE32",
    },
    {
        "159D893D4CDD747246CDCA43590E13",
        "188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012",
        "7192B95FFC8DA78631011ED6B24CDD573F977A11E794811",
        "B357B10AC985C891B29FB37DA56661CCCF50CEC21128D4F6",
        "BA20DC2FA1CC228D3C2D8B538C2177C2921884C6B7F0D96F",
    },

}
