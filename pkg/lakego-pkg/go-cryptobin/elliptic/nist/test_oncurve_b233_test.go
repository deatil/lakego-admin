package nist

import (
    "testing"

    "github.com/deatil/go-cryptobin/elliptic/base_elliptic"
)

func Test_IsOnCurve_B233(t *testing.T) {
    testPoint(t, testcase_B233_PKV, B233())
}

// //////////////////////////////////////////////////////////////////////////////////////////////////
// ECDH_B-233_PKV.txt
var testcase_B233_PKV = []testCase{
    {
        Qx:   base_elliptic.HI(`4ED106462830B1B235D9D9A11CB0447550F7A5F0A1B4815C01A362F67`),
        Qy:   base_elliptic.HI(`1ED02D6000A1FBC64E50FD14D0D2BDC4D0A00B15CE179B77BE5FE75C2ED`),
        Fail: false,
    },
    {
        Qx:   base_elliptic.HI(`3361B9FA5D70EE0C376AA2B561E1ED1EE5B5209D9C87356D2537EB53A3`),
        Qy:   base_elliptic.HI(`169A9DD0AD2DB510D5CD7D7D4623818425E0E221828297C765D549C5174`),
        Fail: false,
    },
    {
        Qx:   base_elliptic.HI(`60998FA5BAE7DBC41EDF0F2C2949BD08A8C756A18A62AAB16FCB876A06`),
        Qy:   base_elliptic.HI(`115E4AF45316AE0D4778CBCD0A087FBC2D6374BCF0474F3076B6CDD957E`),
        Fail: false,
    },
    {
        Qx:   base_elliptic.HI(`9D44B4F1C27069854004233E001BA12D69FC15424E5ABA4F9A33F2B351`),
        Qy:   base_elliptic.HI(`EF5EA3E80D4DF62F590A03E24CC1FD3540DADBFB0E4CDBFE7331B2967C`),
        Fail: false,
    },
    {
        Qx:   base_elliptic.HI(`197A3E6269084FDC27FE5A29A65B037ECF278690A839EA546FB48519BC4`),
        Qy:   base_elliptic.HI(`148BE64EFDF66ED839BFBAC112D527420B60E94A0EE4D4ABF53D33915B2`),
        Fail: false,
    },
    {
        Qx:   base_elliptic.HI(`90286C027F46FFFEA7BB813C930AE2E515DBB94E8F2A42BB5F8E94974C`),
        Qy:   base_elliptic.HI(`39560C85BAA885C2FE3BB067AD7700A9A9F9A6B12D23B43E832FA78BD4`),
        Fail: false,
    },
    {
        Qx:   base_elliptic.HI(`C86707BCF9EF597FE207BA15E00D2B99CB63E001F7DEB09F8910D6EFA5`),
        Qy:   base_elliptic.HI(`C5643953FDD65ACD2FAB5C567863957CE1AD6C4091C4D60243729933F3`),
        Fail: true,
    },
    {
        Qx:   base_elliptic.HI(`417C9274C443506F15FE0165EF97880583362160947EF208404D43AF8A`),
        Qy:   base_elliptic.HI(`99A9BAEAA76815A323CFA2B9C60D172093A4FA53749B450A1B4E3FDF0`),
        Fail: true,
    },
    {
        Qx:   base_elliptic.HI(`1E3D59315CEECE58317607B441A54C29B950B810E3EFD45D3CA11521787`),
        Qy:   base_elliptic.HI(`552C0DAED55027E8584D37D91E96543393687DF27C8EB987F3428BB576`),
        Fail: false,
    },
    {
        Qx:   base_elliptic.HI(`427657CE848E988FFCDB49BF62342842F3DB71F4F0C7CE498934863BBA`),
        Qy:   base_elliptic.HI(`EE7385E04F2154B76537B96650AFE98BCED63CA0170B833D5A41A46722`),
        Fail: false,
    },
}
