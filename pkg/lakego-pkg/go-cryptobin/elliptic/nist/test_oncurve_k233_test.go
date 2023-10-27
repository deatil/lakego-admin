package nist

import (
    "testing"

    "github.com/deatil/go-cryptobin/elliptic/base_elliptic"
)

func Test_IsOnCurve_K233(t *testing.T) {
    testPoint(t, testcase_K233_PKV, K233())
}

// //////////////////////////////////////////////////////////////////////////////////////////////////
// ECDH_K-233_PKV.txt
var testcase_K233_PKV = []testCase{
    {
        Qx:   base_elliptic.HI(`C1EDB9027462AED042357475EA6CB5CA3C5EBC4518A20669E555D8BCFE`),
        Qy:   base_elliptic.HI(`F626CD22DB2C754AFD586B89083214D3BE8DC85BB6FEDA78E2674CE295`),
        Fail: false,
    },
    {
        Qx:   base_elliptic.HI(`1AF024C10B2497589803BAB494D1646A48A85C7C738D89A7DFEA7024A6A`),
        Qy:   base_elliptic.HI(`16367108BB0C77610F7A506D3434DC16A16A61076E81387D874D0D6C192`),
        Fail: false,
    },
    {
        Qx:   base_elliptic.HI(`24CC7ECA53DAFD525B6B94D02CF98EE99579293F2880166E18963A40AA`),
        Qy:   base_elliptic.HI(`240F276292EB60F12DD5092A8651B6DCB524F9EB6764B7B907C324294F`),
        Fail: false,
    },
    {
        Qx:   base_elliptic.HI(`1713CF8FD684EEED32A6821C78B5A45FB06D5428C8FD5474AE802FF79B4`),
        Qy:   base_elliptic.HI(`624F08F510360BF772ED0B43A66F023DD20A89893F310431452B84A243`),
        Fail: false,
    },
    {
        Qx:   base_elliptic.HI(`1A5769B217FA1F952FF6E0755C501424163D9BFDA4ECD95EC8AA8825E16`),
        Qy:   base_elliptic.HI(`1D9BB1AB7B8135C32A3858C348991A7A65DF336352C431A920B688F1181`),
        Fail: false,
    },
    {
        Qx:   base_elliptic.HI(`1E6E8640322FD859238DAF86FE6B59D97D6BD877C806EB1A851A01E3E71`),
        Qy:   base_elliptic.HI(`30B81C58D0B144E1F91AF8FCA1F0894987A66169361058F6C0826F4F31`),
        Fail: false,
    },
    {
        Qx:   base_elliptic.HI(`1AE144AEB73DAECDF89B26325D6C158030DFE63451CF2AC01B29C41CA65`),
        Qy:   base_elliptic.HI(`D812E8FBC040B4C7E89F3E269DA4FC328756D22D3458D967B930BD5944`),
        Fail: true,
    },
    {
        Qx:   base_elliptic.HI(`1DFD5AE716B368C02084CE48C42D9877E18C78B449B8297184BFE364C4A`),
        Qy:   base_elliptic.HI(`69F6F7534856EA4849F2D5D01D56FFB067EEC566ADB390119378B1418A`),
        Fail: true,
    },
    {
        Qx:   base_elliptic.HI(`1238042874C8CDE87FA7BAA20E4515ECA026EFFAFBA048A0BC77D247B58`),
        Qy:   base_elliptic.HI(`131AEF3190E6D67D0E19864FF997BA356AB5EC1259B96BB2EE8158C880F`),
        Fail: false,
    },
    {
        Qx:   base_elliptic.HI(`D9BA62F8202443869DEC3ACBD6DF65B656FF6A37597BE944D6323AA03D`),
        Qy:   base_elliptic.HI(`D64C6D077E9E1A03B8328B3BA926464BADEC2A64ADC0FFEF2DD92086B2`),
        Fail: false,
    },
}
