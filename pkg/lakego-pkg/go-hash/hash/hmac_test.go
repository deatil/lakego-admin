package hash

import (
    "fmt"
    "testing"
)

var hmacTests = []struct {
    name   string
    hash   HmacHash
    input  string
    secret string
    output string
}{
    {"MD5", HmacMD5, "sdfgsdgfsdfg123132", "pass123", "bf4ce19abed97f9d852c5055d08fc188"},
    {"SHA1", HmacSHA1, "dfg.;kp[jewijr0-34lsd", "pass123", "11a43b22a8449fc36918873ac32fd5a99e466c3d"},
    {"SHA224", HmacSHA224, "sdfgsdgfsdfg123156", "pass123", "3c405828e9a2711f50c1fa56c431e1d4df046de53b25a4676d648473"},
    {"SHA256", HmacSHA256, "sdf,gsdgfsdfg123156", "pass123", "810e24593dbf7a616440321bf2b78ed72fcd4d681a98cecad1d890fece618fdc"},
    {"SHA384", HmacSHA384, "sdf,gsdgfsdfg123156", "pass123", "163bb0adb36d1429db500d66410371b809f95c997098b1fa26808e78f6f709ed9a91f31f27081eeecfa8b563ed969958"},
    {"SHA512", HmacSHA512, "sdf,gsdgfsdfg123156", "pass123", "aaf38f79d73a28a02c8ae26635e90a5b716f84d3365a1aa4333f86a99d8a85774ec3eb3c1e4d8e05df393ae7c60dd024feacafbd3564395fee52874902e54a93"},
    {"RIPEMD160", HmacRIPEMD160, "sdf,gsdgfsdfg123156", "pass123", "a6fde50583758876022d48f90db93bcfedfe9615"},
    {"SHA3_256", HmacSHA3_256, "sdffgsdgfsdfg123156rt5", "pass123", "6d9504b686faeeac4eb66f96603c55f4033181da671644357b7f40cd838311ac"},
}

func Test_Hmac(t *testing.T) {
    assert := assertT(t)
    assertError := assertErrorT(t)

    for index, test := range hmacTests {
        e := FromString(test.input).Hmac(test.hash.New, []byte(test.secret))

        t.Run(fmt.Sprintf("Hmac_test_%d", index), func(t *testing.T) {
            assertError(e.Error, "Hmac-" + test.name)
            assert(test.output, e.ToHexString(), "Hmac-" + test.name)
        })
    }
}

func Test_NewHmac(t *testing.T) {
    assert := assertT(t)
    assertError := assertErrorT(t)

    for index, test := range hmacTests {
        e := Hashing().NewHmac(test.hash.New, []byte(test.secret)).
            Write([]byte(test.input)).Sum(nil)

        t.Run(fmt.Sprintf("NewHmac_test_%d", index), func(t *testing.T) {
            assertError(e.Error, "NewHmac" + test.name)
            assert(test.output, e.ToHexString(), "NewHmac" + test.name)
        })
    }
}
