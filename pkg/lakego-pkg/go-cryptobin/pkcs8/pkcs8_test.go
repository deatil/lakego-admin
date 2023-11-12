package pkcs8

import (
    "testing"
    "crypto/rand"
    "encoding/pem"

    cryptobin_test "github.com/deatil/go-cryptobin/tool/test"
)

func Test_EncryptPEMBlock(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    data := "test-data"
    pass := "test-pass"

    block, err := EncryptPEMBlock(rand.Reader, "ENCRYPTED PRIVATE KEY", []byte(data), []byte(pass), DefaultOpts)
    assertError(err, "EncryptPEMBlock-EN")
    assertNotEmpty(block.Bytes, "EncryptPEMBlock-EN")

    deData, err := DecryptPEMBlock(block, []byte(pass))
    assertError(err, "EncryptPEMBlock-DE")
    assertNotEmpty(deData, "EncryptPEMBlock-DE")

    assertEqual(string(deData), data, "EncryptPEMBlock")
}

func test_KeyEncryptPEMBlock(t *testing.T, key string) {
    block, _ := pem.Decode([]byte(key))

    bys, err := DecryptPEMBlock(block, []byte("123"))
    if err != nil {
        t.Fatal("PEM data decrypted error: " + err.Error())
    }

    enblock, err := EncryptPEMBlock(rand.Reader, "ENCRYPTED PRIVATE KEY", bys, []byte("123"), DESCBC)
    if err != nil {
        t.Error("encrypt: ", err)
    }

    if len(enblock.Bytes) == 0 {
        t.Error("EncryptPEMBlock error")
    }

    if enblock.Type != "ENCRYPTED PRIVATE KEY" {
        t.Errorf("unexpected enblock type; got %q want %q", enblock.Type, "RSA PRIVATE KEY")
    }
}

// pbes2
var testKey_desCBC = `
-----BEGIN ENCRYPTED PRIVATE KEY-----
MIHoMFMGCSqGSIb3DQEFDTBGMDEGCSqGSIb3DQEFDDAkBBClOTCUgbqFR+BTDzSy
Y6yAAgInEDAMBggqhkiG9w0CCQUAMBEGBSsOAwIHBAgt4PhQaO/JcASBkHQUI0jy
MO3t47bZXy35UGcjjHilw2p5XTdr97wzYDqO8EiS6Vw1XZ4NBLVWAnxYNfLNY6LB
UJ2XXNKPiiGzas9dk1I+z4NVn9qmWzIhB098cHPiYxybKay6HvMQA3oW6bSVCuE3
yg8M0QxtBk9ThTRXLuRyKpI3Tm21ue6V0QI2MLJOwhaFsoACc5bJuHuLTQ==
-----END ENCRYPTED PRIVATE KEY-----
`
var testKey_des_EDE3_CBC = `
-----BEGIN ENCRYPTED PRIVATE KEY-----
MIIC1DBOBgkqhkiG9w0BBQ0wQTApBgkqhkiG9w0BBQwwHAQIEC+O7LBRmMcCAggA
MAwGCCqGSIb3DQIJBQAwFAYIKoZIhvcNAwcECAjDdkzc8IfpBIICgMCVTuN2fBXd
pL+ai2llU0kdPMxJuc5RVvM3GjeSGR8FD/64enRdPht1HBJ9McmpwvpnDs/n4RV/
Xof2s6Wty27ZXQnotbPR8XGECTpf/zzpCdz+XT7nHN8jUJlmdLRwOnfoQEOmXiVj
mUYkwSL5nXmE78mBxADBwxTJGkjWepE9OLlNTW2reomKUcrBMFIC5ekS0iULMVn1
ZqMsgCk231HdkbWfyNBD+5Qg9oMbK5fsgyJXdxB/FM+kT6tVD7Gk4um+JDQ+poCt
2l+6l4ZfOQ9xcqLRwz8ZG6ncDs1GzvWE1Yx30J9qceXvr9jqPpBd4EnLwvnwPhoD
jG/39r9mzuWf7OriGCP9zXwejz5SvAFCgfRcBxOXQB/aYoLT8dprZY184OyZ/TrO
Z2C7hsNGmrSncBbIzpp2O70ruADQKvz4bIQOKKW0jPowVoxjRWmzMtQ9mWkigbM2
NSG+13Ta1KJKmnjo3NTbuCDxp+571JtB7G3WdtjjvyspY0Oe8pNz4tuto/iHwM4M
mWgm0csGTJrKxo0GGckOqCAxEtCYHh/ciZ3mvl6Q8HbDvgqI1VkUNqxblCllqrCY
e9N9rCrGokxL/gw2W2dXea6a1Spa2mu0HGAR9Ct4DB1GL9OAdTpZysMGtWo3/zWj
mBm+Q4CDdqz05hSVksgKUFRQjdIs69jgMsPLXaRZyc+Gi1v74U214dDiZW9tRL5D
tXnHqcOAORIzC/qfNn4do07UNuMzm6bxuRYq0y7lYoTZ7LSpJLEqaFD+drVo2Kcn
nbs4M/y0eQwgQ4im2pCwas8Jb78ZihlhucstJnpnRc0ersRVoalWOz5m7VM0W1Q4
5qf4R5SGai0=
-----END ENCRYPTED PRIVATE KEY-----
`
var testKey_rc2CBC = `
-----BEGIN ENCRYPTED PRIVATE KEY-----
MIIC2TBTBgkqhkiG9w0BBQ0wRjApBgkqhkiG9w0BBQwwHAQIFaw7YE/NuHICAggA
MAwGCCqGSIb3DQIJBQAwGQYIKoZIhvcNAwIwDQIBOgQIWBeGTal4rGgEggKAF2mP
E4muAb/o3assio2lB9msNRXmCIcf+P26sKZL37XqSwtEYNlWDuY/Rl8jnoLK3mS1
Y890MBfEV2c/7SHDr3P2/vFCDntada9iGu/hwTp09GlY7fT56pA+KOvv319Vv+A9
1jcJXFhmCFFxZzygqXAWyzXih3lNc9007ZurHbwzfq9mCFt2OBkl9mqbUijiUPeH
FtqDs2gqUr7c64zpsgYoNqAIjtmIllgDZHE+eWEubSnWDLql4oEBXq2W51rOWQLL
kLyCYQNGl6kaSuVuMhIK7YOQSb2VDBwg2cryZ9iMFiALK84sn4NOocd9R+2bq/Te
xJnNfcqmIEz8t8FYlR54uKcNh6V5TgMoN2eGWYZuE46ryCSMANa3+zkHJPdn2E5S
/6Vyp82cyPX64xzA2wbpkfBXjSs+2ZP3jzKFnaBafNtnd7fn/o9Rft6Mv3UAtwdr
5K4eCsHNxWaoSMH3whx4belkrnQxeQRSELoKG/1aeqSVENYAws3SEdJfodko3Yul
hrzc1WIjbRh/ezoOTaJx4PTmv/e7gphlBaU3BBhBe3Y/TnsMnZk+HtdfOF2uvYtp
xoYwsSLLHQ+PzqKrR4fiaCorCqjwLbCdYeSfI8cYyOo1JfxOUkL/CE3E0LTf19VN
HkqcTZg7bwxtJE4T4m9cmGCNghRcZmbWyDe3Z9Yx31SEqtn4qi5roaHq5ySqSSjr
rQmPG0ZShbjMJfhKji1FK5/1Ceex/QYjqZFxeyl7y4EyrDed+B644BsXmQsE9sJ+
hqx5TNereXd1YVhxaoetnAI29BfNHrrjsdo2DcizhxDcAilqJDJdV/ccbjBDRUjc
y5qwh51Xbl1ZUvEEHA==
-----END ENCRYPTED PRIVATE KEY-----
`
var testKey_aes128_CBC_PAD = `
-----BEGIN ENCRYPTED PRIVATE KEY-----
MIIC3TBXBgkqhkiG9w0BBQ0wSjApBgkqhkiG9w0BBQwwHAQIq4pXr1xYHP0CAggA
MAwGCCqGSIb3DQIJBQAwHQYJYIZIAWUDBAECBBAdILxNjX7WNSm+isWw6OvrBIIC
gIvLSGMDPjduwLBy0ecnyzGWOXtqkYLhVteA0IKCqVOdZzXSWbZf05obuiVeHQrE
FqvKHXAiRIbS8xY0TC1cSPqxTGg1lDGxy0wNhIedIT/skI1AgXlZySrUlvO4ayYG
QFxoOmaAnNsnZ+7dA8IKaAp7v/j5pfEog3bW2jnb7S00oL9PayB0QAFo4DFoFWVA
7emlE65M7F9JPD9Vg1hY8WfQK6QMlnQJwqjSyPZzJ1Cd5mTkaJXkbZCp0tdbmqsV
Kn3mw4B+MDemmBicjZHRYAolAelexD3Y82VAg/zfiF7mpLdhekzKSwg4tIwLQfuG
L1oeYV95cpc7dAYuAt7ESZuT2aOOEtGpNONWpz1Xl6RRpz6Y2BKUy6MOldKmoWPb
IIrbx/6WDATWJ3yLgCeCbA/JlvGCcmxvWux7CRz7ySClPBQYpkl0qZUNljQ8vuaO
TRI9GgtF2LjRdCUDPJSr0G419oPd52h7rYBK7GJ23cXVzD4WeOl64BLolPbV2sVW
ySPixU5JQhrNUkTsZCr/G+zt0/65Rh1V9F1W8wJw+LEFN52ire/PChcqzdKx84ZS
QNQwp1uRj7yViFmj5kcnJg4n4Ut9OF8HE82NWppxMh47YgmN/LHP7lGT1Md1LxUS
pW6TK9D0AOAp9XEQ93uSJMhphPEqINVQF0ub2zfibpXdY3EQD7VLfDkXttqoADt/
octG8HbHRO1m4DWuA3Vyv9cnFmb1m95PTJjwA9hT17jy8dDOZOTxrctMl/p+7elX
4sTgM9oNBFfMzjf223arTNjO93pNpCFmIOglU2XFrXDP0790OBEzUvHe5fIzY0cJ
u0LasAAErhCd/oLo48jFLGY=
-----END ENCRYPTED PRIVATE KEY-----
`
var testKey_aes192_CBC_PAD = `
-----BEGIN ENCRYPTED PRIVATE KEY-----
MIIC3TBXBgkqhkiG9w0BBQ0wSjApBgkqhkiG9w0BBQwwHAQIPvesrkpoMYICAggA
MAwGCCqGSIb3DQIJBQAwHQYJYIZIAWUDBAEWBBCI9UjdVVkPhgMAJHAjq/SDBIIC
gAnNfWWq/3J+QOxBj3SJRuFnCOpQqWyr4Ew40B/RFcZsufTTlcYmvBh3rDZZoz3a
CV6AwGprKLU2r3rFyCMJaC6CiHdFyUz/iPDYW33ziFf5FLsujmPqBgPYvv+UwfAs
DIkoL6RWYix6lbngN+3IcV9HzobTe+G9DU3bZaMwdTLdK9q/5caGOaL5xIVxzOsb
qTRLeYNLWZxNu65n72PLlDcIGWCvSbzZIbW46pRJYuxfZf/KvpkBRyo/pwi2ntIu
uJdM2qErGGFTPqwA5wRJE1EU5VvfM1IPzMKYdyWWHUMYOTpu59F8GLjkFFLBzdRV
9Pc0OeX9vANFXUfVpgrZs0Go5ajxDB6YJeuVmkYaJ6sRKUJ1pAyW6bjzZVqVmFom
9+d2ffBwBwzHpf1CQgILfdblc4O3qp9Yt17XSakeFUzT9irhmWjy57KLkcE1d4Su
5nKpFzS3LE9ffe+azZj7oCgvu5kTazIIIV573Mp+OSjJEN74NKXsro1O+tGxN3p9
NCcc2CnRPdS2st0TLubzJXRlFmSfjn7H8MhlfpU7tE/c8m7xqa/AaRc02lue9WlX
4yiLKJO7lMjHmNLQUvGraJXaL/iS6akt2oh1IbWgsGU+zq1v4W9tVe2Y4dBv6CTj
NCs6L5ZhSEOodorGP/4XPRhAfj9dMo7cNxMUrU8K/UheB/slElveWad7fWuk6Yfr
h/WnIUOpTmhQVs5I3ui1bexQ6LqWhY8U3Vi0xKlbHvvHfmr0ks9lrUad5OtJqC/T
EM8VJwm+B6gqBeyFDEVMQpDGye6ikeK0rqMDtFHDtF6L3vpS13Z8gxGtYV9a8qpu
UuJWFSxzc5YseyXsAcR36qk=
-----END ENCRYPTED PRIVATE KEY-----
`
var testKey_aes256_CBC_PAD = `
-----BEGIN ENCRYPTED PRIVATE KEY-----
MIIC3TBXBgkqhkiG9w0BBQ0wSjApBgkqhkiG9w0BBQwwHAQI8imqAgJu1JMCAggA
MAwGCCqGSIb3DQIJBQAwHQYJYIZIAWUDBAEqBBANxagHb/P1ZAC6V/2Q9Z5dBIIC
gMGD4iCVua5cNPlubUz7e9qNELp5SVOgjsRlnG4LqzbVoZwv6RYArD2y1PuY3jHW
K0lPlMbLnwUPXZGxfJi7VCnBGsGNk3COR53FaF7MP5ppShJfe5k4udQxxtSttKk4
lU7VmcbK5ylRGzbCxWlvAV/3ezmSuglTieh06OxGbek2XWl05O1JNZHm+2awjzAV
k7hoZLf2HH99KWIeTSX7F+jFE0A+JfzXYzFyzVEcPVSJAkZL7e/0DySD+tiDhAkr
+RWyB0UpLKhCkXxDuo55PUUce0m4R1vP292STFSqIZWg2m+pstvlF7hMuENzjxCg
UUndRxuw3OFiMNWK/OaBeJJYFJ7SapRliz/V52Hy5cRVLFqpUm/+THVlXuGFaWhx
3elD8OUwBTuYwSHS/+pZeOoVTsCR/V4ci1a3SGLB3roQzzSN7PX1CrwATbi3W9O1
bH1lz6zxat57IjQHUiodNZihxJFTUaiH2CmJ22C2T4MWcWLqLrm589lQPmV/QK32
IcM06JhOdjpY0DFWcWzDfT+G+4Bz93G21sOP6kZuFTMQgRzcYo4eOj+EIb+4urAr
fXQhB4cGZoc3RS1Xy2+4VenQfNyyaZbR3k7D6TZPHRq+ui5YsYDkMYSRx/gbQEeh
Mh9yDCw34gLEVGmUlGHzBNzRBF3IUMpY/dATvEIuwkrM3zGyqRet9i3MhHS2HMId
+pmcm3PadUX/d3/9xDmzX1dZmyIWse1yDbtOFJy8wukxQT1564AYh3tCKBpCMJaF
0OOvwnhivmyxLanZTRO/GvF1j26s3nOhI5Pf2gN7D4SUi/Mnsd+DNVPX0TPuKlYS
jsh9Vm+Ih6ETN2iu8dLlOco=
-----END ENCRYPTED PRIVATE KEY-----
`

// PBES1
var testKey_MD5AndDES_CBC = `
-----BEGIN ENCRYPTED PRIVATE KEY-----
MIICoTAbBgkqhkiG9w0BBQMwDgQICxgkvE+P1MQCAggABIICgKYRuOl0PqKK603C
gnVIqEJj3A7uZ7mdd14rgn5azBvSjaNIqc9PCqqb6wV/6D+x+6wOU1Nz0OeJJmv7
+Px+6xuyGCQFPiQG3QyM+YtC2aPr6LfQ5F1amIsVT8ET1F4xwyyxGrAP58rxchJ1
3TlifJkHpEroWatTHQcdX82V5kLmOs5TLdB10ctSiQl0GN/bVIOLWT2hUMNdpw3S
cUoztUn8aWKWeVb62cDJRmJayE1Oe8rDoGFuBm0250HykwIIZAdVICl+fBeOq5Fj
0MDNxZauxxejMOnKKbtNuJwsE1w4j/yEpbplmMmf+dDSRsRM3ac43yq4xAgUXzM3
O01q+VpRNaYZk8q5MnRC0Yn8REQTaV2GUXsWS2nfL2MOZp6TgSwC50guY1cZlcfQ
8mKXLBcUGsCYgdpkRx2tUAOeS7XLPN3Sen4OyspJY9NP6HPsreDEeI1xMv9nfdVz
DiryK6lHWfpYHoGDavu+60mqEn8X7Y8s5qWRUp0W8nujbJAbYlQlHpbBFzQrpo7Q
JWfXOJAouR3ezqgow1MaVKMx2Pq4KXX+0zlc2G0rZDtngNmE5XW6CK/DhLv0ldlD
zdEGsHpYNo2JGrqGIlKDXPUwg/OrVNcFgRTcf4YWO+/MKzeVXt57AW9P6yGQyJXO
WjymWmwAgyfhxK3reEnmN/MPYztzCLBP7jnanutgIMKXTnr8cLAcV2bye8gypplR
EBVam00VjZ8EkT9TmQoe+B8gkYYT4h1+c/SMFNlws4LMmWcTgOxYbt0w2/bdsLJs
jLeHG8o8AROsgrgg0eGmqznNdTothvN3WO82opLo1RMc52V6OagMU4Phgcczh9Fs
GPjmXqo=
-----END ENCRYPTED PRIVATE KEY-----
`
var testKey_MD2AndDES_CBC = `
-----BEGIN ENCRYPTED PRIVATE KEY-----
MIICoTAbBgkqhkiG9w0BBQEwDgQIPNmn4FRflVACAggABIICgJJ0AkWVX60ZYhxu
Qo68RgWkjIFQmIXGNQjCD1ezMVZ2x1bjhykoddO6Iftk0s/+x+gDUiFkVW9j9uKi
y11ItlYubkpTt9yIq7q/ppj7d4xrovSR3i/XkS7e44a2y36ekJ7T4UogIsQJpCsC
ebBGL0jYt+XcRVr4ijbboI1s3y2Qm/MXMcP5Gy+dAsB+CzR/KcK6zwr46/5Lk5Tl
TfTN9I+Y6xikPjt8GQGePNj5OZqw35PMItfa2MecMSioA0gzZmYmnM+czUGJAGgB
FY3PVjZmgmKGyZLMy4LBvXJwMU3F0BQN15jUNvRclbGW/uKwsumxoQ3CzbTTkXT2
iRxaJaN9thehnRvSDqAti6/6ZS7bU3uyZNEe6JGy+ESNfGWt54i20MU662VMcZu+
xQXA581GO4ixqFbe9dpkU39ao8F4Mp5+HubiZkTX4544uLkWpOrAeElUlQJeMaGW
WX6sDyN1m2C8Fnpow8X8fDmHPV0lG6jjJ0kxBfSRp3c5lxEdfoQTbMxpPHmplIXY
lyhcroWSmqiUzsZQAQOyT2brolXlaE01aUrrLDdi1RFWU2H31BWkbiJZ0+aQIzbT
v/3rdIwQCmZQLzcqgV+Wm4bEGK+AbZwPvmPhdlqPvAINudBWDaThi4XKcoRJiYoG
YNQ2IQIitqhuKEHc7MmbEQbGUK/Gh/Mt0KEAZuZXd9tX3PVUzHJAE92XbIpVL9UO
gUYD2ebKGytmgHlxVRUmq3iUvI20I9j4yyNIn+vuJw8wu62F57zkNhJLdZDzqPXB
rCZnygNMcnzACaN2W3rHME2vCDJSh3MgejTtM1VsRwjYXCPYL7j1ZLOeyDRdnnfr
Th1nHW0=
-----END ENCRYPTED PRIVATE KEY-----
`
var testKey_SHA1AndDES_CBC = `
-----BEGIN ENCRYPTED PRIVATE KEY-----
MIICoTAbBgkqhkiG9w0BBQowDgQIM/k0TJbcsTkCAggABIICgDUtUmY1rsPGVhAU
awaq90DBq26/QjPH0Zw0soAn4DYbYY7q//kxuVA+n3sLWJb3o8X9B4hCNg8vP52l
AqmXsLGpvoNmrzKsuKaIVtP39ROLFlTR9bhjsbE6ecbwNvl9JMPhTgqchrLYyoIv
+hxmegP0Tm59H+rygflrHjH3WknSGLLMnAUuPsu2y1lzxB+FA79BeEWO6TPXf3RP
qtqcJBElh7SAWcqrcGy3h/oywlR9kYA4PCXotLyB433Q78qPRQDuEupZi7UOnq38
qRoy5OcH1tBBWYvVDqXmMmNhYzQJt/kqdgxdmaMIo50xAZA6waOmlbm/pDWM31u7
inpvAM7UuHmQaUhUAmmKYZzLue+fm5eM+4qAWH/jdmUSlSnLA422z4RiVxG/kJ1D
rRkCnrHLkwLFTrfutNffuAw8mlbL4O0GcikCuuVIO9TXMcMrDQRE6M0k0jcYVkn3
vaBu+ce+YnyxoRuH2Htte0QwKqDH3pH5qGs32PeKpKixVL9JBMQFoaoc2GY7qHAD
UEMn3QVM2Vfpcgp0qu4uK/TmFsf+mIy0ejgsx5V1qv07PulGp6bw9W1C48P6WHfR
cIzQxbrz/UhngmPm6Mta3Ma61Mq36aLYHTXxjC5ph/CauMAwZ7WEX7E8UasxDBWp
ReiX8ACOEhcBCJM/X5dJZ75dy7dap3yxdWzzWwknrsZ9tWC9UgvgYenS+iB6OurP
RNChCo3aGWTzSO2poa+SNrA1Ru4PXLzp+h9U7nNFlCB/3XN+qsuBPrCHcpuPOiVy
yKUcluvusm76rqE64n3DYUU/fPC/CK5fmVcGO66V7OD+zSrz7p88RhlgXRkE1cLJ
fV7PzME=
-----END ENCRYPTED PRIVATE KEY-----
`

// PBES1-pkcs12
var testKey_SHAAnd128BitRC4 = `
-----BEGIN ENCRYPTED PRIVATE KEY-----
MIICnjAcBgoqhkiG9w0BDAEBMA4ECHh+YQGRZGA3AgIIAASCAnyvI74M8N/eswwd
NzBepOn9h7A/iMRRvv0zczI7kGpnXGT5LAypl1krm3WUONcbuTF796f+JtkNJhIm
UY57ijogvQXbPUunaCiJT948dDVuYh0CfoQEcKtUsJBiwvL2xoyXq008WhCyzo9l
mU3wTyTN0RVuniXAcbD4e4+iBzrZ+pMS2nrwiDXYaJbKp0xpXVK4LBD0BT97eydD
kCbv8n4TMBAwbCHbqrQM+1C8Fg9ioevQ4QTOfPxRTHCVbrbC0eD2Yuk018yXarRS
eKdTO/msD8DRiePL142wUX0wSjdT/UrNcBu7NYA6isGmjWZfCm3ds5GKK1xIV0TK
Pfq9OtSxbS1FCh17cJTdFjMxrG3dwU+wd+5j1MmtgXmnmkOqaftaAy3h/6GnVZ/3
eThOEUt26kCivMZJh6hnopxBLvW13NwmA44pOP4Mqcwaoum0oyie4TlyylbRrHkt
Vts/gO+FDZVd9zBycEfOERuf1w17mclmWqjwASslmTxLD9mXadMK6rAFjyjO2bTZ
KiCdXz6+mqrAtJZ/DkttoE2iI7OTRgLevzYzec7+Y47M325go+99q3SjVpMSiGJg
Vvut3HavU/SVryi9BSWdsFTNwfsflcMxphFOL18ZsxfwDabx9oom6TBdcSRd6JzE
ZetWhPdUH9vO9ayn+atlSTw5fve+BiHvApUXO13q47djkKoYKg4ZEdsktTMfY2eq
P4J83wd4oFg/zcnMUxd9gUMBrcqhbORLh1e4l4e4qlL1tEAPBsQbAdqNUvTDXVmI
M7TQWOGV9HqwM5jjo4FK7JKDW8PXHcudJwmwb+1d4WQDrxsexo4u5bDu6SUt21Lq
6j0=
-----END ENCRYPTED PRIVATE KEY-----
`
var testKey_SHAAnd40BitRC4 = `
-----BEGIN ENCRYPTED PRIVATE KEY-----
MIICnTAcBgoqhkiG9w0BDAECMA4ECF4Uz3MZXFXnAgIIAASCAnsEhbbwvaGg2NCA
THC13+Ydr6KajYol1HufBeeT6XkSjXleY5bO4LFVnVhrETCykqy0c6BRXVnwAf2B
FUn3BZjbV0nJpV1K52BHh0SeW388IhnJn2bhKOjIHiYjyV4No0WG5Rwo7rKiQqqL
pxBOreCE9jBBZxCfWEYAZMHdNt4/TvAa6ZYnRutePjx8NdYgeYSjcRrlh/TLuytD
5/zeLpCMKcijKSimeITESg0tZUF5hfBC3pBovIyVUCrkP5Ukjz+CaO3JIDKvtzdK
YF8K1oqQKDXkcPv6JwdqIjjyKhvlC76WpQZu11Lte6qaE+ptGeyjDFmeeUrN6dXl
rORf/FqTmzqTltMsEVg8c02IfCi/Xml1MnMaYuYmzYaTWaoCDjc4RCamJnocleOc
7bgcYA8grmLbmNgwNVzAPE1xIJ9YY7Tp1MnBTtLGiBSJStM40baP55h6+d0T3NEj
G0GcFl8H72BhyzOnMCqi9XZPfDEteQpt91e/KyhrvHAUXSKgcfIV9KSv9kqh2WEv
+TppUo4AF/ztJ5hE+gB8YlIZUojV49a2H1K/rKM3bfwBeS24VFlLisgg0ZcxMzYR
4dKcBkEscFwKdjxKgljTJl4r6FumKOZUDsocUhC+yO5TEaIosCXNdP+mI22LrazG
MMd5qNwBMWVPe2BbWN8ZZMkZgMXykO+JJrXNz3dOQZpkuMzbLW1bJfCRIkjOmFpl
Zkwq7q70TTP5vk/ZJ97YS5E9Uw7ollmN05V6VakFh6fSYoruDBgS00ZeJflC+nyy
+ZgedP0+I2ajfictHyh9rb5zL6s94gFs/wdJrb0OZow6fjKE8I5Ldzyxg3VXXVTR
Bw==
-----END ENCRYPTED PRIVATE KEY-----
`
var testKey_SHAAnd3_KeyTripleDES_CBC = `
-----BEGIN ENCRYPTED PRIVATE KEY-----
MIICojAcBgoqhkiG9w0BDAEDMA4ECKFQxhiBPkv3AgIIAASCAoAZIg1Ycu612X3e
qkwGz4x+BxBb7vH2bI6hIgA8pIcC2dnoKvWcNcUD27i8obyokmn1Eg1HKo1ii9S/
zYtG2l+29NG48Zfa8kIp88nZVbUX+npE+KOB+WXNUc159qf/Hl6BZPGALMeSlkvd
j4+rlTG3k48YVr2MyvYe3N4B4VfYaz3vwVDgieQ+NlthLgIjz4QxCztwWOLvGFz1
PKQ0qdYE3BU/5N5Io++t/kEST7UulXUBscPI/SzJ1SJKg7byVopW7C3shUqq8Vm/
5A6buPzlWKD5+sVDfuLVxKWbOTLl6vVv+hzPmMHzsEad5q7POg171EWbZNxwfhKX
mtnTVgalYx72lxFiK6kdWP1/9f/EvYFKi8Y35uEC0sxu0pFOwNwDIBL/ouC8WTXV
yZWR68WdCeR936kFg6WVabAjUdDZVuzUywDkKlVUuWvu7KCcNahWPWZLT+bUgErG
x7RnvHjIyesgk1sKHvOi3K33piQLDrcm0tvr68EVxnDZ3b2z9sJotg4bLemoXKqe
by7CD+FYCoPe9YzPnroFH7aP+ccVfnwaRVGDlTjVRrI83RrZrHlL1ppV1g3ql+sH
+ywbfuY6GE7Pr2oQ2y0aIsvvGuz2pjluWC0WeW/MsTm8lrSoR6CcLpsDJ5ZmWSvV
H7znd55sjgSKVKMUsS2pHyMCmpuIn/n+tX7xIYEqbSruTYJTPS6Z/gdePOD3Ge3/
3eCNxhdb3Z62xK2A/4wNHecksrR1f7MNRbiPLmROqqABfrvYedSLHozQ9SaBC0f4
cp9Iarl1RcThU5RFlJRAfgAUVpKqr8BDZTi3QAVn/YHrMPEnCr1R8Q9MwBJgqg6p
+WNotzrk
-----END ENCRYPTED PRIVATE KEY-----
`
var testKey_SHAAnd2_KeyTripleDES_CBC = `
-----BEGIN ENCRYPTED PRIVATE KEY-----
MIICojAcBgoqhkiG9w0BDAEEMA4ECMADmqcx3N0PAgIIAASCAoD/Gs6g5uh1flAD
zB255LlF2cGQIPgkm6yYBqZ5ARymxFSeqr3IAAdqL3Yx9BHu6mBh6cUHkpzYWX4R
WKelnrqcrpA3I63nvwug/VjxUKOCMJ1Q703ed93QRQCUCMsVim86Kfth+197mxOM
RaUMOO4Z8MpkVWrKdtbqbF/V9VBDzWzqsOcoVV1PmIZEb+oCw3uop7EIXVSyb84f
hlrWwdwAiE7+AZ2o07n3EQkX6Ml1uCia/HT7VyAQpANCmBVIR91H35AeKsVQMTAI
mTVzDaXQ8n4UGmtb26wDd0ovlDIzbhIjzvEaQmr5k+a2jF23aKorGaXaUOhMkL3f
sJo8uybKH4BykPoM1tphdfQ2W5i8zwwIGFvXEyrKtu+11+D6BZgSeCX+DYZ24jWp
5Bh1pK6PuVii8kIH8NUIeGzUdRsYlL0qJgF5Iz/TsAYZ341RKL+W7dfLiQUtC06d
wUgnMYdQuUlrSYLN6p6FXTn3nTNNe5AkLwlYNfxAiYuqiQLCn4lqdQcMreXe8QO+
sh7AsDJAcSSbv6pZ+nT8KqMBzu1Fad2D0pqIF5wqf2JnCtxbd6NKHz8v2RttcL1w
wkSB6x+5xb07AtU4z8Sq2gj0cskpYS37xoAOq7u2/7eM/XGMhwv1K4Ch/gx0bxh7
rhvdhxd0SnYmFy1dJc5W/yzFsXUZ5oblQla7dL/rvPhpMbLqT6VYsOHyWM8/qqR5
PnB0+zB+76p4473FE/sFT6DC8fAyF5u5xH4tzYhYH4WhY2eAHQ3TVSnPETsvCkyb
X/FzmJUXqjtu8MRmOhjj5a4YiasThSb7rDqoPAr4Y6ozkKMrUs1O1XhzZ9VAEhZk
SBQvFQzb
-----END ENCRYPTED PRIVATE KEY-----
`
var testKey_SHAAnd128BitRC2_CBC = `
-----BEGIN ENCRYPTED PRIVATE KEY-----
MIICojAcBgoqhkiG9w0BDAEFMA4ECNOjvDobu0VoAgIIAASCAoAUdzB4p42s5m2E
lUMs7t7WjJB9aHsw0LP6nGha96WHGZDGoDDHUz/lcszPOPGX/JwdRZF8jOk17YSd
dFbrhfty9oTa2+MArlp8O7HZ9RZbW3L852uBktHpnVx7i3Rm7LdrwPhBAPbDLyiZ
+S8+e2m7GAm4vZLc0IsNNiooRPF8W02xvnXQfRIRKfx7qfSA6ijpRPYiWGGmUSid
jDZXhwUvE/g4czBhyft9bA+EQWgB5y+M5P+w3dY37gv29TBYpX8bodXuE8XUiSxL
1J3d38krsPcsdayZ4yWhZ+M+XdtZPl2NIM1PDwQlDThT7q6n1WYslEjIROE0j77e
r0FCHjoISqkcNuSoNK0QUiJpqZ5892OhLdby0udvvYJQA2CR1CcV6LqNjz/bIYgM
NGClhtIpqswN8K86T+01qeNnKAoSm7nMxN91Mio6RdVrU+ZmYSgfgUXQvMfbBO/s
/opxO35KCPSplbNnA1oE6oantZsgVv+fh6ejMDaYjZxraBAJqIP09DcxSD77j8q0
BQxaFGcEVEg/nqkbnLSvx2eiXkYbyrHKHOQaFrAereDlCrWqT/v6ggv0wR/RnmfV
zQ+1Wo3hHR397Qg3EgkvZZV1Tjlgcxw0xAjuE3kMUlY4MfGZbQx7MLHRgcUJxJmw
gkuSkN/yT9ODz6+lxX/+WRqc6gjkPu1tfksF4nsdbM44mXUWeMd18gaJF5zVKGWI
VMU7/4D7vDE2bEdRciYjtJkBvPl/MWRWNi+bv2YU0Twf+bOFDXjx3XTMDfUQZT8A
34L74WFgNDikGoxGfjrErzUBPGuaI6gtr9hQIh0Mg2Z4LvF07pCxL1trwd0kYWLN
KJjTgb3N
-----END ENCRYPTED PRIVATE KEY-----
`
var testKey_SHAAnd40BitRC2_CBC = `
-----BEGIN ENCRYPTED PRIVATE KEY-----
MIICojAcBgoqhkiG9w0BDAEGMA4ECDCePU6qIjMAAgIIAASCAoD1J443o2t3n6MB
N21KA/ELpAWfnProU2z7L8rYppiGYv+cZvBft1WQQ5xBudogE4dflpD86Y8pyoy2
uCpjo8HRsoUWVJuxV5FSjbF4wKn/KyucYRRrdtHxu/+BkjPdSMg764kVn90ROR2g
Ep7rX5WueaduDK95yq3OXsyZ5/Z87UxeP4UpypkUay5pIKjpbG1YUFbRfyvS3TP5
6IB4eGv7LNWAtPtczEkQm+EdeF/2Tl2BYejzBMfciKjdJZy+FpnZv4KFN0q2nOBy
4YzTsPAf0+vSgF9k99PNKEQcVJytYIdukwKqn8QbhQEFl0Nw4Li8LrRvY0TBnCrl
B77+QJipp4b996zQO1/xhHSh2jXE2+WMfpQMqr/bYJGR3RhNH/v7b0DE78c+7Lsn
z2/pubza4q0yH53WJMV+REuv7nentAmyr2grKDLpDD7u804KnSmdPPpII7AwVcnd
VMVcUgseUHBYYRPh5j04yycM4vmJkmBaw8FjvEUY7D/hGGj5U56walhtnvKcr5at
fgW8FGf6QZzxRuW9Dp4lCGh/IOnRC71Tv4+U8umfAuEf9PmT7Zt7J40L3Op1mEN/
jGLvHmBM+0BFyYfmJEC4qiUg4vRZ3F1NNBRl6BFFHeKg2ItjTYXRdw12nbk3F5Fy
gEnr+T4xkcG4UpmwoJFpkcA60+MGW6vpwcUtlpXBkWVFDLIKlLPY2BhlMUvWLbzB
EojyJeoBoZw9P1bIAfOYAs34lOpIfndzMrHVJl3F5f2mJFWw15ZFzqRxCtMsVzso
6bzraVkXinMlphpZdr3AC+rD96iVbsvCc4kHxr58v3eexxO4vF2YJ9YWN/zgWIVR
quz8QCdO
-----END ENCRYPTED PRIVATE KEY-----
`

func Test_Check_PEMBlock(t *testing.T) {
    t.Run("desCBC", func(t *testing.T) {
        test_KeyEncryptPEMBlock(t, testKey_desCBC)
    })

    t.Run("des_EDE3_CBC", func(t *testing.T) {
        test_KeyEncryptPEMBlock(t, testKey_des_EDE3_CBC)
    })
    t.Run("rc2CBC", func(t *testing.T) {
        test_KeyEncryptPEMBlock(t, testKey_rc2CBC)
    })

    t.Run("aes128_CBC_PAD", func(t *testing.T) {
        test_KeyEncryptPEMBlock(t, testKey_aes128_CBC_PAD)
    })
    t.Run("aes192_CBC_PAD", func(t *testing.T) {
        test_KeyEncryptPEMBlock(t, testKey_aes192_CBC_PAD)
    })
    t.Run("aes256_CBC_PAD", func(t *testing.T) {
        test_KeyEncryptPEMBlock(t, testKey_aes256_CBC_PAD)
    })

    t.Run("MD5AndDES_CBC", func(t *testing.T) {
        test_KeyEncryptPEMBlock(t, testKey_MD5AndDES_CBC)
    })
    t.Run("MD2AndDES_CBC", func(t *testing.T) {
        test_KeyEncryptPEMBlock(t, testKey_MD2AndDES_CBC)
    })

    t.Run("SHA1AndDES_CBC", func(t *testing.T) {
        test_KeyEncryptPEMBlock(t, testKey_SHA1AndDES_CBC)
    })

    t.Run("SHAAnd128BitRC4", func(t *testing.T) {
        test_KeyEncryptPEMBlock(t, testKey_SHAAnd128BitRC4)
    })
    t.Run("SHAAnd40BitRC4", func(t *testing.T) {
        test_KeyEncryptPEMBlock(t, testKey_SHAAnd40BitRC4)
    })

    t.Run("SHAAnd3_KeyTripleDES_CBC", func(t *testing.T) {
        test_KeyEncryptPEMBlock(t, testKey_SHAAnd3_KeyTripleDES_CBC)
    })
    t.Run("SHAAnd2_KeyTripleDES_CBC", func(t *testing.T) {
        test_KeyEncryptPEMBlock(t, testKey_SHAAnd2_KeyTripleDES_CBC)
    })

    t.Run("SHAAnd128BitRC2_CBC", func(t *testing.T) {
        test_KeyEncryptPEMBlock(t, testKey_SHAAnd128BitRC2_CBC)
    })
    t.Run("SHAAnd40BitRC2_CBC", func(t *testing.T) {
        test_KeyEncryptPEMBlock(t, testKey_SHAAnd40BitRC2_CBC)
    })
}
