package pkcs8

import (
    "testing"
    "crypto/rsa"
    "crypto/rand"
    "crypto/x509"
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

// PBES2
var testKey_desCBC = `
-----BEGIN ENCRYPTED PRIVATE KEY-----
MIIC0TBLBgkqhkiG9w0BBQ0wPjApBgkqhkiG9w0BBQwwHAQIYJs/t/KH1cECAggA
MAwGCCqGSIb3DQIJBQAwEQYFKw4DAgcECAHF27cwRDqIBIICgJtz9UiGXQ8M/Q3U
mMdFiKauHiImDcr7Ud1MS2nGhY255xUL1pdsGdHDzv77pGmRV5Dy89Qeud0gWWkz
O0XWM8lxDladhklnkUD3r6GpOmNi+99oXw9kzxdRB7/Zf29B0RrIktRKe9QCv1u6
65Fky8ME4dp/WOl5pUqw2xZL8MNVco5ppH3v/brKePwfCSBHWPcayZCrti6BT8sp
GCtxdRoR7hyHIotrhizaDT/Cb1hBtO3hynOJ9InWYXlk7beJYtsMH280y1uLO0Yi
4ifzwKj4qMkYZh1DOGLvqHhl5EhS18GH7oBbYXhPfX7moKMa8mY0GxTjqeFSbN6h
7cxEd6iExPfUUF0T5aRftPXekqP17aui59gRtSA8tHmRlYaVLSfg70i+GzxPpYSt
AX/aQX6joVoQ2hSJh8bYev6Ug/bzeun8Y+jyDAVWs91EE/n6KyXzi8uedMRn5szW
bMqjDcyN8ULtxPlWzNBkrkyvDQP6LqMpOGU5ExM0P/TYDyVq1nMzQG76fjzXXQVz
ZfRASaob2mfoSJpZfoQIMnrlvYd5TE+Y01/VTfZSKY1NB4qWTFb2V55vzbGAnuoU
fiPXsoxo417u0I/hKKnunMAXvM5fwO/MFSWOmfSRr5O/znB20jmNImrDQNaNuWWV
/x34GCQj8ahZsaOD/yKAzDUqL3//u2YXGd8juDdeAUV1JDaGskj5coVUB7ctGfva
QTlryMseNvkqQ4JxFqrKmeAaQtBjsGFfTSHo01oouWXCyyaYfy9E+/LS7lkj4oeK
wOhO7q1J1ec4DfJps8JvUvNh/XmygaD/nCLOHyuluvzkdoWwk/SSvRO6tJiSOUaw
+yNx04I=
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
var testKey_MD2AndRC2_CBC = `
-----BEGIN ENCRYPTED PRIVATE KEY-----
MIICoTAbBgkqhkiG9w0BBQQwDgQIp5Audl9ye8ICAggABIICgDn0Y7DFBQRHfRCo
EV0cUbaPSjpogXDMsPdgRCPsAwXKFL5f6OBlmjVbTUPgcY0zmIWzdFfN3Bi/htR3
IPzyOvmyRoXzIXmzeq9z1msr4Qdu8ms0uWSNbS0ByaUQGy2an+knoJ+dKYk5+HDk
TwUVBz86fxtiIUQ6GJI/v4GqwFhujxg42UL+LDxo1Efhdn3Rt6HAdP6rSw4mxGlb
KDEs84TusJHFf5KQSipQSUypRdQe6AiH9G5ZQBUTEt1P49qTFEZqxfv4MspOh/FX
MAxk5cpmSrDc4KsrhK83xd0JMxbpOmfN8xo+5cZpJZYbvhxhOYjba2tNbMaF33cH
xNg4NBnsrDKUN/nzrQUqNOi8xmsipPjedQwx01PQV9ACRA0dME7aCPhu2TQ6KxoE
f3rO5ylttdOyX8Wr1o6YmaWBDzd7NYThoIrgFzO4Dxzfr5MWrp3qBZAd2bgC+vit
tL7LEAMTfXuw2xHTXwfwrDiM289yFDGJHnnDfIxBeJT5nGq/RNqx8RfpjfSqH4eB
wX6sebi8OmKTg21aJNPKXYB5ctlD2wiHqGXznvCoQpC0Bhy/tCS8hcKCoCt5aHSn
fG2weKt3zatBCyjSjfFa//32E7SBugXHqOPVEagq05F17rE3RgkZIIpv0ayBf9zX
CHrOJZp1xqYZN32H+XPbcYm147tr/iOylCasR1Zu4Ht0J6lBaHnz4C3X1T/S1Pbh
JC/RkJHqBu2hRZqWtzOkNjQu5v8GkKdEfcWsAGy2EDyav1FoDMHN70cnxgHxwyJp
d5XGxkasd+sD+Zy/gPRLlv5BR09T/Nhqk3DpoIM+08EYKv/RqcmZQDkwBBVmDs4b
dh5CKJs=
-----END ENCRYPTED PRIVATE KEY-----
`
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
var testKey_MD5AndRC2_CBC = `
-----BEGIN ENCRYPTED PRIVATE KEY-----
MIICoTAbBgkqhkiG9w0BBQYwDgQIAmadXJE04aACAggABIICgM9BNUi8uQoYkbB5
L7iljLpaA0JGAeTCWbFHkGJwpeFhewc1bueyRJSIB1ZeJQ0UlkI0I24U+ui3AOVo
Wqvu2jADWDDxFbb4mxakQ9nY0h8YO3lnrs4UJXu+QxgQVNkww8PrHAD1Gx7a34hw
+ZiVzuN4G0gxF68MWux7bQuOhCkLLfN3tFp2rasG5J0zgTZ3ENMCZnTJdRQcswQA
WmNi4aeKjGRXjudjA9OKBRcdGiCkFOUNECl3XLHheXgBqxqltB2yl6+gpbXHQB4i
OPQrqhypTV3BNgKc6ZjcLLBfvv2GZv0STV25hEphRoZ4bOtRNUkMMtEmOyqVP8ks
jL2OJZf3Bv5zlg4cPEYNeIkHTojyFgD1mVLrIJKLYkdjYZpXfgjKAC4+rkGQMJre
/y+3mCEVGE6V81xZ3tvxTHJQFNEWFDqRNDxDWmX45m6XhRcxY7BRDhs/4WrnF4ro
r/cFKNhpLVEaNeCYjAtoBv7EjJUy4RzJTVPtQth+WzFzokPt835lOYP47G0Xu3VU
guw1ar7D3B60U32ef3GZEED9frttwP0nX9fqxzqJNMN1p6T8ckvqOoErIjESR2WN
oprHWeuTo/KHCxx/EDmvTwd+CmHv5eqy6jK5QF5akg6YvwkzO1RVXSODrWMdNKPf
a4hWeWtT2pSjVdwA7inW37K1hZhvo4RNI8rPJaDE4YOcr6p6o/VTcuFvpeT5ibkA
hkym78/6QlNTCPmEJU3MJooUk9XGWYzhevzqXjp0ulBmTmYWFYyJTYaILLoVb5WF
xRid47/8DCniXEprXGgL+Z5pSjMB4owa9xwDPru82D/loHwtnKHKKKw5DS2pANZF
IVMases=
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
var testKey_SHA1AndRC2_CBC = `
-----BEGIN ENCRYPTED PRIVATE KEY-----
MIICoTAbBgkqhkiG9w0BBQswDgQIwjLfEL51ehcCAggABIICgH4yHzcJ8KECz6Ki
6UOQ3F0hSry96Bha4hzvRs02ECksf9OY3o9A0BA1dLZZ2WGoVtn63XsuDrCujqzY
172iy7qAa4bhUwf6bwpdnBaVF7XZgb31c29ycVIDYwFruQSkFK+hRyiEt9Z3IwqH
wbzGNGWj3wtln8NujsDPbXwZfsgceEMqzJw1qBWg927H13uGZyiJIspXX/frw0sB
hFdBIslm9KEwRYGK7q/tl1jfC7mhvJM63jbdsv5qDIlsnef5c6jfH9y+0Ab6G6d7
PDNeAp3fGJHBy0tc2ZT/YGixx+kaG028/5Uwa8qxlzjGq0HZHoieLDJB5tbhIzw8
IDdUdeuxIeVWwNNmq1JuIu6QF8vqZ+MjTujeVBfKu4On15BdAXvi4JnEI1mn8Tal
R3FPYjMDK/VQ85zf0SiV8+ZwMFxy0Y0WJl83uyT2Zw8X7fhZyHDFb9PQceQCXHVH
eWVCeyCfSmH50GwTSxA8v7HbDiRNAWs9/NJqtSvlJYrnEb3cDq9SxFhPC5DYJ8gU
Z3d8TdygDuz6yRDbc0RFKzHY79zAXfpPu+qT1mSW3DdrwrzQAtkPRR1/z2HnFYvq
YbIG5dyxufQdmoipatBVYVY0c4dCYg61L0g9pQOpD0mH5th+ucvkNSJmc9+PRRCr
tlQy+hNF6J8qtvm95YFpKZQlA1XwL9SpakKHGPpAKb54OFB0ax7x5LRi5iWNOwKz
woZw5zt9Wi6wHfgB0IDwu4CsM/yjqLdzcHQl7NmJ1VopBvDao8JicCGRO8gk3E5y
LobujAZ41mFPCxEtlSbnLXxv4kRmsXS2WshqSadMbTNC1vdH0TiWfjOU8ZkPCwLS
L9gvtlU=
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

    t.Run("MD2AndDES_CBC", func(t *testing.T) {
        test_KeyEncryptPEMBlock(t, testKey_MD2AndDES_CBC)
    })
    t.Run("MD2AndRC2_CBC", func(t *testing.T) {
        test_KeyEncryptPEMBlock(t, testKey_MD2AndRC2_CBC)
    })
    t.Run("MD5AndDES_CBC", func(t *testing.T) {
        test_KeyEncryptPEMBlock(t, testKey_MD5AndDES_CBC)
    })
    t.Run("MD5AndRC2_CBC", func(t *testing.T) {
        test_KeyEncryptPEMBlock(t, testKey_MD5AndRC2_CBC)
    })
    t.Run("SHA1AndDES_CBC", func(t *testing.T) {
        test_KeyEncryptPEMBlock(t, testKey_SHA1AndDES_CBC)
    })
    t.Run("SHA1AndRC2_CBC", func(t *testing.T) {
        test_KeyEncryptPEMBlock(t, testKey_SHA1AndRC2_CBC)
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

// with sm3
var testKey_SM4GCM = `
-----BEGIN ENCRYPTED PRIVATE KEY-----
MIH6MFsGCSqGSIb3DQEFDTBOMC0GCSqGSIb3DQEFDDAgBAhDy2qUWc1GjwICJxAC
ARAwDQYJKoEcz1UBgxECBQAwHQYIKoEcz1UBaAgwEQQMSYm5EaGJbzIyDGFBAgEQ
BIGaIQxiZMAaX8QNrjySmZPqhh8fz1DMqF/AtMXneUaPw8UPca30blEcXuZI7ZZ2
zKX5dDmGsfY3SqjSP6+NJOg/dq9EeonjEyGzZ5lc0YI4Boft2y6Oi0d622BfyMwV
j0MPtEqv7YWqaUVAGd8tBtyr7/SUoDe3ZjUEFwFrMHgAp8OqqeN1RBRjTrzY8ISH
ovjnfuDMBswqFwmrxg==
-----END ENCRYPTED PRIVATE KEY-----
`
var testKey_SM4CBC = `
-----BEGIN ENCRYPTED PRIVATE KEY-----
MIHvMFoGCSqGSIb3DQEFDTBNMC0GCSqGSIb3DQEFDDAgBAiixswwAeiJdQICJxAC
ARAwDQYJKoEcz1UBgxECBQAwHAYIKoEcz1UBaAIEEKKLBZjZ5WU0kCua2ag9hLME
gZDGvBUrGO0H9rxh9N8lEpPsPpeb/h4gVueJ7vYDtl4Zpkb2C1Y1XBx6NjBvsR9T
outzObC9GfGUkL1hdS01htFntM2MZXF6ZIgaAVJmdInrZpiA24R/GrKbF59V+Fzr
WoajpzTvlofy5PVtws1sd3JFhOjw64IY3/QgH4WIVg6D/oQfCepu5WRpyhYlPDk2
5os=
-----END ENCRYPTED PRIVATE KEY-----
`
var testKey_SM4ECB = `
-----BEGIN ENCRYPTED PRIVATE KEY-----
MIHdMEgGCSqGSIb3DQEFDTA7MC0GCSqGSIb3DQEFDDAgBAiAyKQuqPdYpwICJxAC
ARAwDQYJKoEcz1UBgxECBQAwCgYIKoEcz1UBaAEEgZCSnggK7LL5S8V86fNXVXQ6
Te4IGJo1tdaXVc56bgq5JgbBXBvLRrqoh+K0nvkqhI7xiJacolXpiUOjJwROo9PL
ViFpmi89JZ9cnSryepPH5R0V1HmYpO5IyKxkr8U8S1I9vKxg1IIUdsNeJPJ7H4bQ
+b3ygZ0bOwCHN3/E0qfy+FfO11i8t3BwfNjQOkR0frI=
-----END ENCRYPTED PRIVATE KEY-----
`

var testKey_AES128GCM = `
-----BEGIN ENCRYPTED PRIVATE KEY-----
MIH7MFwGCSqGSIb3DQEFDTBPMC0GCSqGSIb3DQEFDDAgBAjreXilIJfmnQICJxAC
ARAwDQYJKoEcz1UBgxECBQAwHgYJYIZIAWUDBAEGMBEEDGESn09YP/3TkcYAGAIB
EASBmoPYofVZtbpWxUCh4Q5Ei1SDIHkSV1HW3UjDFRlt6ksJO4zLZZG6AIhhWzkW
249CIqojCGXfzMnQk8H2iE1Id8xKrWYJjhfJAIvWO7ARnNEknaf3/Trxxy+tsczx
N8fa5fpY6EHvJA2j3IacHyqDHd1Bbe7lfnpIEcf9qKgtG3+U9rNGz1BoDkAramSt
e2KTP7GB7bUOSJbxjAM=
-----END ENCRYPTED PRIVATE KEY-----
`
var testKey_AES192GCM = `
-----BEGIN ENCRYPTED PRIVATE KEY-----
MIH7MFwGCSqGSIb3DQEFDTBPMC0GCSqGSIb3DQEFDDAgBAihhPCWHrMIAwICJxAC
ARgwDQYJKoEcz1UBgxECBQAwHgYJYIZIAWUDBAEaMBEEDC31ftLw/wCY0+QxFQIB
EASBmi3rU8QxuCG2/idLjft4qXXBJvbMWUJelKPvMLzOa+LY4pFBQuMjw8o41+9L
TEolMbkTVCH1jDaTda5fhPcq+aVJwUc7tMEoNBxZuPmCYeQXafVbOoZyedGSr0Y6
OvgRupv7sU2eLp76nlw1RrJIEWwBJEHl/sZlN9epmA4AAKEtVOPAWZffxmufdYg+
pUzJcMjTUcSgO5u2oO4=
-----END ENCRYPTED PRIVATE KEY-----
`
var testKey_AES256GCM = `
-----BEGIN ENCRYPTED PRIVATE KEY-----
MIH7MFwGCSqGSIb3DQEFDTBPMC0GCSqGSIb3DQEFDDAgBAjK6am3aHuutQICJxAC
ASAwDQYJKoEcz1UBgxECBQAwHgYJYIZIAWUDBAEuMBEEDGxf2Bj3fTt80UilsQIB
EASBmnRl8g3+LZoVfLvnSWbv5DyFkkRPTSnnHkGrZgQlDDMk9pBgNuhaL2WawQO/
7snVMdGbPW7k5xI77UxCYLlHPUI2Z/5pt9guf3rzkCYcq616XPJScMiVLEYpsY+k
gqC5tbjTnx8qDKnQ3tJCOX6yfWQoZRECMRpik/3oIJwq+hYa8SmJWE/eJFbwe+Fr
dDzN6HnxZ+uoYVqEGOE=
-----END ENCRYPTED PRIVATE KEY-----
`

var testKey_GostCipher = `
-----BEGIN ENCRYPTED PRIVATE KEY-----
MIIC1DBTBgkqhkiG9w0BBQ0wRjAjBgkqhkiG9w0BBQwwFgQQ2ubZaNdrvbYhyDgn
yCA38gICJxAwHwYGKoUDAgIVMBUECAtc/H5r8CI1BgkqhQMHAQIFAQEEggJ7Ddip
iQDoLqtWaf7Yo8/bulx/9GJl16MO6oQFf/3UDUFbPOp8Jl9K67mkh1mXT8YaxAPI
v9FXXbJS2IksXJlGxamo4auzR+R9LopRpXDzq+Gh+hIex+VUkOAKRMhurfDzpHuc
WNmLKHDyI/Iv1qvK8j1JEsAnkOodtP53M6N5DE6ZcDDAnGBKX8Yp7y6FsASLzaaY
YAqLd21FkkrwOeg6F6W9gemFHTnlCtqhTJU94A4j3G4421eHPFcLIrMJ6A/vE/tY
rXgSNCwxqnL8sy/AqNm1Eh7PmTYUw96DefLF192anvXsrawZU7fPA1TdGDjI5PFm
SK++l5hfdrBQURozJDjJ3PnY/imjUxerCyEuKkUaQU3iHkMwfsLJHuxUBPMBR3pN
m9mrRLkmupXs0wZ+gn6wBmPUMoht6Bq3Sp5hsNcSClZV6ZOWWwtJAQkCvhrJEq1w
pnsDzpCCxYnjmvEko78xWGwcH7EmNFtU0qyJULBSf5KOyEqufW2bMUtPEuGNd+S0
7wQtgAvqCCfeuLdcxMT8OSxowml0ZSfUk3aa7eC+fu7yiADrlwbdXq2Dnu69yWFn
UKoohmAoCZwg2Ntheghg/hb7UpIlsF4d/yWJWSVefCaXsZ2F5m4L/1ZrhOICA5SD
HmrYUpY8VGmOS+weqoQoxXy1o0p27U7JgHRdbcrzLqLH1vWatlvuRzkcHr5+orhA
2Ji4/w/Zo5RtVrJmgbG4xH7JbW4WU2tK9U6oTCnhQPwqtklVVwMJxwUB30NP6R5z
tBppen9C1pLgYs90/2jR8SgwlA0fum7ONYwkR1woWzrzBzae1Q08iFcCYnWjcvh7
u/wvi4jm4YU=
-----END ENCRYPTED PRIVATE KEY-----
`

func Test_Check_PEMBlock2(t *testing.T) {
    t.Run("SM4GCM", func(t *testing.T) {
        test_KeyEncryptPEMBlock2(t, testKey_SM4GCM)
    })
    t.Run("SM4CBC", func(t *testing.T) {
        test_KeyEncryptPEMBlock2(t, testKey_SM4CBC)
    })
    t.Run("SM4ECB", func(t *testing.T) {
        test_KeyEncryptPEMBlock2(t, testKey_SM4ECB)
    })

    t.Run("AES128GCM", func(t *testing.T) {
        test_KeyEncryptPEMBlock2(t, testKey_AES128GCM)
    })
    t.Run("AES192GCM", func(t *testing.T) {
        test_KeyEncryptPEMBlock2(t, testKey_AES192GCM)
    })
    t.Run("AES256GCM", func(t *testing.T) {
        test_KeyEncryptPEMBlock2(t, testKey_AES256GCM)
    })

    t.Run("GostCipher", func(t *testing.T) {
        test_KeyEncryptPEMBlock2(t, testKey_GostCipher)
    })
}

func test_KeyEncryptPEMBlock2(t *testing.T, key string) {
    block, _ := pem.Decode([]byte(key))

    bys, err := DecryptPEMBlock(block, []byte("test-passsss"))
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

func encodePEM(src []byte, typ string) string {
    keyBlock := &pem.Block{
        Type:  typ,
        Bytes: src,
    }

    keyData := pem.EncodeToMemory(keyBlock)

    return string(keyData)
}

var testCheckKey = `
-----BEGIN ENCRYPTED PRIVATE KEY-----
MIIC1jBQBgkqhkiG9w0BBQ0wQzAmBgkqhkiG9w0BBQwwGQQQESYq9aSCYUwnV5dC
cOUVRwICJxACARAwGQYIKoZIhvcNAwIwDQIBOgQIOhoZn2SYfZ4EggKAVV0UEZez
qmjRPuBRT9FN0VLdYCaTx+VlVumn3suzd7b9DX/vFxnuc4aZWEc2SzeZDgGRAz5h
HEMtrAwi2xYNyjtsQ9sS6vY5QOnKDnTLNr/xNaQwRU6mayELBsiIZAQHobzVLCcb
kjb0D8stk8Ki6xLEu6dCfkT/TAscGOnjQ3Gn5rDu3ooSylqrKoxNePaOl87C87Il
2Yo7txsRmS7DVJXfhcV4Rtw3buSsTH1BVIFRBnQTbzSeEF8M2mVE4CSYaITnWARB
YOH0D4Ym5pGXa8jLmTj06lv0frjqXL/nGIdxMtrgTCazJYJIq6aVUkk8Nvf21g+/
W0pwPtHGl3A2T6gq1sN/Y+TQSWGCtNII04sEvC+3U6Es3bwRV3B43aQNvRkMCO1m
0aBtbFfVLRKDmcLm914W99skrIZV1gWobS0TxZ+WdPLVwOoYLyaILjQkEFFYlAHp
W5LaHhOa0UExpR8SCWJiyo7tM9zNAUIwm7xk3IFRqtguuF4+dlomXCs58eN70e6x
kycX7trFIZmaLkLML7EBx15h8n4WKCZrxA74qJZ8BVRaexrLyE4mSiifBbZVwvF3
b7kvJ82rXgQEYJhPzwfXbEIBxdzcF2jYGwSiMTCCXHBqmP1JitaMfKoNzFMFSyhO
9l+C+KbDb9CsOXEv+A8Mm0Xki7Gh8WWVoVsKNAVyBfaKZSvf3ne47bgIeCXB90aw
9NKw9JukHE7jNQ4VZ0AHnbi//ia6bu/EXIJbgvlAzCXvlFMrrhHJiZ5O+CJ9deb0
IS+cN06Zpe67EKjWPE88msXFQfR31qf432j57MjHvKQNeb9zbAHefmZuAsocGJ+I
6Mn4OdOPDPuGUw==
-----END ENCRYPTED PRIVATE KEY-----
`

func Test_EncryptPEMBlock2(t *testing.T) {
    block, _ := pem.Decode([]byte(testKey_desCBC))

    bys, err := DecryptPEMBlock(block, []byte("123"))
    if err != nil {
        t.Fatal("PEM data decrypted error: " + err.Error())
    }

    enblock, err := EncryptPEMBlock(rand.Reader, "ENCRYPTED PRIVATE KEY", bys, []byte("123"), RC2_128CBC)
    if err != nil {
        t.Error("encrypt: ", err)
    }

    if len(enblock.Bytes) == 0 {
        t.Error("EncryptPEMBlock error")
    }

    if enblock.Type != "ENCRYPTED PRIVATE KEY" {
        t.Errorf("unexpected enblock type; got %q want %q", enblock.Type, "RSA PRIVATE KEY")
    }

    res := encodePEM(enblock.Bytes, "ENCRYPTED PRIVATE KEY")
    if len(res) == 0 {
        t.Errorf("encodePEM error")
    }
}

var testCheckScryptKey = `
-----BEGIN ENCRYPTED PRIVATE KEY-----
MIIBvDBWBgkqhkiG9w0BBQ0wSTAoBgkrBgEEAdpHBAswGwQQ4RXy39LiElWdxleQ
fNRrawIBBAIBCAIBATAdBglghkgBZQMEASoEENYgwu2wE/eEZHtJ3VnWvzQEggFg
cidA9RttrpvYhK9Uac08gOL1BM7XXGojdy4spMNzldS9mDNaqnKhnvlU8queiTUc
Yk/zcppent9aZcWM3UQXKZf8wGzEKBrkR+EBwbcIB2+k7Ngl8JGlLsuN65Vqm4pQ
MVp3SEhWZRxGQE2hy6CRkH9a53plnjBU74sfYbRr1YbaSP4BW5OqiN0ag+skCr94
ga4hMJu7/WrhhmxYrkYKusfWHFJAztXMWLUmBsu4vEc2ztS0qVl5U2Ax6+osKGLq
Y/Mf/4HI0ErW/mCaa8hwXw6Tw56Gqb177VoXMQCQ3lTU9WhzZ5sLRFJFKEUdNgy4
sIU03KcoxgXeEpbbyJ9jr6k/LUg5fRExSnMbiHN7HUMK1H0+5s3q8otKRJOtmLwM
MI0BMNutXMvRWN/ma4wNfZ8cb5luRvt3GI0XujxnrtJwYz2TYpHPWdxVLEXPsW2A
Z3E/tti8bFM6JjLtiaX7FQ==
-----END ENCRYPTED PRIVATE KEY-----
`

func Test_EncryptPEMBlock_Scrypt(t *testing.T) {
    privateKey, err := rsa.GenerateKey(rand.Reader, 512)
    if err != nil {
        t.Fatal("GenerateKey error: " + err.Error())
    }

    x509PrivateKey, err := x509.MarshalPKCS8PrivateKey(privateKey)
    if err != nil {
        t.Fatal("MarshalPKCS8PrivateKey error: " + err.Error())
    }

    enblock, err := EncryptPEMBlock(
        rand.Reader,
        "ENCRYPTED PRIVATE KEY",
        x509PrivateKey,
        []byte("123"),
        Opts{
            Cipher:  AES256CBC,
            KDFOpts: DefaultScryptOpts,
        },
    )
    if err != nil {
        t.Error("encrypt: ", err)
    }

    if len(enblock.Bytes) == 0 {
        t.Error("EncryptPEMBlock error")
    }

    if enblock.Type != "ENCRYPTED PRIVATE KEY" {
        t.Errorf("unexpected enblock type; got %q want %q", enblock.Type, "RSA PRIVATE KEY")
    }

    res := encodePEM(enblock.Bytes, "ENCRYPTED PRIVATE KEY")
    if len(res) == 0 {
        t.Errorf("encodePEM error")
    }

    // t.Error(res)
}

func Test_EncryptPEMBlock_Pkcs8(t *testing.T) {
    privateKey, err := rsa.GenerateKey(rand.Reader, 512)
    if err != nil {
        t.Fatal("GenerateKey error: " + err.Error())
    }

    x509PrivateKey, err := x509.MarshalPKCS8PrivateKey(privateKey)
    if err != nil {
        t.Fatal("MarshalPKCS8PrivateKey error: " + err.Error())
    }

    t.Run("SHA1And3DES", func(t *testing.T) {
        test_EncryptPEMBlock_Pkcs8(t, x509PrivateKey, SHA1And3DES)
    })
    t.Run("SHA1And2DES", func(t *testing.T) {
        test_EncryptPEMBlock_Pkcs8(t, x509PrivateKey, SHA1And2DES)
    })
    t.Run("SHA1AndRC2_128", func(t *testing.T) {
        test_EncryptPEMBlock_Pkcs8(t, x509PrivateKey, SHA1AndRC2_128)
    })
    t.Run("SHA1AndRC2_40", func(t *testing.T) {
        test_EncryptPEMBlock_Pkcs8(t, x509PrivateKey, SHA1AndRC2_40)
    })
    t.Run("SHA1AndRC4_128", func(t *testing.T) {
        test_EncryptPEMBlock_Pkcs8(t, x509PrivateKey, SHA1AndRC4_128)
    })
    t.Run("SHA1AndRC4_40", func(t *testing.T) {
        test_EncryptPEMBlock_Pkcs8(t, x509PrivateKey, SHA1AndRC4_40)
    })

    t.Run("MD2AndDES", func(t *testing.T) {
        test_EncryptPEMBlock_Pkcs8(t, x509PrivateKey, MD2AndDES)
    })
    t.Run("MD2AndRC2_64", func(t *testing.T) {
        test_EncryptPEMBlock_Pkcs8(t, x509PrivateKey, MD2AndRC2_64)
    })
    t.Run("MD5AndDES", func(t *testing.T) {
        test_EncryptPEMBlock_Pkcs8(t, x509PrivateKey, MD5AndDES)
    })
    t.Run("MD5AndRC2_64", func(t *testing.T) {
        test_EncryptPEMBlock_Pkcs8(t, x509PrivateKey, MD5AndRC2_64)
    })
    t.Run("SHA1AndDES", func(t *testing.T) {
        test_EncryptPEMBlock_Pkcs8(t, x509PrivateKey, SHA1AndDES)
    })
    t.Run("SHA1AndRC2_64", func(t *testing.T) {
        test_EncryptPEMBlock_Pkcs8(t, x509PrivateKey, SHA1AndRC2_64)
    })

    t.Run("DESCBC", func(t *testing.T) {
        test_EncryptPEMBlock_Pkcs8(t, x509PrivateKey, DESCBC)
    })
    t.Run("DESEDE3CBC", func(t *testing.T) {
        test_EncryptPEMBlock_Pkcs8(t, x509PrivateKey, DESEDE3CBC)
    })

    t.Run("RC2CBC", func(t *testing.T) {
        test_EncryptPEMBlock_Pkcs8(t, x509PrivateKey, RC2CBC)
    })
    t.Run("RC2_40CBC", func(t *testing.T) {
        test_EncryptPEMBlock_Pkcs8(t, x509PrivateKey, RC2_40CBC)
    })
    t.Run("RC2_64CBC", func(t *testing.T) {
        test_EncryptPEMBlock_Pkcs8(t, x509PrivateKey, RC2_64CBC)
    })
    t.Run("RC2_128CBC", func(t *testing.T) {
        test_EncryptPEMBlock_Pkcs8(t, x509PrivateKey, RC2_128CBC)
    })

    t.Run("RC5CBC", func(t *testing.T) {
        test_EncryptPEMBlock_Pkcs8(t, x509PrivateKey, RC5CBC)
    })
    t.Run("RC5_128CBC", func(t *testing.T) {
        test_EncryptPEMBlock_Pkcs8(t, x509PrivateKey, RC5_128CBC)
    })
    t.Run("RC5_192CBC", func(t *testing.T) {
        test_EncryptPEMBlock_Pkcs8(t, x509PrivateKey, RC5_192CBC)
    })
    t.Run("RC5_256CBC", func(t *testing.T) {
        test_EncryptPEMBlock_Pkcs8(t, x509PrivateKey, RC5_256CBC)
    })

    t.Run("AES128ECB", func(t *testing.T) {
        test_EncryptPEMBlock_Pkcs8(t, x509PrivateKey, AES128ECB)
    })
    t.Run("AES128CBC", func(t *testing.T) {
        test_EncryptPEMBlock_Pkcs8(t, x509PrivateKey, AES128CBC)
    })
    t.Run("AES128OFB", func(t *testing.T) {
        test_EncryptPEMBlock_Pkcs8(t, x509PrivateKey, AES128OFB)
    })
    t.Run("AES128CFB", func(t *testing.T) {
        test_EncryptPEMBlock_Pkcs8(t, x509PrivateKey, AES128CFB)
    })
    t.Run("AES128GCM", func(t *testing.T) {
        test_EncryptPEMBlock_Pkcs8(t, x509PrivateKey, AES128GCM)
    })
    t.Run("AES128CCM", func(t *testing.T) {
        test_EncryptPEMBlock_Pkcs8(t, x509PrivateKey, AES128CCM)
    })

    t.Run("AES192ECB", func(t *testing.T) {
        test_EncryptPEMBlock_Pkcs8(t, x509PrivateKey, AES192ECB)
    })
    t.Run("AES192CBC", func(t *testing.T) {
        test_EncryptPEMBlock_Pkcs8(t, x509PrivateKey, AES192CBC)
    })
    t.Run("AES192OFB", func(t *testing.T) {
        test_EncryptPEMBlock_Pkcs8(t, x509PrivateKey, AES192OFB)
    })
    t.Run("AES192CFB", func(t *testing.T) {
        test_EncryptPEMBlock_Pkcs8(t, x509PrivateKey, AES192CFB)
    })
    t.Run("AES192GCM", func(t *testing.T) {
        test_EncryptPEMBlock_Pkcs8(t, x509PrivateKey, AES192GCM)
    })
    t.Run("AES192CCM", func(t *testing.T) {
        test_EncryptPEMBlock_Pkcs8(t, x509PrivateKey, AES192CCM)
    })

    t.Run("AES256ECB", func(t *testing.T) {
        test_EncryptPEMBlock_Pkcs8(t, x509PrivateKey, AES256ECB)
    })
    t.Run("AES256CBC", func(t *testing.T) {
        test_EncryptPEMBlock_Pkcs8(t, x509PrivateKey, AES256CBC)
    })
    t.Run("AES256OFB", func(t *testing.T) {
        test_EncryptPEMBlock_Pkcs8(t, x509PrivateKey, AES256OFB)
    })
    t.Run("AES256CFB", func(t *testing.T) {
        test_EncryptPEMBlock_Pkcs8(t, x509PrivateKey, AES256CFB)
    })
    t.Run("AES256GCM", func(t *testing.T) {
        test_EncryptPEMBlock_Pkcs8(t, x509PrivateKey, AES256GCM)
    })
    t.Run("AES256CCM", func(t *testing.T) {
        test_EncryptPEMBlock_Pkcs8(t, x509PrivateKey, AES256CCM)
    })

    t.Run("SM4ECB", func(t *testing.T) {
        test_EncryptPEMBlock_Pkcs8(t, x509PrivateKey, SM4ECB)
    })
    t.Run("SM4CBC", func(t *testing.T) {
        test_EncryptPEMBlock_Pkcs8(t, x509PrivateKey, SM4CBC)
    })
    t.Run("SM4OFB", func(t *testing.T) {
        test_EncryptPEMBlock_Pkcs8(t, x509PrivateKey, SM4OFB)
    })
    t.Run("SM4CFB", func(t *testing.T) {
        test_EncryptPEMBlock_Pkcs8(t, x509PrivateKey, SM4CFB)
    })
    t.Run("SM4CFB1", func(t *testing.T) {
        test_EncryptPEMBlock_Pkcs8(t, x509PrivateKey, SM4CFB1)
    })
    t.Run("SM4CFB8", func(t *testing.T) {
        test_EncryptPEMBlock_Pkcs8(t, x509PrivateKey, SM4CFB8)
    })
    t.Run("SM4GCM", func(t *testing.T) {
        test_EncryptPEMBlock_Pkcs8(t, x509PrivateKey, SM4GCM)
    })
    t.Run("SM4CCM", func(t *testing.T) {
        test_EncryptPEMBlock_Pkcs8(t, x509PrivateKey, SM4CCM)
    })

    t.Run("ARIA128ECB", func(t *testing.T) {
        test_EncryptPEMBlock_Pkcs8(t, x509PrivateKey, ARIA128ECB)
    })
    t.Run("ARIA128CBC", func(t *testing.T) {
        test_EncryptPEMBlock_Pkcs8(t, x509PrivateKey, ARIA128CBC)
    })
    t.Run("ARIA128CFB", func(t *testing.T) {
        test_EncryptPEMBlock_Pkcs8(t, x509PrivateKey, ARIA128CFB)
    })
    t.Run("ARIA128OFB", func(t *testing.T) {
        test_EncryptPEMBlock_Pkcs8(t, x509PrivateKey, ARIA128OFB)
    })
    t.Run("ARIA128CTR", func(t *testing.T) {
        test_EncryptPEMBlock_Pkcs8(t, x509PrivateKey, ARIA128CTR)
    })
    t.Run("ARIA128GCM", func(t *testing.T) {
        test_EncryptPEMBlock_Pkcs8(t, x509PrivateKey, ARIA128GCM)
    })
    t.Run("ARIA128CCM", func(t *testing.T) {
        test_EncryptPEMBlock_Pkcs8(t, x509PrivateKey, ARIA128CCM)
    })

    t.Run("ARIA192ECB", func(t *testing.T) {
        test_EncryptPEMBlock_Pkcs8(t, x509PrivateKey, ARIA192ECB)
    })
    t.Run("ARIA192CBC", func(t *testing.T) {
        test_EncryptPEMBlock_Pkcs8(t, x509PrivateKey, ARIA192CBC)
    })
    t.Run("ARIA192CFB", func(t *testing.T) {
        test_EncryptPEMBlock_Pkcs8(t, x509PrivateKey, ARIA192CFB)
    })
    t.Run("ARIA192OFB", func(t *testing.T) {
        test_EncryptPEMBlock_Pkcs8(t, x509PrivateKey, ARIA192OFB)
    })
    t.Run("ARIA192CTR", func(t *testing.T) {
        test_EncryptPEMBlock_Pkcs8(t, x509PrivateKey, ARIA192CTR)
    })
    t.Run("ARIA192GCM", func(t *testing.T) {
        test_EncryptPEMBlock_Pkcs8(t, x509PrivateKey, ARIA192GCM)
    })
    t.Run("ARIA192CCM", func(t *testing.T) {
        test_EncryptPEMBlock_Pkcs8(t, x509PrivateKey, ARIA192CCM)
    })

    t.Run("ARIA256ECB", func(t *testing.T) {
        test_EncryptPEMBlock_Pkcs8(t, x509PrivateKey, ARIA256ECB)
    })
    t.Run("ARIA256CBC", func(t *testing.T) {
        test_EncryptPEMBlock_Pkcs8(t, x509PrivateKey, ARIA256CBC)
    })
    t.Run("ARIA256CFB", func(t *testing.T) {
        test_EncryptPEMBlock_Pkcs8(t, x509PrivateKey, ARIA256CFB)
    })
    t.Run("ARIA256OFB", func(t *testing.T) {
        test_EncryptPEMBlock_Pkcs8(t, x509PrivateKey, ARIA256OFB)
    })
    t.Run("ARIA256CTR", func(t *testing.T) {
        test_EncryptPEMBlock_Pkcs8(t, x509PrivateKey, ARIA256CTR)
    })
    t.Run("ARIA256GCM", func(t *testing.T) {
        test_EncryptPEMBlock_Pkcs8(t, x509PrivateKey, ARIA256GCM)
    })
    t.Run("ARIA256CCM", func(t *testing.T) {
        test_EncryptPEMBlock_Pkcs8(t, x509PrivateKey, ARIA256CCM)
    })

}

func test_EncryptPEMBlock_Pkcs8(t *testing.T, key []byte, c any) {
    assertEqual := cryptobin_test.AssertEqualT(t)

    pass := []byte("123")

    enblock, err := EncryptPEMBlock(
        rand.Reader,
        "ENCRYPTED PRIVATE KEY",
        key,
        pass,
        c,
    )
    if err != nil {
        t.Error("encrypt: ", err)
    }

    if len(enblock.Bytes) == 0 {
        t.Error("EncryptPEMBlock error")
    }

    if enblock.Type != "ENCRYPTED PRIVATE KEY" {
        t.Errorf("unexpected enblock type; got %q want %q", enblock.Type, "RSA PRIVATE KEY")
    }

    bys, err := DecryptPEMBlock(enblock, pass)
    if err != nil {
        t.Fatal("PEM data decrypted error: " + err.Error())
    }

    assertEqual(bys, key, "DecryptPEMBlock error")
}

func Test_EncryptPEMBlock_Gost(t *testing.T) {
    block, _ := pem.Decode([]byte(testKey_des_EDE3_CBC))

    bys, err := DecryptPEMBlock(block, []byte("123"))
    if err != nil {
        t.Fatal("PEM data decrypted error: " + err.Error())
    }

    enblock, err := EncryptPEMBlock(rand.Reader, "ENCRYPTED PRIVATE KEY", bys, []byte("test-passsss"), GostCipher)
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
