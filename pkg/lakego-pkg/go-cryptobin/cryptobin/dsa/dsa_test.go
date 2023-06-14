package dsa

import (
    "testing"

    cryptobin_test "github.com/deatil/go-cryptobin/tool/test"
)

var (
    prikeyXML = `
<DSAKeyValue>
    <P>81XZh1ZNtyTnT9lkaZnM1jZeR1yTQksP2wxQCzNSvJf0r2men7z+lYy6SccAHd8X8JRxm7PlkN2vMqGggE+Abw7ftMgfopwcSPd2CuC825K2RzB8Jfa0hEb9qwAkTkQ/SI/xwXgMGhkIiK2wF4IiMyKoxFP8/dUgzUHNjzm46DsPVmHvwB9rF0DIp5+NnTKo5qA64tP3ULgGy+FQ8E0gc4nVjsRBJwnzJF3vPWZjZwufQHE3axoGgUbMVk6X+ZnHDP+sMoNXGo4VypPJgWX7GFGRw1P3XJ2/Vaj3OI17PZgalzN+rhu8BAQ6oikwvt8CJ6nGMCd9f3ammDTzfqJzxQ==</P>
    <Q>qiNxZYHeUeDOuDKJTmpkEpyTEPguq5DPyEntEQ==</Q>
    <G>qnmTL0JxOxUcwmrZPsqV5wKgg3BhBqXzP40O8BBYGG8deNWFWB6BkgOSIybssGZdm/NDfIHgyDvtmau7gkI3QujOeyWs76o7F7PRI5GgOPlurpvktTLT9lLdRvd+lK0wKZJuWzOhnR2LpTVCV8oJGIIRlqYVmrEMcxoQtWkBBJx9IYFi8Rnrpo/BdxsbkxF+GPh7t0zNZxF7BraIY7MaNprvHLFCOVQ9A7kityJHylElCmZ665ZP5nDdsVGyvF9pc7rj1tRk1M5Q4gF3exlbQFB+nfLw6OGICxAYCoQ60Anw/oa4j/8l0vQMcfmpJMm5GFZyqh+ps/LC1MiQEORlmQ==</G>
    <Y>yvFanSGUiiyzuq8lYeXFFbB4TLHIcNcdrj0ulUujLp+7SbjLTzkdzaSzV3TGrwfzOQqOfbBdruZzK3sSZ8y1/d8ytyU0nRtl19xBbqh/BQ8SEw+vDh2e5tErMJcT5vp6Av4L8krbChzavCoksXf3nBkTRJPFoMuvWU3k7FLSu8UEdhwEug2xtQznqRk8qqDZy4U8eP1nLjpsDF8dXtaCYywV+0KNk8YInqaj99/fhDk56HWiazSa+5uv+fviTsYBqKHMDDrs59GfTHQI0xnAG6XXNHCMocfKXnPUWw0WtN4r19JIHnoIPUmdUX98ujXiZ0QqYeiLDrFqTqdEATLNoA==</Y>
    <X>a+fL1Qm1mxUEaGJ6DNfWla5v4Su3XxABKNAjqg==</X>
</DSAKeyValue>
    `

    pubkeyXML = `
<DSAKeyValue>
    <P>81XZh1ZNtyTnT9lkaZnM1jZeR1yTQksP2wxQCzNSvJf0r2men7z+lYy6SccAHd8X8JRxm7PlkN2vMqGggE+Abw7ftMgfopwcSPd2CuC825K2RzB8Jfa0hEb9qwAkTkQ/SI/xwXgMGhkIiK2wF4IiMyKoxFP8/dUgzUHNjzm46DsPVmHvwB9rF0DIp5+NnTKo5qA64tP3ULgGy+FQ8E0gc4nVjsRBJwnzJF3vPWZjZwufQHE3axoGgUbMVk6X+ZnHDP+sMoNXGo4VypPJgWX7GFGRw1P3XJ2/Vaj3OI17PZgalzN+rhu8BAQ6oikwvt8CJ6nGMCd9f3ammDTzfqJzxQ==</P>
    <Q>qiNxZYHeUeDOuDKJTmpkEpyTEPguq5DPyEntEQ==</Q>
    <G>qnmTL0JxOxUcwmrZPsqV5wKgg3BhBqXzP40O8BBYGG8deNWFWB6BkgOSIybssGZdm/NDfIHgyDvtmau7gkI3QujOeyWs76o7F7PRI5GgOPlurpvktTLT9lLdRvd+lK0wKZJuWzOhnR2LpTVCV8oJGIIRlqYVmrEMcxoQtWkBBJx9IYFi8Rnrpo/BdxsbkxF+GPh7t0zNZxF7BraIY7MaNprvHLFCOVQ9A7kityJHylElCmZ665ZP5nDdsVGyvF9pc7rj1tRk1M5Q4gF3exlbQFB+nfLw6OGICxAYCoQ60Anw/oa4j/8l0vQMcfmpJMm5GFZyqh+ps/LC1MiQEORlmQ==</G>
    <Y>yvFanSGUiiyzuq8lYeXFFbB4TLHIcNcdrj0ulUujLp+7SbjLTzkdzaSzV3TGrwfzOQqOfbBdruZzK3sSZ8y1/d8ytyU0nRtl19xBbqh/BQ8SEw+vDh2e5tErMJcT5vp6Av4L8krbChzavCoksXf3nBkTRJPFoMuvWU3k7FLSu8UEdhwEug2xtQznqRk8qqDZy4U8eP1nLjpsDF8dXtaCYywV+0KNk8YInqaj99/fhDk56HWiazSa+5uv+fviTsYBqKHMDDrs59GfTHQI0xnAG6XXNHCMocfKXnPUWw0WtN4r19JIHnoIPUmdUX98ujXiZ0QqYeiLDrFqTqdEATLNoA==</Y>
</DSAKeyValue>
    `
)

func Test_XMLSign(t *testing.T) {
    assertEmpty := cryptobin_test.AssertEmptyT(t)
    assertBool := cryptobin_test.AssertBoolT(t)
    assertError := cryptobin_test.AssertErrorT(t)

    data := "test-pass"

    // 签名
    objSign := NewDSA().
        FromString(data).
        FromXMLPrivateKey([]byte(prikeyXML)).
        SignAsn1()
    signed := objSign.ToBase64String()

    assertError(objSign.Error(), "XMLSign-Sign")
    assertEmpty(signed, "XMLSign-Sign")

    // 验证
    objVerify := NewDSA().
        FromBase64String(signed).
        FromXMLPublicKey([]byte(pubkeyXML)).
        VerifyAsn1([]byte(data))

    assertError(objVerify.Error(), "XMLSign-Verify")
    assertBool(objVerify.ToVerify(), "XMLSign-Verify")
}
