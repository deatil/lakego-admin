### 使用方法

~~~go
signData := sign.Sign("md5").
    WithData("test", "测试测试").
    WithAppID("API123456").
    GetSignMap()

data := sign.Check("md5").
    WithData(signData).
    GetDataWithoutSign()

check := sign.Check("md5").
    WithData(signData).
    WithTimeout(1000).
    CheckData()

signData2, _ := sign.Sign("md5").
    WithDatas(data).
    GetSignDataString()

checkData := sign.Check("md5").
    CheckSign(signData2, signData["sign"])
~~~
