### 使用方法

~~~go
import "lakego-admin/lakego/facade/sign"

signData := sign.Sign("md5").
    WithData("test", "测试测试").
    WithAppID("API123456").
    GetSignMap()

check, _ := sign.Check("md5").
    WithData(signData).
    WithTimeout(1000).
    CheckData()

data := sign.Check("md5").
    WithDatas(signData).
    GetDataWithoutSign()

signData2, _ := sign.Sign("md5").
    WithDatas(data).
    GetSignDataString()

checkData := sign.Check("md5").
    CheckSign(signData2, signData["sign"])
~~~
