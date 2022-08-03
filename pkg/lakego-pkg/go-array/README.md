## 数组数据获取


### 项目介绍

*  数组数据获取


### 下载安装

~~~go
go get -u github.com/deatil/go-array
~~~


### 使用

~~~go
import "github.com/deatil/go-array/array"

arrData := map[string]any{
    "a": 123,
    "b": map[string]any{
        "c": "ccc",
        "d": map[string]any{
            "e": "eee",
            "f": map[string]any{
                "g": "ggg",
            },
        },
        "dd": []any{
            "ccccc",
            "ddddd",
            "fffff",
        },
        "ff": map[any]any{
            111: "fccccc",
            222: "fddddd",
            333: "dfffff",
        },
    },
}

arr := array.ArrGet(arrData, "b.d.e")
// output: eee
~~~


### 开源协议

*  本软件包遵循 `Apache2` 开源协议发布，在保留本软件包版权的情况下提供个人及商业免费使用。


### 版权

*  本软件包所属版权归 deatil(https://github.com/deatil) 所有。
