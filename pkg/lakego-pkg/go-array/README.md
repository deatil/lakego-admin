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
        "hh": map[int]any{
            111: "hccccc",
            222: "hddddd",
            333: map[any]string{
                "qq1": "qq1ccccc",
                "qq2": "qq2ddddd",
                "qq3": "qq3fffff",
            },
        },
        "kJh21ay": map[string]any{
            "Hjk2": "fccDcc",
            "23rt": "^hgcF5c",
        },
    },
}

data := array.ArrGet(arrData, "b.d.e")
// output: eee

data := array.ArrGet(arrData, "b.dd.1")
// output: ddddd

data := array.ArrGet(arrData, "b.kJh21ay.Hjk2")
// output: fccDcc
~~~


### 开源协议

*  本软件包遵循 `Apache2` 开源协议发布，在保留本软件包版权的情况下提供个人及商业免费使用。


### 版权

*  本软件包所属版权归 deatil(https://github.com/deatil) 所有。
