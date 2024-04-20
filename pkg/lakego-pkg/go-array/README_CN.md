## go-array

<p align="center">
<a href="https://pkg.go.dev/github.com/deatil/go-array" ><img src="https://pkg.go.dev/badge/deatil/go-array.svg" alt="Go Reference"></a>
<a href="https://codecov.io/gh/deatil/go-array" ><img src="https://codecov.io/gh/deatil/go-array/graph/badge.svg?token=SS2Z1IY0XL"/></a>
<img src="https://goreportcard.com/badge/github.com/deatil/go-array" />
<a href="https://github.com/avelino/awesome-go"><img src="https://awesome.re/mentioned-badge.svg" alt="Mentioned in Awesome Go"></a>
</p>

<p align="center">
go-array 可以快速的从 map, slice 及 json 中获取数据或者设置数据
</p>

中文 | [English](README.md)


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
            1115: "hccccc",
            2225: "hddddd",
            3335: map[any]string{
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

data := array.Get(arrData, "b.d.e")
// output: eee

data := array.Get(arrData, "b.dd.1")
// output: ddddd

data := array.Get(arrData, "b.hh.3335.qq2")
// output: qq2ddddd

data := array.Get(arrData, "b.kJh21ay.Hjk2", "defValString")
// output: fccDcc

data := array.Get(arrData, "b.kJh21ay.Hjk23333", "defValString")
// output: defValString
~~~


### 常用示例

* 判断是否存在
~~~go
var res bool = array.New(arrData).Exists("b.kJh21ay.Hjk2")
// output: true

var res bool = array.New(arrData).Exists("b.kJh21ay.Hjk12")
// output: false
~~~

* 获取数据
~~~go
var res any = array.New(arrData).Get("b.kJh21ay.Hjk2")
// output: fccDcc

var res any = array.New(arrData).Get("b.kJh21ay.Hjk12", "defVal")
// output: defVal
~~~

* 查找数据
~~~go
var res any = array.New(arrData).Find("b.kJh21ay.Hjk2")
// output: fccDcc

var res any = array.New(arrData).Find("b.kJh21ay.Hjk12")
// output: nil
~~~

* 用 Sub 获取数据
~~~go
var res any = array.New(arrData).Sub("b.kJh21ay.Hjk2").Value()
// output: fccDcc

var res any = array.New(arrData).Sub("b.kJh21ay.Hjk12").Value()
// output: nil
~~~

* 用 Search 获取数据
~~~go
var res any = array.New(arrData).Search("b", "kJh21ay", "Hjk2").Value()
// output: fccDcc

var res any = array.New(arrData).Search("b", "kJh21ay", "Hjk12").Value()
// output: nil
~~~

* 用 Index 获取数据
~~~go
var res any = array.New(arrData).Sub("b.dd").Index(1).Value()
// output: ddddd

var res any = array.New(arrData).Sub("b.dd").Index(6).Value()
// output: nil
~~~

* 用 Set 设置数据
~~~go
arr, err := array.New(arrData).Set("qqqyyy", "b", "ff", 222)
// arr.Get("b.ff.222") output: qqqyyy
~~~

* 用 SetIndex 设置数据
~~~go
arr, err := array.New(arrData).Sub("b.dd").SetIndex("qqqyyySetIndex", 1)
// arr.Get("b.dd.1") output: qqqyyySetIndex
~~~

* 用 Delete 删除数据
~~~go
arr, err := array.New(arrData).Delete("b", "hh", 2225)
// arr.Get("b.hh.2225") output: nil
~~~

* 用 DeleteKey 删除数据
~~~go
arr, err := array.New(arrData).DeleteKey("b.d.e")
// arr.Get("b.d.e") output: nil
~~~


### 开源协议

*  本软件包遵循 `Apache2` 开源协议发布，在保留本软件包版权的情况下提供个人及商业免费使用。


### 版权

*  本软件包所属版权归 deatil(https://github.com/deatil) 所有。
