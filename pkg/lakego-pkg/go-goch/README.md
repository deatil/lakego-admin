## 数据转换


### 项目介绍

*  常用的数据转换
*  可先传入数据后再格式化


### 下载安装

~~~go
go get -u github.com/deatil/go-goch
~~~


### 使用

~~~go
package main

import (
    "fmt"
    "github.com/deatil/go-goch/goch"
)

func main() {
    // 需要转换的数据
    var data any

    // 直接转换
    newData := goch.ToFloat64(data).
    
    // 传递数据后转换
    newData2 := goch.New(data).ToString()
}
~~~


### 可用方法

*  可用方法包括直接使用和传递数据后数据转换
*  可用方法列表：
`ToBool(i any) bool`, 
`ToTime(i any) time.Time`, 
`ToTimeInDefaultLocation(i any, location *time.Location) time.Time`, 
`ToDuration(i any) time.Duration`, 
`ToFloat64(i any) float64`, 
`ToFloat32(i any) float32`, 
`ToInt64(i any) int64`, 
`ToInt32(i any) int32`, 
`ToInt16(i any) int16`, 
`ToInt8(i any) int8`, 
`ToInt(i any) int`, 
`ToUint(i any) uint`, 
`ToUint64(i any) uint64`, 
`ToUint32(i any) uint32`, 
`ToUint16(i any) uint16`, 
`ToUint8(i any) uint8`, 
`ToString(i any) string`, 
`ToStringMapString(i any) map[string]string`, 
`ToStringMapStringSlice(i any) map[string][]string`, 
`ToStringMapBool(i any) map[string]bool`, 
`ToStringMapInt(i any) map[string]int`, 
`ToStringMapInt64(i any) map[string]int64`, 
`ToStringMap(i any) map[string]any`, 
`ToSlice(i any) []any`, 
`ToBoolSlice(i any) []bool`, 
`ToStringSlice(i any) []string`, 
`ToIntSlice(i any) []int`, 
`ToDurationSlice(i any) []time.Duration`


### 开源协议

*  `go-goch` 遵循 `Apache2` 开源协议发布，在保留本软件版权的情况下提供个人及商业免费使用。


### 版权

*  本软件包代码来自于网络
*  修改的代码所属版权归 deatil(https://github.com/deatil) 所有。
