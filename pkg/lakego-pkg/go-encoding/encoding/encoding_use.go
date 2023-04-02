package encoding

import (
    "fmt"
)

// 编码解码接口
type IEncoding interface {
    // 编码
    Encode([]byte, ...map[string]any) ([]byte, error)

    // 解码
    Decode([]byte, ...map[string]any) ([]byte, error)
}

// 编码解码
var UseEncoding = NewDataSet[string, IEncoding]()

// 获取编码解码方式
func getEncoding(name string) (IEncoding, error) {
    if !UseEncoding.Has(name) {
        err := fmt.Errorf("Encoding: Encoding type [%s] is error.", name)
        return nil, err
    }

    // 编码解码
    newEncoding := UseEncoding.Get(name)

    return newEncoding(), nil
}

// 编码
func (this Encoding) EncodeBy(name string, cfg ...map[string]any) Encoding {
    // 编码解码
    newEncoding, err := getEncoding(name)
    if err != nil {
        this.Error = err
        return this
    }

    this.data, this.Error = newEncoding.Encode(this.data, cfg...)

    return this
}

// 解码
func (this Encoding) DecodeBy(name string, cfg ...map[string]any) Encoding {
    // 编码解码
    newEncoding, err := getEncoding(name)
    if err != nil {
        this.Error = err
        return this
    }

    this.data, this.Error = newEncoding.Decode(this.data, cfg...)

    return this
}
