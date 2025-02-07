package encoding

import (
    "fmt"
)

// EncodeDecode接口
type IEncoding interface {
    // Encode
    Encode([]byte, ...map[string]any) ([]byte, error)

    // Decode
    Decode([]byte, ...map[string]any) ([]byte, error)
}

// EncodeDecode
var UseEncoding = NewDataSet[string, IEncoding]()

// get Encoding
func getEncoding(name string) (IEncoding, error) {
    if !UseEncoding.Has(name) {
        err := fmt.Errorf("Encoding: Encoding type [%s] is error.", name)
        return nil, err
    }

    // EncodeDecode
    newEncoding := UseEncoding.Get(name)

    return newEncoding(), nil
}

// Encode
func (this Encoding) EncodeBy(name string, cfg ...map[string]any) Encoding {
    newEncoding, err := getEncoding(name)
    if err != nil {
        this.Error = err
        return this
    }

    this.data, this.Error = newEncoding.Encode(this.data, cfg...)

    return this
}

// Decode
func (this Encoding) DecodeBy(name string, cfg ...map[string]any) Encoding {
    newEncoding, err := getEncoding(name)
    if err != nil {
        this.Error = err
        return this
    }

    this.data, this.Error = newEncoding.Decode(this.data, cfg...)

    return this
}
