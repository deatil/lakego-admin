package bencode

import (
    "io"
    "fmt"
    "bytes"
)

// 生成
func NewEncoder(w io.Writer) *Encoder {
    return &Encoder{w: w}
}

// 解析
func NewDecoder(r io.Reader) *Decoder {
    return &Decoder{r: &scanner{r: r}}
}

// Marshal the value 'v' to the bencode form, return the result as []byte and
// an error if any.
func Marshal(v any) ([]byte, error) {
    var buf bytes.Buffer

    e := Encoder{w: &buf}

    err := e.Encode(v)
    if err != nil {
        return nil, err
    }

    return buf.Bytes(), nil
}

func MustMarshal(v any) []byte {
    b, err := Marshal(v)

    if err != nil {
        panic(fmt.Sprintf("expected nil; got %v", err))
    }

    return b
}

// Unmarshal the bencode value in the 'data' to a value pointed by the 'v' pointer, return a non-nil
// error if any. If there are trailing bytes, this results in UnusedTrailingBytesError, but the value
// will be valid. It's probably more consistent to use Decoder.Decode if you want to rely on this
// behaviour (inspired by Rust's serde here).
func Unmarshal(data []byte, v any) (err error) {
    buf := bytes.NewReader(data)

    e := Decoder{r: buf}
    err = e.Decode(v)

    if err == nil && buf.Len() != 0 {
        err = UnusedTrailingBytesError{buf.Len()}
    }

    return
}
