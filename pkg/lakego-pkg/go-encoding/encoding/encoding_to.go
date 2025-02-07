package encoding

import (
    "io"
    "bytes"
)

// output String
func (this Encoding) String() string {
    return this.ToString()
}

// output Bytes
func (this Encoding) ToBytes() []byte {
    return this.data
}

// output String
func (this Encoding) ToString() string {
    return string(this.data)
}

// output io.Reader
func (this Encoding) ToReader() io.Reader {
    return bytes.NewBuffer(this.data)
}
