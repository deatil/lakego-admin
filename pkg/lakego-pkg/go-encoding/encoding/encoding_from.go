package encoding

import (
    "io"
    "bytes"
)

// From Bytes
func (this Encoding) FromBytes(data []byte) Encoding {
    this.data = data

    return this
}

// FromBytes
func FromBytes(data []byte) Encoding {
    return defaultEncoding.FromBytes(data)
}

// FromString
func (this Encoding) FromString(data string) Encoding {
    this.data = []byte(data)

    return this
}

// FromString
func FromString(data string) Encoding {
    return defaultEncoding.FromString(data)
}

// FromReader
func (this Encoding) FromReader(reader io.Reader) Encoding {
    buf := bytes.NewBuffer(nil)

    if _, err := io.Copy(buf, reader); err != nil {
        this.Error = err

        return this
    }

    this.data = buf.Bytes()

    return this
}

// FromReader
func FromReader(reader io.Reader) Encoding {
    return defaultEncoding.FromReader(reader)
}
