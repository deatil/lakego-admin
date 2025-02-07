package encoding

/**
 * Encode
 *
 * @create 2022-4-3
 * @author deatil
 */
type Encoding struct {
    // data bytes
    data []byte

    // Error
    Error error
}

// NewEncoding
func NewEncoding() Encoding {
    return Encoding{}
}

// New
func New() Encoding {
    return NewEncoding()
}

// default Encoding
var defaultEncoding = NewEncoding()
