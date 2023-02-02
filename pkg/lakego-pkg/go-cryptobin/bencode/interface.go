package bencode

// Any type which implements this interface, will be marshaled using the
// specified method.
type Marshaler interface {
    MarshalBencode() ([]byte, error)
}

// Any type which implements this interface, will be unmarshaled using the
// specified method.
type Unmarshaler interface {
    UnmarshalBencode([]byte) error
}
