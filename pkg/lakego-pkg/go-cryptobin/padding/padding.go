package padding

// padding interface struct
type Padding interface {
    // Padding
    Padding(text []byte, blockSize int) []byte

    // UnPadding
    UnPadding(src []byte) ([]byte, error)
}
