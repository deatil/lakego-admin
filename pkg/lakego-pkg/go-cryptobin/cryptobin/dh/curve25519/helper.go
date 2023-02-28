package curve25519

// 构造函数
func NewEcdh() Curve25519 {
    return Curve25519{
        Errors: make([]error, 0),
    }
}

// 构造函数
func New() Curve25519 {
    return NewEcdh()
}
