package ca

// 构造函数
func NewCA() CA {
    return CA{
        Errors: make([]error, 0),
    }
}

// 构造函数
func New() CA {
    return NewCA()
}
