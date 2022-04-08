package interfaces

// 驱动接口
type Driver interface {
    // 签名
    Sign(string) string

    // 验证 data, signData
    Validate(string, string) bool
}

