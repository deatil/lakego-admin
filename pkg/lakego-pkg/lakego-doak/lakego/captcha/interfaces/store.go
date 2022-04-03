package interfaces

/**
 * 存储接口
 *
 * @create 2021-10-18
 * @author deatil
 */
type Store interface {
    // 设置
    Set(string, string) error

    // 获取
    Get(string, bool) string

    // 验证
    Verify(string, string, bool) bool
}

