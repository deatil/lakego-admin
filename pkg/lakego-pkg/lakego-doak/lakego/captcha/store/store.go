package store

/**
 * 默认
 *
 * @create 2021-10-18
 * @author deatil
 */
type Store struct {}

// 设置
func (this *Store) Set(id string, value string) error {
    panic("接口未定义")
}

// 获取
func (this *Store) Get(id string, clear bool) string {
    return ""
}

// 验证
func (this *Store) Verify(id string, answer string, clear bool) bool {
    return false
}
