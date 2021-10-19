package store

/**
 * 默认
 *
 * @create 2021-10-18
 * @author deatil
 */
type Store struct {}

// 设置
func (s *Store) Set(id string, value string) error {
    panic("接口未定义")
}

// 获取
func (s *Store) Get(id string, clear bool) string {
    panic("接口未定义")
}
