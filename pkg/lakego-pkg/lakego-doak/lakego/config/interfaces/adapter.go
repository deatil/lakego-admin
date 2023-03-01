package interfaces

/**
 * 适配器接口
 *
 * @create 2021-9-25
 * @author deatil
 */
type Adapter interface {
    // 设置默认
    SetDefault(keyName string, value any)

    Set(keyName string, value any)

    IsSet(keyName string) bool

    Get(keyName string) any

    OnConfigChange(f func(string))
}
