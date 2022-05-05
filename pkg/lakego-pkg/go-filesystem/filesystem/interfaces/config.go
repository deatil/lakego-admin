package interfaces

/**
 * 配置接口
 *
 * @create 2021-8-1
 * @author deatil
 */
type Config interface {
    // 覆盖旧数据
    Set(map[string]any) Config

    // 设置单个新数据
    With(string, any) Config

    // 是否存在
    Has(string) bool

    // 获取一个带默认的值
    Get(string, ...any) any
}
