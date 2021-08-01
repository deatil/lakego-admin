package interfaces

type Config interface {
    // 设置配置信息
    WithSetting(map[string]interface{}) Config

    // 设置配置信息
    With(string, interface{}) Config

    // 获取一个设置
    Get(string) interface{}

    // 通过一个 key 值判断设置是否存在
    Has(string) bool

    // 获取一个值带默认
    GetDefault(string, ...interface{}) interface{}

    // 设置
    Set(string, interface{}) Config

    // 设置一个 fallback
    SetFallback(Config) Config
}
