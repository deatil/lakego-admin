package adapter

/**
 * 适配器
 *
 * @create 2021-9-25
 * @author deatil
 */
type Adapter struct {}

// 设置默认值
func (this *Adapter) SetDefault(keyName string, value any) {
    panic("方法没有实现")
}

// 设置
func (this *Adapter) Set(keyName string, value any) {
    panic("方法没有实现")
}

// 是否设置
func (this *Adapter) IsSet(keyName string) bool {
    panic("方法没有实现")
}

// Get 一个原始值
func (this *Adapter) Get(keyName string) any {
    panic("方法没有实现")
}

// 事件
func (this *Adapter) OnConfigChange(f func(string)) {
    panic("方法没有实现")
}

