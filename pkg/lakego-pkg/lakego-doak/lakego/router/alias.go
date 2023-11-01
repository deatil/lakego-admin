package router

/**
 * 别名
 *
 * @create 2021-10-16
 * @author deatil
 */
type Alias struct {
    // 中间件
    item map[string]any
}

/**
 * New
 */
func NewAlias() *Alias {
    item := make(map[string]any)

    return &Alias{
        item: item,
    }
}

/**
 * 设置中间件
 */
func (this *Alias) With(name string, middleware any) *Alias {
    this.item[name] = middleware

    return this
}

/**
 * 获取
 */
func (this *Alias) Get(name string) any {
    if middleware, ok := this.item[name]; ok {
        return middleware
    }

    return nil
}

/**
 * 移除
 */
func (this *Alias) Remove(name string) {
    delete(this.item, name)
}

/**
 * 获取全部
 */
func (this *Alias) GetAll() map[string]any {
    return this.item
}

