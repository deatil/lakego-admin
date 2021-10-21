package router

/**
 * New
 */
func NewAlias() *Alias {
    item := make(map[string]interface{})

    return &Alias{
        item: item,
    }
}

/**
 * 别名
 *
 * @create 2021-10-16
 * @author deatil
 */
type Alias struct {
    // 中间件
    item map[string]interface{}
}

/**
 * 设置中间件
 */
func (this *Alias) With(name string, middleware interface{}) *Alias {
    this.item[name] = middleware

    return this
}

/**
 * 获取
 */
func (this *Alias) Get(name string) interface{} {
    if middleware, ok := this.item[name]; ok {
        return middleware
    }

    return nil
}

/**
 * 获取全部
 */
func (this *Alias) GetAll() map[string]interface{} {
    return this.item
}

