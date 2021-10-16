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
func (alias *Alias) With(name string, middleware interface{}) *Alias {
    alias.item[name] = middleware

    return alias
}

/**
 * 获取
 */
func (alias *Alias) Get(name string) interface{} {
    if middleware, ok := alias.item[name]; ok {
        return middleware
    }

    return nil
}

/**
 * 获取全部
 */
func (alias *Alias) GetAll() map[string]interface{} {
    return alias.item
}

