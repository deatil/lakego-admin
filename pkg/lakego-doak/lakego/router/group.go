package router

/**
 * New
 */
func NewGroup() *Group {
    groups := make(map[string]*Middlewares)

    return &Group{
        groups: groups,
    }
}

/**
 * 分组
 *
 * @create 2021-10-16
 * @author deatil
 */
type Group struct {
    // 中间件分组
    groups map[string]*Middlewares
}

/**
 * 后置添加分组
 */
func (this *Group) Push(name string, middleware interface{}) *Group {
    var newGroup *Middlewares

    if exists := this.Exists(name); exists {
        newGroup = this.Get(name)
    } else {
        newGroup = NewMiddlewares()
    }

    // 添加数据
    newGroup.Push(middleware)

    this.groups[name] = newGroup

    return this
}

/**
 * 前置添加分组
 */
func (this *Group) Prepend(name string, middleware interface{}) *Group {
    var newGroup *Middlewares

    if exists := this.Exists(name); exists {
        newGroup = this.Get(name)
    } else {
        newGroup = NewMiddlewares()
    }

    // 添加数据
    newGroup.Prepend(middleware)

    this.groups[name] = newGroup

    return this
}

/**
 * 判断
 */
func (this *Group) Exists(name string) bool {
    if _, ok := this.groups[name]; ok {
        return true
    }

    return false
}

/**
 * 删除
 */
func (this *Group) Delete(name string) {
    delete(this.groups, name)
}

/**
 * 获取分组
 */
func (this *Group) Get(name string) *Middlewares {
    if data, ok := this.groups[name]; ok {
        return data
    }

    return nil
}
