package router

/**
 * 分组
 *
 * @create 2021-10-16
 * @author deatil
 */
type Groups struct {
    // 中间件分组
    groups map[string]*Middlewares
}

/**
 * New
 */
func NewGroups() *Groups {
    return &Groups{
        groups: make(map[string]*Middlewares),
    }
}

/**
 * 添加分组 - 覆盖
 */
func (this *Groups) With(name string, middlewares []any) *Groups {
    newGroup := NewMiddlewares()

    // 添加数据
    newGroup.With(middlewares)

    // 删除已存在
    if exists := this.Exists(name); exists {
        this.Remove(name)
    }

    this.groups[name] = newGroup

    return this
}

/**
 * 添加分组 - 前置
 */
func (this *Groups) Prepend(name string, middleware any) *Groups {
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
 * 添加分组 - 后置
 */
func (this *Groups) Push(name string, middleware any) *Groups {
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
 * 判断
 */
func (this *Groups) Exists(name string) bool {
    if _, ok := this.groups[name]; ok {
        return true
    }

    return false
}

/**
 * 删除
 */
func (this *Groups) Remove(name string) {
    delete(this.groups, name)
}

/**
 * 获取分组
 */
func (this *Groups) Get(name string) *Middlewares {
    if data, ok := this.groups[name]; ok {
        return data
    }

    return nil
}
