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
func (group *Group) Push(name string, middleware interface{}) *Group {
    var newGroup *Middlewares

    if exists := group.Exists(name); exists {
        newGroup = group.Get(name)
    } else {
        newGroup = NewMiddlewares()
    }

    // 添加数据
    newGroup.Push(middleware)

    group.groups[name] = newGroup

    return group
}

/**
 * 前置添加分组
 */
func (group *Group) Prepend(name string, middleware interface{}) *Group {
    var newGroup *Middlewares

    if exists := group.Exists(name); exists {
        newGroup = group.Get(name)
    } else {
        newGroup = NewMiddlewares()
    }

    // 添加数据
    newGroup.Prepend(middleware)

    group.groups[name] = newGroup

    return group
}

/**
 * 判断
 */
func (group *Group) Exists(name string) bool {
    if _, ok := group.groups[name]; ok {
        return true
    }

    return false
}

/**
 * 删除
 */
func (group *Group) Delete(name string) {
    delete(group.groups, name)
}

/**
 * 获取分组
 */
func (group *Group) Get(name string) *Middlewares {
    if data, ok := group.groups[name]; ok {
        return data
    }

    return nil
}
