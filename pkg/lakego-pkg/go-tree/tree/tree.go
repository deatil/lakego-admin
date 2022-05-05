package tree

// 构造函数
func New() *Tree {
    return &Tree{
        icon: []string{
            "│",
            "├",
            "└",
        },
        blankspace: "&nbsp;",

        idKey: "id",
        parentidKey: "parentid",
        spacerKey: "spacer",
        depthKey: "depth",
        haschildKey: "haschild",

        buildChildKey: "children",
    }
}

/**
 * map 数据格式化为树
 *
 * @create 2021-9-8
 * @author deatil
 */
type Tree struct {
    // 生成树型结构所需要的2维数组
    data []map[string]any

    // 生成树型结构所需修饰符号
    icon []string
    blankspace string

    // 查询
    idKey string
    parentidKey string
    spacerKey string
    depthKey string
    haschildKey string

    // 返回子级key
    buildChildKey string
}

func (this *Tree) WithIcon(icon []string) *Tree {
    this.icon = icon
    return this
}

func (this *Tree) WithBlankspace(blankspace string) *Tree {
    this.blankspace = blankspace
    return this
}

func (this *Tree) WithIdKey(idKey string) *Tree {
    this.idKey = idKey
    return this
}

func (this *Tree) WithParentidKey(parentidKey string) *Tree {
    this.parentidKey = parentidKey
    return this
}

func (this *Tree) WithSpacerKey(spacerKey string) *Tree {
    this.spacerKey = spacerKey
    return this
}

func (this *Tree) WithDepthKey(depthKey string) *Tree {
    this.depthKey = depthKey
    return this
}

func (this *Tree) WithHaschildKey(haschildKey string) *Tree {
    this.haschildKey = haschildKey
    return this
}

func (this *Tree) WithBuildChildKey(buildChildKey string) *Tree {
    this.buildChildKey = buildChildKey
    return this
}

// 设置数据
func (this *Tree) WithData(data []map[string]any) *Tree {
    this.data = data
    return this
}

// 构建数组
func (this *Tree) Build(id any, itemprefix string, depth int) []map[string]any {
    children := this.GetListChild(id)
    if len(children) <= 0 {
        return nil
    }

    data := make([]map[string]any, 0)
    var number int = 1

    total := len(children)
    for _, v := range children {
        info := v

        j := ""
        k := ""

        if number == total {
            if len(this.icon) >= 3 {
                j = j + this.icon[2]
            }

            if itemprefix != "" {
                k = this.blankspace
            }
        } else {
            if len(this.icon) >= 2 {
                j = j + this.icon[1]
            }

            if itemprefix != "" {
                if len(this.icon) >= 1 {
                    k = this.icon[0]
                }
            }
        }

        spacer := ""
        if itemprefix != "" {
            spacer = itemprefix + j
        }

        info[this.spacerKey] = spacer

        // 深度
        info[this.depthKey] = depth

        childList := this.Build(v[this.idKey], itemprefix + k + this.blankspace, depth + 1)
        if len(childList) > 0{
            info[this.buildChildKey] = childList
        }

        data = append(data, info)
        number++
    }

    return data
}

// 所有父节点
func (this *Tree) GetListParents(id any, sort ...string) []map[string]any {
    if len(this.data) <= 0 {
        return nil
    }

    var order string = "desc"
    if len(sort) > 0{
        order = sort[0]
    }

    self := this.GetListSelf(id)
    if self == nil {
        return nil
    }

    parentid := self[this.parentidKey].(string)
    newData := make([]map[string]any, 0)
    for _, v := range this.data {
        // 不存在跳过
        if _, ok := v[this.idKey]; !ok {
            continue
        }

        switch v[this.idKey].(type) {
            case string:
                dataId := v[this.idKey].(string)

                if dataId == parentid {
                    newData = append(newData, v)

                    parents := this.GetListParents(v[this.idKey], sort...)
                    if len(parents) > 0{
                        if order == "asc" {
                            newData = append(newData, parents...)
                        } else {
                            newData = append(parents, newData...)
                        }
                    }
                }
            default:
                continue
        }
    }

    return newData
}

// 获取所有父节点ID列表
func (this *Tree) GetListParentIds(id any) []any {
    data := this.GetListParents(id)
    if len(data) <= 0 {
        return nil
    }

    ids := make([]any, 0)
    for _, v := range data {
        // 不存在跳过
        if _, ok := v[this.idKey]; !ok {
            continue
        }

        ids = append(ids, v[this.idKey])
    }

    return ids
}

// 获取当前ID的所有子节点
func (this *Tree) GetListChildren(id any, sort ...string) []map[string]any {
    if len(this.data) <= 0 {
        return nil
    }

    var order string = "desc"
    if len(sort) > 0{
        order = sort[0]
    }

    id = id.(string)
    newData := make([]map[string]any, 0)
    for _, v := range this.data {
        // 不存在跳过
        if _, ok := v[this.parentidKey]; !ok {
            continue
        }

        switch v[this.parentidKey].(type) {
            case string:
                dataParentId := v[this.parentidKey].(string)
                if dataParentId == id {
                    newData = append(newData, v)

                    children := this.GetListChildren(v[this.idKey], sort...)
                    if len(children) > 0{
                        if order == "asc" {
                            newData = append(newData, children...)
                        } else {
                            newData = append(children, newData...)
                        }
                    }
                }
            default:
                continue
        }

    }

    return newData
}

// 获取当前ID的所有子节点id列表
func (this *Tree) GetListChildIds(id any) []any {
    data := this.GetListChildren(id)
    if len(data) <= 0 {
        return nil
    }

    ids := make([]any, 0)
    for _, v := range data {
        // 不存在跳过
        if _, ok := v[this.idKey]; !ok {
            continue
        }

        ids = append(ids, v[this.idKey])
    }

    return ids
}

// 得到子级第一级数组
func (this *Tree) GetListChild(id any) []map[string]any {
    if len(this.data) <= 0 {
        return nil
    }

    id = id.(string)
    newData := make([]map[string]any, 0)
    for _, v := range this.data {
        // 不存在跳过
        if _, ok := v[this.parentidKey]; !ok {
            continue
        }

        dataParentId := v[this.parentidKey].(string)
        if dataParentId == id {
            newData = append(newData, v)
        }
    }

    return newData
}

// 获取ID自己的数据
func (this *Tree) GetListSelf(id any) map[string]any {
    if len(this.data) <= 0 {
        return nil
    }

    id = id.(string)
    for _, v := range this.data {
        // 不存在跳过
        if _, ok := v[this.idKey]; !ok {
            continue
        }

        dataId := v[this.idKey].(string)
        if dataId == id {
            return v
        }
    }

    return nil
}

// 将 build 的结果返回为二维数组
func (this *Tree) BuildFormatList(data []map[string]any, parentid any) []map[string]any {
    if len(data) <= 0 {
        return nil
    }

    var list = make([]map[string]any, 0)
    for _, v := range data {
        if len(v) > 0 {
            if _, ok := v[this.spacerKey]; !ok {
                v[this.spacerKey] = ""
            }

            var ok2 bool
            var child any
            if child, ok2 = v[this.buildChildKey]; ok2 {
                v[this.haschildKey] = 1
            } else {
                v[this.haschildKey] = 0
            }

            delete(v, this.buildChildKey)

            if _, ok3 := v[this.parentidKey]; !ok3 {
                v[this.parentidKey] = parentid
            }

            list = append(list, v)

            if child != nil {
                children := child.([]map[string]any)
                if len(children) > 0 {
                    childData := this.BuildFormatList(children, v[this.idKey])
                    list = append(list, childData...)
                }
            }
        }
    }

    return list
}
