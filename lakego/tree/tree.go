package tree

// map 数据格式化为树
// "lakego-admin/lakego/tree"
type Tree struct {
    // 生成树型结构所需要的2维数组
    data []map[string]interface{}

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

func (tree *Tree) WithIcon(icon []string) *Tree {
    tree.icon = icon
    return tree
}

func (tree *Tree) WithBlankspace(blankspace string) *Tree {
    tree.blankspace = blankspace
    return tree
}

func (tree *Tree) WithIdKey(idKey string) *Tree {
    tree.idKey = idKey
    return tree
}

func (tree *Tree) WithParentidKey(parentidKey string) *Tree {
    tree.parentidKey = parentidKey
    return tree
}

func (tree *Tree) WithSpacerKey(spacerKey string) *Tree {
    tree.spacerKey = spacerKey
    return tree
}

func (tree *Tree) WithDepthKey(depthKey string) *Tree {
    tree.depthKey = depthKey
    return tree
}

func (tree *Tree) WithHaschildKey(haschildKey string) *Tree {
    tree.haschildKey = haschildKey
    return tree
}

func (tree *Tree) WithBuildChildKey(buildChildKey string) *Tree {
    tree.buildChildKey = buildChildKey
    return tree
}

// 设置数据
func (tree *Tree) WithData(data []map[string]interface{}) *Tree {
    tree.data = data
    return tree
}

// 构建数组
func (tree *Tree) Build(id interface{}, itemprefix string, depth int) []map[string]interface{} {
    children := tree.GetListChildren(id)
    if len(children) <= 0 {
        return nil
    }

    data := make([]map[string]interface{}, 0)
    var number int = 1

    total := len(children)
    for _, v := range children {
        info := v

        j := ""
        k := ""

        if number == total {
            if len(tree.icon) >= 3 {
                j = j + tree.icon[2]
            }

            if itemprefix != "" {
                k = tree.blankspace
            }
        } else {
            if len(tree.icon) >= 2 {
                j = j + tree.icon[1]
            }

            if itemprefix != "" {
                if len(tree.icon) >= 1 {
                    k = tree.icon[0]
                }
            }
        }

        spacer := ""
        if itemprefix != "" {
            spacer = itemprefix + j
        }

        info[tree.spacerKey] = spacer

        // 深度
        info[tree.depthKey] = depth

        childList := tree.Build(v[tree.idKey], itemprefix + k + tree.blankspace, depth + 1)
        if len(childList) > 0{
            info[tree.buildChildKey] = childList
        }

        data = append(data, info)
        number++
    }

    return data
}

// 所有父节点
func (tree *Tree) GetListParents(id interface{}, sort ...string) []map[string]interface{} {
    if len(tree.data) <= 0 {
        return nil
    }

    var order string = "desc"
    if len(sort) > 0{
        order = sort[0]
    }

    self := tree.GetListSelf(id)
    if self == nil {
        return nil
    }

    parentid := self[tree.parentidKey].(string)
    newData := make([]map[string]interface{}, 0)
    for _, v := range tree.data {
        dataId := v[tree.idKey].(string)
        if dataId == parentid {
            newData = append(newData, v)

            parents := tree.GetListParents(v[tree.idKey], sort...)
            if len(parents) > 0{
                if order == "asc" {
                    newData = append(newData, parents...)
                } else {
                    newData = append(parents, newData...)
                }
            }
        }
    }

    return newData
}

// 获取所有父节点ID列表
func (tree *Tree) GetListParentIds(id interface{}) []interface{} {
    data := tree.GetListParents(id)
    if len(data) <= 0 {
        return nil
    }

    ids := make([]interface{}, 0)
    for _, v := range data {
        ids = append(ids, v[tree.idKey])
    }

    return ids
}

// 获取当前ID的所有子节点
func (tree *Tree) GetListChildren(id interface{}, sort ...string) []map[string]interface{} {
    if len(tree.data) <= 0 {
        return nil
    }

    var order string = "desc"
    if len(sort) > 0{
        order = sort[0]
    }

    id = id.(string)
    newData := make([]map[string]interface{}, 0)
    for _, v := range tree.data {
        dataParentId := v[tree.parentidKey].(string)
        if dataParentId == id {
            newData = append(newData, v)

            children := tree.GetListChildren(v[tree.idKey], sort...)
            if len(children) > 0{
                if order == "asc" {
                    newData = append(newData, children...)
                } else {
                    newData = append(children, newData...)
                }
            }
        }
    }

    return newData
}

// 获取当前ID的所有子节点id列表
func (tree *Tree) GetListChildIds(id interface{}) []interface{} {
    data := tree.GetListChildren(id)
    if len(data) <= 0 {
        return nil
    }

    ids := make([]interface{}, 0)
    for _, v := range data {
        ids = append(ids, v[tree.idKey])
    }

    return ids
}

// 得到子级第一级数组
func (tree *Tree) GetListChild(id interface{}) []map[string]interface{} {
    if len(tree.data) <= 0 {
        return nil
    }

    id = id.(string)
    newData := make([]map[string]interface{}, 0)
    for _, v := range tree.data {
        dataParentId := v[tree.parentidKey].(string)
        if dataParentId == id {
            newData = append(newData, v)
        }
    }

    return newData
}

// 获取ID自己的数据
func (tree *Tree) GetListSelf(id interface{}) map[string]interface{} {
    if len(tree.data) <= 0 {
        return nil
    }

    id = id.(string)
    for _, v := range tree.data {
        dataId := v[tree.idKey].(string)
        if dataId == id {
            return v
        }
    }

    return nil
}

// 将 build 的结果返回为二维数组
func (tree *Tree) BuildFormatList(data []map[string]interface{}, parentid interface{}) []map[string]interface{} {
    if len(data) <= 0 {
        return nil
    }

    var list []map[string]interface{} = make([]map[string]interface{}, 0)
    for _, v := range data {
        if len(v) > 0 {
            if _, ok := v[tree.spacerKey]; !ok {
                v[tree.spacerKey] = ""
            }

            var ok2 bool
            var child interface{}
            if child, ok2 = v[tree.buildChildKey]; ok2 {
                v[tree.haschildKey] = 1
            } else {
                v[tree.haschildKey] = 0
            }

            delete(v, tree.buildChildKey)

            if _, ok3 := v[tree.parentidKey]; !ok3 {
                v[tree.parentidKey] = parentid
            }

            list = append(list, v)

            if child != nil {
                children := child.([]map[string]interface{})
                if len(children) > 0 {
                    childData := tree.BuildFormatList(children, v[tree.idKey])
                    list = append(list, childData...)
                }
            }
        }
    }

    return list
}
