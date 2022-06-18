package tree

// 所有父节点
func (this *Tree) GetListParents(id string, sort ...string) []map[string]any {
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

                    parents := this.GetListParents(v[this.idKey].(string), sort...)
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
func (this *Tree) GetListParentIds(id string) []any {
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
func (this *Tree) GetListChildren(id string, sort ...string) []map[string]any {
    if len(this.data) <= 0 {
        return nil
    }

    var order string = "desc"
    if len(sort) > 0{
        order = sort[0]
    }

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

                    children := this.GetListChildren(v[this.idKey].(string), sort...)
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
func (this *Tree) GetListChildIds(id string) []any {
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
func (this *Tree) GetListChild(id string) []map[string]any {
    if len(this.data) <= 0 {
        return nil
    }

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
func (this *Tree) GetListSelf(id string) map[string]any {
    if len(this.data) <= 0 {
        return nil
    }

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
