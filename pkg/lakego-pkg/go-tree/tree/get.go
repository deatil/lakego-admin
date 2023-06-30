package tree

// 所有父节点
func (this *Tree[K]) GetListParents(parentid K, sort ...string) []map[string]any {
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
        dataId, ok := v[this.idKey].(K)
        if !ok {
            continue
        }

        if dataId == parentid {
            newData = append(newData, v)

            parents := this.GetListParents(v[this.parentidKey].(K), sort...)
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
func (this *Tree[K]) GetListParentIds(id K) []K {
    data := this.GetListParents(id)
    if len(data) <= 0 {
        return nil
    }

    ids := make([]K, 0)
    for _, v := range data {
        // 不存在跳过
        dataId, ok := v[this.idKey].(K)
        if !ok {
            continue
        }

        ids = append(ids, dataId)
    }

    return ids
}

// 获取当前ID的所有子节点
func (this *Tree[K]) GetListChildren(id K, sort ...string) []map[string]any {
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
        dataParentId, ok := v[this.parentidKey].(K)
        if !ok {
            continue
        }

        if dataParentId == id {
            newData = append(newData, v)

            children := this.GetListChildren(v[this.idKey].(K), sort...)
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
func (this *Tree[K]) GetListChildIds(id K) []K {
    data := this.GetListChildren(id)
    if len(data) <= 0 {
        return nil
    }

    ids := make([]K, 0)
    for _, v := range data {
        // 不存在跳过
        dataId, ok := v[this.idKey].(K)
        if !ok {
            continue
        }

        ids = append(ids, dataId)
    }

    return ids
}

// 得到子级第一级数组
func (this *Tree[K]) GetListChild(id K) []map[string]any {
    if len(this.data) <= 0 {
        return nil
    }

    newData := make([]map[string]any, 0)
    for _, v := range this.data {
        // 不存在跳过
        dataParentId, ok := v[this.parentidKey].(K)
        if !ok {
            continue
        }

        if dataParentId == id {
            newData = append(newData, v)
        }
    }

    return newData
}

// 获取ID自己的数据
func (this *Tree[K]) GetListSelf(id K) map[string]any {
    if len(this.data) <= 0 {
        return nil
    }

    for _, v := range this.data {
        // 不存在跳过
        dataId, ok := v[this.idKey].(K)
        if !ok {
            continue
        }

        if dataId == id {
            return v
        }
    }

    return nil
}
