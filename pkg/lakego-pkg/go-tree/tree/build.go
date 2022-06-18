package tree

// 构建数组
func (this *Tree) Build(id string, itemprefix string, depth int) []map[string]any {
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

        childList := this.Build(v[this.idKey].(string), itemprefix + k + this.blankspace, depth + 1)
        if len(childList) > 0{
            info[this.buildChildKey] = childList
        }

        data = append(data, info)
        number++
    }

    return data
}

// 将 build 的结果返回为二维数组
func (this *Tree) BuildFormatList(data []map[string]any, parentid string) []map[string]any {
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
                    childData := this.BuildFormatList(children, v[this.idKey].(string))
                    list = append(list, childData...)
                }
            }
        }
    }

    return list
}
