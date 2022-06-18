package tree

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
