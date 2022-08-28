package tree

func (this *Tree[K]) WithIcon(icon []string) *Tree[K] {
    this.icon = icon
    return this
}

func (this *Tree[K]) WithBlankspace(blankspace string) *Tree[K] {
    this.blankspace = blankspace
    return this
}

func (this *Tree[K]) WithIdKey(idKey string) *Tree[K] {
    this.idKey = idKey
    return this
}

func (this *Tree[K]) WithParentidKey(parentidKey string) *Tree[K] {
    this.parentidKey = parentidKey
    return this
}

func (this *Tree[K]) WithSpacerKey(spacerKey string) *Tree[K] {
    this.spacerKey = spacerKey
    return this
}

func (this *Tree[K]) WithDepthKey(depthKey string) *Tree[K] {
    this.depthKey = depthKey
    return this
}

func (this *Tree[K]) WithHaschildKey(haschildKey string) *Tree[K] {
    this.haschildKey = haschildKey
    return this
}

func (this *Tree[K]) WithBuildChildKey(buildChildKey string) *Tree[K] {
    this.buildChildKey = buildChildKey
    return this
}

// 设置数据
func (this *Tree[K]) WithData(data []map[string]any) *Tree[K] {
    this.data = data
    return this
}
