package tree

// 构造函数
func New[K Ordered]() *Tree[K] {
    return &Tree[K]{
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
