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
