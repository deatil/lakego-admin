package tree

type Ordered interface{
    ~int | ~int8 | ~int16 | ~int32 | ~int64 |
    ~uint | ~uint8 | ~uint16 | ~uint32 | ~uint64 |
    ~float32 | ~float64 |
    ~string
}

/**
 * map 数据格式化为树
 *
 * @create 2021-9-8
 * @author deatil
 */
type Tree[K Ordered] struct {
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
