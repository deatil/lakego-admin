package tree

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
