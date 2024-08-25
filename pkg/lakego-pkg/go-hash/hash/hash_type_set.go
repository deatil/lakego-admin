package hash

// Type Name
type TypeName interface {
    ~uint | ~int
}

// Type Set
type TypeSet[N TypeName, D any] struct {
    // 最大值
    max N

    // 数据
    names *DataSet[N, D]
}

// New TypeSet
func NewTypeSet[N TypeName, D any](max N) *TypeSet[N, D] {
    return &TypeSet[N, D]{
        max:   max,
        names: NewDataSet[N, D](),
    }
}

// 生成新序列
// Generate new id
func (this *TypeSet[N, D]) Generate() N {
    old := this.max
    this.max++

    return old
}

// 类型名称列表
// name list
func (this *TypeSet[N, D]) Names() *DataSet[N, D] {
    return this.names
}
