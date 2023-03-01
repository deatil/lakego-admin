package adapter

var (
    // 默认
    defaultPath *Path
)

type (
    // 路径类型
    PathesMap = map[string][]string
)

func init() {
    defaultPath = NewPath()
}

/**
 * 配置路径
 *
 * @create 2022-1-3
 * @author deatil
 */
type Path struct {
    // 路径
    Pathes PathesMap
}

// 单例
func NewPath() *Path {
    path := &Path{
        Pathes: make(PathesMap),
    }

    return path
}

// 添加
func (this *Path) WithPath(name string, path string) *Path {
    if _, ok := this.Pathes[name]; !ok {
        this.Pathes[name] = make([]string, 0)
    }

    this.Pathes[name] = append(this.Pathes[name], path)

    return this
}

// 添加
func WithPath(name string, path string) *Path {
    return defaultPath.WithPath(name, path)
}

// 获取
func (this *Path) GetPath(name string) []string {
    if paths, ok := this.Pathes[name]; ok {
        return paths
    }

    return make([]string, 0)
}

// 获取
func GetPath(name string) []string {
    return defaultPath.GetPath(name)
}
