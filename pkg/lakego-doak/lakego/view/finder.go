package view

import (
    "os"
    "sync"
    "strings"
    "path"
    "path/filepath"
)

var instance *ViewFinder
var once sync.Once

// 单例
func InstanceViewFinder() *ViewFinder {
    once.Do(func() {
        instance = NewViewFinder()
    })

    return instance
}

// 构造函数
func NewViewFinder() *ViewFinder {
    return &ViewFinder{
        HintPathDelimiter: "::",
        Paths: make(PathsArray, 0),
        Views: make(ViewsMap),
        Hints: make(HintsMap),
        Extensions: ExtensionsArray{
            "htm",
            "php",
            "css",
            "html",
        },
    }
}

type (
    // 路径
    PathsArray = []string

    // 试图
    ViewsMap = map[string]string

    // 命中
    HintsMap = map[string][]string

    // 后缀
    ExtensionsArray = []string
)

/**
 * 视图
 *
 * @create 2022-1-1
 * @author deatil
 */
type ViewFinder struct {
    // 分隔符 "::"
    HintPathDelimiter string

    // 路径
    Paths PathsArray

    // 试图
    Views ViewsMap

    // 命中
    Hints HintsMap

    // 后缀
    Extensions ExtensionsArray
}

// 查找视图
func (this *ViewFinder) Find(name string) string {
    name = this.NormalizeName(name)

    if viewsData, ok := this.Views[name]; ok {
        return viewsData
    }

    name = strings.Trim(name, " ")

    if this.HasHintInformation(name) {
        this.Views[name] = this.FindNamespacedView(name)
        return this.Views[name]
    }

    this.Views[name] = this.FindInPaths(name, this.Paths)
    return this.Views[name]
}

// 查找命名空间视图
func (this *ViewFinder) FindNamespacedView(name string) string {
    data := this.ParseNamespaceSegments(name)

    namespace := data[0]
    view := data[1]

    return this.FindInPaths(view, this.Hints[namespace])
}

// 解析命名空间
func (this *ViewFinder) ParseNamespaceSegments(name string) []string {
    segments := strings.Split(name, this.HintPathDelimiter)

    if len(segments) != 2 {
        panic("视图文件名 [" + name + "] 错误")
    }

    if _, ok := this.Hints[segments[0]]; !ok {
        panic("该 [" + segments[0] + "] 没有定义文件目录")
    }

    return segments
}

// 在目录里查找文件
func (this *ViewFinder) FindInPaths(name string, paths []string) string {
    if len(paths) > 0 {
        for _, pathV := range paths {
            for _, file := range this.GetPossibleViewFiles(name) {
                viewPath := path.Join(pathV, file)
                if !filepath.IsAbs(viewPath) {
                    viewPath, _ = filepath.Abs(viewPath)
                }

                if this.FileExist(viewPath) {
                    return viewPath
                }
            }
        }
    }

    panic("视图文件 [" + name + "] 不存在")
}

// 添加
func (this *ViewFinder) GetPossibleViewFiles(name string) []string {
    nameArray := make([]string, 0)
    if len(this.Extensions) > 0 {
        for _, ext := range this.Extensions {
            nameArray = append(nameArray, strings.ReplaceAll(name, ".", "/") + "." + ext)
        }
    }

    return nameArray
}

// 添加
func (this *ViewFinder) AddLocation(location string) *ViewFinder {
    this.Paths = append(this.Paths, location)

    return this
}

// prependLocation
func (this *ViewFinder) PrependLocation(location string) *ViewFinder {
    location = this.ResolvePath(location)

    this.Paths = append(PathsArray{location}, this.Paths...)

    return this
}

// 重设路径
func (this *ViewFinder) ResolvePath(path string) string {
    newPath, err := filepath.Abs(path)
    if err != nil {
        panic(err)
    }

    return newPath
}

// 重设
func (this *ViewFinder) NormalizeName(name string) string {
    delimiter := this.HintPathDelimiter

    if !strings.Contains(name, delimiter) {
        return strings.ReplaceAll(name, "/", ".")
    }

    arr := strings.SplitN(name, delimiter, 2)

    namespace := arr[0]
    name2 := arr[1]

    return namespace + delimiter + strings.ReplaceAll(name2, "/", ".")
}

// 添加命名空间
func (this *ViewFinder) AddNamespace(namespace string, hints []string) *ViewFinder {
    newHints := hints
    if getHints, ok := this.Hints[namespace]; ok {
        newHints = append(getHints, newHints...)
    }

    this.Hints[namespace] = newHints

    return this
}

// 添加命名空间到前面
func (this *ViewFinder) PrependNamespace(namespace string, hints []string) *ViewFinder {
    newHints := hints
    if getHints, ok := this.Hints[namespace]; ok {
        newHints = append(newHints, getHints...)
    }

    this.Hints[namespace] = newHints

    return this
}

// 替换命名空间
func (this *ViewFinder) ReplaceNamespace(namespace string, hints []string) *ViewFinder {
    this.Hints[namespace] = hints

    return this
}

// 添加后缀
func (this *ViewFinder) AddExtension(extension string) *ViewFinder {
    for extk, ext := range this.Extensions {
        if ext == extension {
            this.Extensions = append(this.Extensions[:extk], this.Extensions[extk:]...)
        }
    }

    oldExtensions := this.Extensions
    newExtensions := ExtensionsArray{extension}
    this.Extensions = append(newExtensions, oldExtensions...)

    return this
}

// 判断是否有分隔符
func (this *ViewFinder) HasHintInformation(name string) bool {
    return strings.Contains(name, this.HintPathDelimiter)
}

// 清空
func (this *ViewFinder) Flush() *ViewFinder {
    this.Views = ViewsMap{}

    return this
}

// 获取试图
func (this *ViewFinder) GetViews() ViewsMap {
    return this.Views
}

// 获取命中
func (this *ViewFinder) GetHints() HintsMap {
    return this.Hints
}

// 获取后缀
func (this *ViewFinder) GetExtensions() ExtensionsArray {
    return this.Extensions
}

// 文件判断是否存在
func (this *ViewFinder) FileExist(filename string) bool {
    _, err := os.Stat(filename)
    return err == nil || os.IsExist(err)
}

