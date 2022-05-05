package upload

import (
    "fmt"
    "path"
    "time"
    "strconv"
    "strings"

    "github.com/deatil/go-hash/hash"
    "github.com/deatil/lakego-doak/lakego/random"
)

// 重命名
func NewRename() *Rename {
    return &Rename{}
}

/**
 * 重命名
 *
 * @create 2021-8-15
 * @author deatil
 */
type Rename struct {
    // 自定义命名
    name string

    // 命名方式
    generateName string

    // 默认的命名
    defaultName string

    // 默认的后缀
    defaultExtension string

    // 文件存在检测
    checkFileExistsFunc func(string) bool
}

// 设置文件名带后缀
func (this *Rename) WithFileName(filename string) *Rename {
    this.defaultExtension = strings.TrimPrefix(path.Ext(filename), ".")
    this.defaultName = strings.TrimSuffix(filename, "." + this.defaultExtension)

    return this
}

// 设置文件存在检测函数
func (this *Rename) WithCheckFileExistsFunc(f func(string) bool) *Rename {
    this.checkFileExistsFunc = f

    return this
}

// 设置默认的命名
func (this *Rename) WithDefaultName(name string) *Rename {
    this.defaultName = name

    return this
}

// 获取默认的命名
func (this *Rename) GetDefaultName() string {
    return this.defaultName
}

// 设置默认的后缀
func (this *Rename) WithdDefaultExtension(ext string) *Rename {
    this.defaultExtension = ext

    return this
}

// 获取默认的后缀
func (this *Rename) GetDefaultExtension() string {
    return this.defaultExtension
}

// 设置文件名
func (this *Rename) WithName(name string) *Rename {
    this.name = name

    return this
}

// 获取文件名
func (this *Rename) GetName() any {
    return this.name
}

// UniqueName 命名文件名
func (this *Rename) UniqueName() *Rename {
    this.generateName = "unique"

    return this
}

// datetimeName 命名文件名
func (this *Rename) DatetimeName() *Rename {
    this.generateName = "datetime"

    return this
}

// sequenceName 命名文件名
func (this *Rename) SequenceName() *Rename {
    this.generateName = "sequence"

    return this
}

// 唯一命名
func (this *Rename) GenerateUniqueName() string {
    name := hash.MD5(strconv.FormatInt(time.Now().Unix(), 10))

    return name + "." + this.GetDefaultExtension()
}

// 时间命名
func (this *Rename) GenerateDatetimeName() string {
    name := fmt.Sprintf("%s", time.Now().Format("20060102150405")) + random.String(6, random.Numeric)

    return name + "." + this.GetDefaultExtension()
}

// sequence 命名
func (this *Rename) GenerateSequenceName() string {
    var index int = 1
    extension := this.GetDefaultExtension()
    original := this.GetDefaultName()
    newFilename := fmt.Sprintf("%s_%d.%s", original, index, extension)

    for {
        if this.checkFileExistsFunc == nil {
            break
        }

        if !this.checkFileExistsFunc(newFilename) {
            break
        }

        index++
        newFilename = fmt.Sprintf("%s_%d.%s", original, index, extension)
    }

    return newFilename
}

// 原始命名
func (this *Rename) GenerateClientName() string {
    return this.GetDefaultName() + "." + this.GetDefaultExtension()
}

// 获取最后存储名称
func (this *Rename) GetStoreName() string {
    if this.name != "" {
        return this.name
    }

    if this.generateName == "unique" {
        return this.GenerateUniqueName()
    } else if this.generateName == "datetime" {
        return this.GenerateDatetimeName()
    } else if this.generateName == "sequence" {
        return this.GenerateSequenceName()
    }

    return this.GenerateClientName()
}

