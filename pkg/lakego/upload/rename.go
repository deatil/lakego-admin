package upload

import (
    "fmt"
    "path"
    "time"
    "strconv"
    "strings"

    "github.com/deatil/lakego-admin/lakego/support/hash"
    "github.com/deatil/lakego-admin/lakego/support/random"
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
func (rename *Rename) WithFileName(filename string) *Rename {
    rename.defaultExtension = strings.TrimPrefix(path.Ext(filename), ".")
    rename.defaultName = strings.TrimSuffix(filename, "." + rename.defaultExtension)

    return rename
}

// 设置文件存在检测函数
func (rename *Rename) WithCheckFileExistsFunc(f func(string) bool) *Rename {
    rename.checkFileExistsFunc = f

    return rename
}

// 设置默认的命名
func (rename *Rename) WithDefaultName(name string) *Rename {
    rename.defaultName = name

    return rename
}

// 获取默认的命名
func (rename *Rename) GetDefaultName() string {
    return rename.defaultName
}

// 设置默认的后缀
func (rename *Rename) WithdDefaultExtension(ext string) *Rename {
    rename.defaultExtension = ext

    return rename
}

// 获取默认的后缀
func (rename *Rename) GetDefaultExtension() string {
    return rename.defaultExtension
}

// 设置文件名
func (rename *Rename) WithName(name string) *Rename {
    rename.name = name

    return rename
}

// 获取文件名
func (rename *Rename) GetName() interface{} {
    return rename.name
}

// UniqueName 命名文件名
func (rename *Rename) UniqueName() *Rename {
    rename.generateName = "unique"

    return rename
}

// datetimeName 命名文件名
func (rename *Rename) DatetimeName() *Rename {
    rename.generateName = "datetime"

    return rename
}

// sequenceName 命名文件名
func (rename *Rename) SequenceName() *Rename {
    rename.generateName = "sequence"

    return rename
}

// 唯一命名
func (rename *Rename) GenerateUniqueName() string {
    name := hash.MD5(strconv.FormatInt(time.Now().Unix(), 10))

    return name + "." + rename.GetDefaultExtension()
}

// 时间命名
func (rename *Rename) GenerateDatetimeName() string {
    name := fmt.Sprintf("%s", time.Now().Format("20060102150405")) + random.String(6, random.Numeric)

    return name + "." + rename.GetDefaultExtension()
}

// sequence 命名
func (rename *Rename) GenerateSequenceName() string {
    var index int = 1
    extension := rename.GetDefaultExtension()
    original := rename.GetDefaultName()
    newFilename := fmt.Sprintf("%s_%d.%s", original, index, extension)

    for {
        if rename.checkFileExistsFunc == nil {
            break
        }

        if !rename.checkFileExistsFunc(newFilename) {
            break
        }

        index++
        newFilename = fmt.Sprintf("%s_%d.%s", original, index, extension)
    }

    return newFilename
}

// 原始命名
func (rename *Rename) GenerateClientName() string {
    return rename.GetDefaultName() + "." + rename.GetDefaultExtension()
}

// 获取最后存储名称
func (rename *Rename) GetStoreName() string {
    if rename.name != "" {
        return rename.name
    }

    if rename.generateName == "unique" {
        return rename.GenerateUniqueName()
    } else if rename.generateName == "datetime" {
        return rename.GenerateDatetimeName()
    } else if rename.generateName == "sequence" {
        return rename.GenerateSequenceName()
    }

    return rename.GenerateClientName()
}

