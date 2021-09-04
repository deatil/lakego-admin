package fllesystem

import(
    "os"
    "strings"

    "lakego-admin/lakego/fllesystem/interfaces"
)

/**
 * 文件系统
 *
 * @create 2021-8-7
 * @author deatil
 */
type MountManager struct {
    filesystems map[string]interfaces.Fllesystem
}

// 实例化
func NewMountManager(filesystems ...map[string]interface{}) *MountManager {
    ifs := make(map[string]interfaces.Fllesystem)
    mm := &MountManager{
        filesystems: ifs,
    }

    if len(filesystems) > 0{
        mm.MountFilesystems(filesystems[0])
    }

    return mm
}

// 批量
func (mm *MountManager) MountFilesystems(filesystems map[string]interface{}) *MountManager {
    for prefix, filesystem := range filesystems {
        mm.MountFilesystem(prefix, filesystem.(interfaces.Fllesystem))
    }

    return mm
}

// 单独
func (mm *MountManager) MountFilesystem(prefix string, filesystem interfaces.Fllesystem) *MountManager {
    mm.filesystems[prefix] = filesystem

    return mm
}

// 获取文件管理器
func (mm *MountManager) GetFilesystem(prefix string) interfaces.Fllesystem {
    if _, ok := mm.filesystems[prefix]; !ok {
        panic("[" + prefix + "]文件管理前缀不存在")
    }

    return mm.filesystems[prefix]
}

// 过滤
// [:prefix, :arguments]
func (mm *MountManager) FilterPrefix(arguments []string) (string, []string) {
    if len(arguments) < 1 {
        panic("arguments 切片不能为空")
    }

    path := arguments[0]

    prefix, path := mm.GetPrefixAndPath(path)

    newArguments := make([]string, len(arguments))
    newArguments = append(newArguments, path)
    newArguments = append(newArguments, arguments[1:]...)

    return prefix, newArguments
}

// 获取前缀和路径
// [:prefix, :path]
func (mm *MountManager) GetPrefixAndPath(path string) (string, string) {
    paths := strings.SplitN(path, "://", 2)

    if len(paths) < 1 {
        panic("在 " + path + " 里前缀 prefix 不存在")
    }

    return paths[0], paths[1]
}

// 列出内容
func (mm *MountManager) ListContents(directory string, recursive ...bool) []map[string]interface{} {
    prefix, dir := mm.GetPrefixAndPath(directory)

    filesystem := mm.GetFilesystem(prefix)

    result := filesystem.ListContents(dir, recursive...)

    for key, item := range result {
        item["filesystem"] = prefix
        result[key] = item
    }

    return result
}

// 复制
func (mm *MountManager) Copy(from string, to string, conf ...map[string]interface{}) bool {
    prefixFrom, pathFrom := mm.GetPrefixAndPath(from)

    buffer := mm.GetFilesystem(prefixFrom).ReadStream(pathFrom)
    if buffer == nil {
        return false
    }

    // 手动关闭文件流
    defer buffer.Close()

    prefixTo, pathTo := mm.GetPrefixAndPath(to)

    result := mm.GetFilesystem(prefixTo).WriteStream(pathTo, buffer, conf...)

    return result
}

// 移动
func (mm *MountManager) Move(from string, to string, conf ...map[string]interface{}) bool {
    prefixFrom, pathFrom := mm.GetPrefixAndPath(from)
    prefixTo, pathTo := mm.GetPrefixAndPath(to)

    if prefixFrom == prefixTo {
        filesystem := mm.GetFilesystem(prefixFrom)
        renamed := filesystem.Rename(pathFrom, pathTo)

        if len(conf) > 0 {
            if visibility, ok := conf[0]["visibility"]; ok && renamed {
                return filesystem.SetVisibility(pathTo, visibility.(string))
            }
        }

        return renamed
    }

    copied := mm.Copy(from, to, conf...)

    if copied {
        return mm.Delete(from)
    }

    return false
}

// 判断
func (mm *MountManager) Has(path string) bool {
    prefix, newPath := mm.GetPrefixAndPath(path)

    return mm.GetFilesystem(prefix).Has(newPath)
}

// 文件到字符
func (mm *MountManager) Read(path string) interface{} {
    prefix, newPath := mm.GetPrefixAndPath(path)

    return mm.GetFilesystem(prefix).Read(newPath)
}

// 读取成数据流
func (mm *MountManager) ReadStream(path string) *os.File {
    prefix, newPath := mm.GetPrefixAndPath(path)

    return mm.GetFilesystem(prefix).ReadStream(newPath)
}

// 信息数据
func (mm *MountManager) GetMetadata(path string) map[string]interface{} {
    prefix, newPath := mm.GetPrefixAndPath(path)

    return mm.GetFilesystem(prefix).GetMetadata(newPath)
}

// 大小
func (mm *MountManager) GetSize(path string) int64 {
    prefix, newPath := mm.GetPrefixAndPath(path)

    return mm.GetFilesystem(prefix).GetSize(newPath)
}

// 类型
func (mm *MountManager) GetMimetype(path string) string {
    prefix, newPath := mm.GetPrefixAndPath(path)

    return mm.GetFilesystem(prefix).GetMimetype(newPath)
}

// 时间戳
func (mm *MountManager) GetTimestamp(path string) int64 {
    prefix, newPath := mm.GetPrefixAndPath(path)

    return mm.GetFilesystem(prefix).GetTimestamp(newPath)
}

// 权限
func (mm *MountManager) GetVisibility(path string) string {
    prefix, newPath := mm.GetPrefixAndPath(path)

    return mm.GetFilesystem(prefix).GetVisibility(newPath)
}

// 写入文件
func (mm *MountManager) Write(path string, contents string, conf ...map[string]interface{}) bool {
    prefix, newPath := mm.GetPrefixAndPath(path)

    return mm.GetFilesystem(prefix).Write(newPath, contents, conf...)
}

// 写入数据流
func (mm *MountManager) WriteStream(path string, resource *os.File, conf ...map[string]interface{}) bool {
    prefix, newPath := mm.GetPrefixAndPath(path)

    return mm.GetFilesystem(prefix).WriteStream(newPath, resource, conf...)
}

// 更新字符
func (mm *MountManager) Update(path string, contents string, conf ...map[string]interface{}) bool {
    prefix, newPath := mm.GetPrefixAndPath(path)

    return mm.GetFilesystem(prefix).Update(newPath, contents, conf...)
}

// 更新数据流
func (mm *MountManager) UpdateStream(path string, resource *os.File, conf ...map[string]interface{}) bool {
    prefix, newPath := mm.GetPrefixAndPath(path)

    return mm.GetFilesystem(prefix).UpdateStream(newPath, resource, conf...)
}

// 重命名
func (mm *MountManager) Rename(path string, newpath string) bool {
    prefix, pather := mm.GetPrefixAndPath(path)

    return mm.GetFilesystem(prefix).Rename(pather, newpath)
}

// 删除
func (mm *MountManager) Delete(path string) bool {
    prefix, newPath := mm.GetPrefixAndPath(path)

    return mm.GetFilesystem(prefix).Delete(newPath)
}

// 删除文件夹
func (mm *MountManager) DeleteDir(dirname string) bool {
    prefix, newDirname := mm.GetPrefixAndPath(dirname)

    return mm.GetFilesystem(prefix).DeleteDir(newDirname)
}

// 创建文件夹
func (mm *MountManager) CreateDir(dirname string, conf ...map[string]interface{}) bool {
    prefix, newDirname := mm.GetPrefixAndPath(dirname)

    return mm.GetFilesystem(prefix).CreateDir(newDirname, conf...)
}

// 设置权限
func (mm *MountManager) SetVisibility(path string, visibility string) bool {
    prefix, newPath := mm.GetPrefixAndPath(path)

    return mm.GetFilesystem(prefix).SetVisibility(newPath, visibility)
}

// 更新
func (mm *MountManager) Put(path string, contents string, conf ...map[string]interface{}) bool {
    prefix, newPath := mm.GetPrefixAndPath(path)

    return mm.GetFilesystem(prefix).Put(newPath, contents, conf...)
}

// 更新数据流
func (mm *MountManager) PutStream(path string, resource *os.File, conf ...map[string]interface{}) bool {
    prefix, newPath := mm.GetPrefixAndPath(path)

    return mm.GetFilesystem(prefix).PutStream(newPath, resource, conf...)
}

// 读取并删除
func (mm *MountManager) ReadAndDelete(path string) (interface{}, error) {
    prefix, newPath := mm.GetPrefixAndPath(path)

    return mm.GetFilesystem(prefix).ReadAndDelete(newPath)
}

// 获取
// Get("file.txt").(*fllesystem.File).Read()
// Get("/file").(*fllesystem.Directory).Read()
func (mm *MountManager) Get(path string, handler ...func(interfaces.Fllesystem, string) interface{}) interface{} {
    prefix, newPath := mm.GetPrefixAndPath(path)

    return mm.GetFilesystem(prefix).Get(newPath, handler...)
}
