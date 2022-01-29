package filesystem

import(
    "io"
    "os"
    "strings"

    "github.com/deatil/go-filesystem/filesystem/interfaces"
)

// 文件系统实例化
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

/**
 * 文件系统
 *
 * @create 2021-8-7
 * @author deatil
 */
type MountManager struct {
    filesystems map[string]interfaces.Fllesystem
}

// 批量
func (this *MountManager) MountFilesystems(filesystems map[string]interface{}) *MountManager {
    for prefix, filesystem := range filesystems {
        this.MountFilesystem(prefix, filesystem.(interfaces.Fllesystem))
    }

    return this
}

// 单独
func (this *MountManager) MountFilesystem(prefix string, filesystem interfaces.Fllesystem) *MountManager {
    this.filesystems[prefix] = filesystem

    return this
}

// 获取文件管理器
func (this *MountManager) GetFilesystem(prefix string) interfaces.Fllesystem {
    if _, ok := this.filesystems[prefix]; !ok {
        panic("[" + prefix + "]文件管理前缀不存在")
    }

    return this.filesystems[prefix]
}

// 过滤
// [:prefix, :arguments]
func (this *MountManager) FilterPrefix(arguments []string) (string, []string) {
    if len(arguments) < 1 {
        panic("arguments 切片不能为空")
    }

    path := arguments[0]

    prefix, path := this.GetPrefixAndPath(path)

    newArguments := make([]string, len(arguments))
    newArguments = append(newArguments, path)
    newArguments = append(newArguments, arguments[1:]...)

    return prefix, newArguments
}

// 获取前缀和路径
// [:prefix, :path]
func (this *MountManager) GetPrefixAndPath(path string) (string, string) {
    paths := strings.SplitN(path, "://", 2)

    if len(paths) < 1 {
        panic("在 " + path + " 里前缀 prefix 不存在")
    }

    return paths[0], paths[1]
}

// 列出内容
func (this *MountManager) ListContents(directory string, recursive ...bool) []map[string]interface{} {
    prefix, dir := this.GetPrefixAndPath(directory)

    filesystem := this.GetFilesystem(prefix)

    result := filesystem.ListContents(dir, recursive...)

    for key, item := range result {
        item["filesystem"] = prefix
        result[key] = item
    }

    return result
}

// 复制
func (this *MountManager) Copy(from string, to string, conf ...map[string]interface{}) bool {
    prefixFrom, pathFrom := this.GetPrefixAndPath(from)

    buffer := this.GetFilesystem(prefixFrom).ReadStream(pathFrom)
    if buffer == nil {
        return false
    }

    // 手动关闭文件流
    defer buffer.Close()

    prefixTo, pathTo := this.GetPrefixAndPath(to)

    result := this.GetFilesystem(prefixTo).WriteStream(pathTo, buffer, conf...)

    return result
}

// 移动
func (this *MountManager) Move(from string, to string, conf ...map[string]interface{}) bool {
    prefixFrom, pathFrom := this.GetPrefixAndPath(from)
    prefixTo, pathTo := this.GetPrefixAndPath(to)

    if prefixFrom == prefixTo {
        filesystem := this.GetFilesystem(prefixFrom)
        renamed := filesystem.Rename(pathFrom, pathTo)

        if len(conf) > 0 {
            if visibility, ok := conf[0]["visibility"]; ok && renamed {
                return filesystem.SetVisibility(pathTo, visibility.(string))
            }
        }

        return renamed
    }

    copied := this.Copy(from, to, conf...)

    if copied {
        return this.Delete(from)
    }

    return false
}

// 判断
func (this *MountManager) Has(path string) bool {
    prefix, newPath := this.GetPrefixAndPath(path)

    return this.GetFilesystem(prefix).Has(newPath)
}

// 文件到字符
func (this *MountManager) Read(path string) interface{} {
    prefix, newPath := this.GetPrefixAndPath(path)

    return this.GetFilesystem(prefix).Read(newPath)
}

// 读取成数据流
func (this *MountManager) ReadStream(path string) *os.File {
    prefix, newPath := this.GetPrefixAndPath(path)

    return this.GetFilesystem(prefix).ReadStream(newPath)
}

// 信息数据
func (this *MountManager) GetMetadata(path string) map[string]interface{} {
    prefix, newPath := this.GetPrefixAndPath(path)

    return this.GetFilesystem(prefix).GetMetadata(newPath)
}

// 大小
func (this *MountManager) GetSize(path string) int64 {
    prefix, newPath := this.GetPrefixAndPath(path)

    return this.GetFilesystem(prefix).GetSize(newPath)
}

// 类型
func (this *MountManager) GetMimetype(path string) string {
    prefix, newPath := this.GetPrefixAndPath(path)

    return this.GetFilesystem(prefix).GetMimetype(newPath)
}

// 时间戳
func (this *MountManager) GetTimestamp(path string) int64 {
    prefix, newPath := this.GetPrefixAndPath(path)

    return this.GetFilesystem(prefix).GetTimestamp(newPath)
}

// 权限
func (this *MountManager) GetVisibility(path string) string {
    prefix, newPath := this.GetPrefixAndPath(path)

    return this.GetFilesystem(prefix).GetVisibility(newPath)
}

// 写入文件
func (this *MountManager) Write(path string, contents string, conf ...map[string]interface{}) bool {
    prefix, newPath := this.GetPrefixAndPath(path)

    return this.GetFilesystem(prefix).Write(newPath, contents, conf...)
}

// 写入数据流
func (this *MountManager) WriteStream(path string, resource io.Reader, conf ...map[string]interface{}) bool {
    prefix, newPath := this.GetPrefixAndPath(path)

    return this.GetFilesystem(prefix).WriteStream(newPath, resource, conf...)
}

// 更新字符
func (this *MountManager) Update(path string, contents string, conf ...map[string]interface{}) bool {
    prefix, newPath := this.GetPrefixAndPath(path)

    return this.GetFilesystem(prefix).Update(newPath, contents, conf...)
}

// 更新数据流
func (this *MountManager) UpdateStream(path string, resource io.Reader, conf ...map[string]interface{}) bool {
    prefix, newPath := this.GetPrefixAndPath(path)

    return this.GetFilesystem(prefix).UpdateStream(newPath, resource, conf...)
}

// 重命名
func (this *MountManager) Rename(path string, newpath string) bool {
    prefix, pather := this.GetPrefixAndPath(path)

    return this.GetFilesystem(prefix).Rename(pather, newpath)
}

// 删除
func (this *MountManager) Delete(path string) bool {
    prefix, newPath := this.GetPrefixAndPath(path)

    return this.GetFilesystem(prefix).Delete(newPath)
}

// 删除文件夹
func (this *MountManager) DeleteDir(dirname string) bool {
    prefix, newDirname := this.GetPrefixAndPath(dirname)

    return this.GetFilesystem(prefix).DeleteDir(newDirname)
}

// 创建文件夹
func (this *MountManager) CreateDir(dirname string, conf ...map[string]interface{}) bool {
    prefix, newDirname := this.GetPrefixAndPath(dirname)

    return this.GetFilesystem(prefix).CreateDir(newDirname, conf...)
}

// 设置权限
func (this *MountManager) SetVisibility(path string, visibility string) bool {
    prefix, newPath := this.GetPrefixAndPath(path)

    return this.GetFilesystem(prefix).SetVisibility(newPath, visibility)
}

// 更新
func (this *MountManager) Put(path string, contents string, conf ...map[string]interface{}) bool {
    prefix, newPath := this.GetPrefixAndPath(path)

    return this.GetFilesystem(prefix).Put(newPath, contents, conf...)
}

// 更新数据流
func (this *MountManager) PutStream(path string, resource io.Reader, conf ...map[string]interface{}) bool {
    prefix, newPath := this.GetPrefixAndPath(path)

    return this.GetFilesystem(prefix).PutStream(newPath, resource, conf...)
}

// 读取并删除
func (this *MountManager) ReadAndDelete(path string) (interface{}, error) {
    prefix, newPath := this.GetPrefixAndPath(path)

    return this.GetFilesystem(prefix).ReadAndDelete(newPath)
}

// 获取
// Get("file.txt").(*fllesystem.File).Read()
// Get("/file").(*fllesystem.Directory).Read()
func (this *MountManager) Get(path string, handler ...func(interfaces.Fllesystem, string) interface{}) interface{} {
    prefix, newPath := this.GetPrefixAndPath(path)

    return this.GetFilesystem(prefix).Get(newPath, handler...)
}
