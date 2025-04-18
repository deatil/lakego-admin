package filesystem

import(
    "io"
    "os"
    "strings"
)

/**
 * 文件系统
 *
 * @create 2021-8-7
 * @author deatil
 */
type MountManager struct {
    filesystems map[string]*Filesystem
}

// 文件系统实例化
func NewMountManager(filesystems ...map[string]any) *MountManager {
    mm := &MountManager{
        filesystems: make(map[string]*Filesystem),
    }

    if len(filesystems) > 0{
        mm.MountFilesystems(filesystems[0])
    }

    return mm
}

// 批量
func (this *MountManager) MountFilesystems(filesystems map[string]any) *MountManager {
    for prefix, filesystem := range filesystems {
        this.MountFilesystem(prefix, filesystem.(*Filesystem))
    }

    return this
}

// 单独
func (this *MountManager) MountFilesystem(prefix string, filesystem *Filesystem) *MountManager {
    this.filesystems[prefix] = filesystem

    return this
}

// 获取文件管理器
func (this *MountManager) GetFilesystem(prefix string) *Filesystem {
    if _, ok := this.filesystems[prefix]; !ok {
        panic("go-filesystem: [" + prefix + "] prefix not exists")
    }

    return this.filesystems[prefix]
}

// 过滤
// [:prefix, :arguments]
func (this *MountManager) FilterPrefix(arguments []string) (string, []string) {
    if len(arguments) < 1 {
        panic("go-filesystem: arguments slice not empty")
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
        panic("go-filesystem: " + path + "'prefix not exists")
    }

    return paths[0], paths[1]
}

// 列出内容
func (this *MountManager) ListContents(directory string, recursive ...bool) ([]map[string]any, error) {
    prefix, dir := this.GetPrefixAndPath(directory)

    filesystem := this.GetFilesystem(prefix)

    result, err := filesystem.ListContents(dir, recursive...)
    if err != nil {
        return nil, err
    }

    for key, item := range result {
        item["filesystem"] = prefix
        result[key] = item
    }

    return result, nil
}

// 复制
func (this *MountManager) Copy(from string, to string, conf ...map[string]any) (bool, error) {
    prefixFrom, pathFrom := this.GetPrefixAndPath(from)

    buffer, err := this.GetFilesystem(prefixFrom).ReadStream(pathFrom)
    if err != nil {
        return false, err
    }

    // 手动关闭文件流
    defer buffer.Close()

    prefixTo, pathTo := this.GetPrefixAndPath(to)

    result, err2 := this.GetFilesystem(prefixTo).WriteStream(pathTo, buffer, conf...)
    if err2 != nil {
        return false, err2
    }

    return result, nil
}

// 移动
func (this *MountManager) Move(from string, to string, conf ...map[string]any) (bool, error) {
    prefixFrom, pathFrom := this.GetPrefixAndPath(from)
    prefixTo, pathTo := this.GetPrefixAndPath(to)

    if prefixFrom == prefixTo {
        filesystem := this.GetFilesystem(prefixFrom)

        renamed, err := filesystem.Rename(pathFrom, pathTo)
        if err != nil {
            return false, err
        }

        if len(conf) > 0 {
            if visibility, ok := conf[0]["visibility"]; ok && renamed {
                return filesystem.SetVisibility(pathTo, visibility.(string))
            }
        }

        return renamed, nil
    }

    copied, err := this.Copy(from, to, conf...)
    if copied {
        return this.Delete(from)
    }

    return false, err
}

// 判断
func (this *MountManager) Has(path string) bool {
    prefix, newPath := this.GetPrefixAndPath(path)

    return this.GetFilesystem(prefix).Has(newPath)
}

// 文件到字符
func (this *MountManager) Read(path string) ([]byte, error) {
    prefix, newPath := this.GetPrefixAndPath(path)

    return this.GetFilesystem(prefix).Read(newPath)
}

// 读取成数据流
func (this *MountManager) ReadStream(path string) (*os.File, error) {
    prefix, newPath := this.GetPrefixAndPath(path)

    return this.GetFilesystem(prefix).ReadStream(newPath)
}

// 信息数据
func (this *MountManager) GetMetadata(path string) (map[string]any, error) {
    prefix, newPath := this.GetPrefixAndPath(path)

    return this.GetFilesystem(prefix).GetMetadata(newPath)
}

// 大小
func (this *MountManager) GetSize(path string) (int64, error) {
    prefix, newPath := this.GetPrefixAndPath(path)

    return this.GetFilesystem(prefix).GetSize(newPath)
}

// 类型
func (this *MountManager) GetMimetype(path string) (string, error) {
    prefix, newPath := this.GetPrefixAndPath(path)

    return this.GetFilesystem(prefix).GetMimetype(newPath)
}

// 时间戳
func (this *MountManager) GetTimestamp(path string) (int64, error) {
    prefix, newPath := this.GetPrefixAndPath(path)

    return this.GetFilesystem(prefix).GetTimestamp(newPath)
}

// 权限
func (this *MountManager) GetVisibility(path string) (string, error) {
    prefix, newPath := this.GetPrefixAndPath(path)

    return this.GetFilesystem(prefix).GetVisibility(newPath)
}

// 写入文件
func (this *MountManager) Write(path string, contents []byte, conf ...map[string]any) (bool, error) {
    prefix, newPath := this.GetPrefixAndPath(path)

    return this.GetFilesystem(prefix).Write(newPath, contents, conf...)
}

// 写入数据流
func (this *MountManager) WriteStream(path string, resource io.Reader, conf ...map[string]any) (bool, error) {
    prefix, newPath := this.GetPrefixAndPath(path)

    return this.GetFilesystem(prefix).WriteStream(newPath, resource, conf...)
}

// 更新字符
func (this *MountManager) Update(path string, contents []byte, conf ...map[string]any) (bool, error) {
    prefix, newPath := this.GetPrefixAndPath(path)

    return this.GetFilesystem(prefix).Update(newPath, contents, conf...)
}

// 更新数据流
func (this *MountManager) UpdateStream(path string, resource io.Reader, conf ...map[string]any) (bool, error) {
    prefix, newPath := this.GetPrefixAndPath(path)

    return this.GetFilesystem(prefix).UpdateStream(newPath, resource, conf...)
}

// 重命名
func (this *MountManager) Rename(path string, newpath string) (bool, error) {
    prefix, pather := this.GetPrefixAndPath(path)

    return this.GetFilesystem(prefix).Rename(pather, newpath)
}

// 删除
func (this *MountManager) Delete(path string) (bool, error) {
    prefix, newPath := this.GetPrefixAndPath(path)

    return this.GetFilesystem(prefix).Delete(newPath)
}

// 删除文件夹
func (this *MountManager) DeleteDir(dirname string) (bool, error) {
    prefix, newDirname := this.GetPrefixAndPath(dirname)

    return this.GetFilesystem(prefix).DeleteDir(newDirname)
}

// 创建文件夹
func (this *MountManager) CreateDir(dirname string, conf ...map[string]any) (bool, error) {
    prefix, newDirname := this.GetPrefixAndPath(dirname)

    return this.GetFilesystem(prefix).CreateDir(newDirname, conf...)
}

// 设置权限
func (this *MountManager) SetVisibility(path string, visibility string) (bool, error) {
    prefix, newPath := this.GetPrefixAndPath(path)

    return this.GetFilesystem(prefix).SetVisibility(newPath, visibility)
}

// 更新
func (this *MountManager) Put(path string, contents []byte, conf ...map[string]any) (bool, error) {
    prefix, newPath := this.GetPrefixAndPath(path)

    return this.GetFilesystem(prefix).Put(newPath, contents, conf...)
}

// 更新数据流
func (this *MountManager) PutStream(path string, resource io.Reader, conf ...map[string]any) (bool, error) {
    prefix, newPath := this.GetPrefixAndPath(path)

    return this.GetFilesystem(prefix).PutStream(newPath, resource, conf...)
}

// 读取并删除
func (this *MountManager) ReadAndDelete(path string) (any, error) {
    prefix, newPath := this.GetPrefixAndPath(path)

    return this.GetFilesystem(prefix).ReadAndDelete(newPath)
}

// 获取
// file := Get("/file.txt").(*File)
// dir := Get("/dir").(*Directory)
func (this *MountManager) Get(path string, handler ...func(*Filesystem, string) any) any {
    prefix, newPath := this.GetPrefixAndPath(path)

    return this.GetFilesystem(prefix).Get(newPath, handler...)
}
