package local

import (
    "io"
    "os"
    "fmt"
    "errors"
    "strings"
    "net/http"
    "path/filepath"

    "github.com/deatil/go-filesystem/filesystem/interfaces"
    "github.com/deatil/go-filesystem/filesystem/adapter"
)

// 本地文件适配器
func New(root string) *Local {
    local := &Local{}

    local.EnsureDirectory(root)
    local.SetPathPrefix(root)

    return local
}

// 权限列表
var permissionMap map[string]map[string]uint32 = map[string]map[string]uint32{
    "file": {
        "public": 0644,
        "private": 0600,
    },
    "dir": {
        "public": 0755,
        "private": 0700,
    },
}

/**
 * 本地文件适配器
 *
 * @create 2021-8-1
 * @author deatil
 */
type Local struct {
    // 默认适配器基类
    adapter.Adapter

    // 权限
    visibility string
}

/**
 * 确认文件夹
 */
func (this *Local) EnsureDirectory(root string) error {
    err := os.MkdirAll(root, this.FormatPerm(permissionMap["dir"]["public"]))
    if err != nil {
        return errors.New("执行函数 os.MkdirAll() 失败, 错误为:" + err.Error())
    }

    if !this.IsFile(root) {
        return errors.New("创建一个根目录文件夹失败" )
    }

    return nil
}

/**
 * 判断是否存在
 */
func (this *Local) Has(path string) bool {
    location := this.ApplyPathPrefix(path)

    _, err := os.Stat(location)
    return err == nil || os.IsExist(err)
}

// 上传
func (this *Local) Write(path string, contents string, conf interfaces.Config) (map[string]interface{}, error) {
    location := this.ApplyPathPrefix(path)
    this.EnsureDirectory(filepath.Dir(location))

    out, createErr := os.Create(location)
    if createErr != nil {
        return nil, errors.New("执行函数 os.Create() 失败, 错误为:" + createErr.Error())
    }

    defer out.Close()

    _, writeErr := out.WriteString(contents)
    if writeErr != nil {
        return nil, errors.New("执行函数 os.WriteString() 失败, 错误为:" + writeErr.Error())
    }

    size, sizeErr := this.FileSize(location)
    if sizeErr != nil {
        return nil, errors.New("获取文件大小失败, 错误为:" + writeErr.Error())
    }

    result := map[string]interface{}{
        "type": "file",
        "size": size,
        "path": path,
        "contents": contents,
    }

    if visibility := conf.Get("visibility"); visibility != nil {
        result["visibility"] = visibility.(string)
        this.SetVisibility(location, visibility.(string))
    }

    return result, nil
}

// 上传 Stream 文件类型
func (this *Local) WriteStream(path string, stream io.Reader, conf interfaces.Config) (map[string]interface{}, error) {
    location := this.ApplyPathPrefix(path)
    this.EnsureDirectory(filepath.Dir(location))

    newFile, createErr := os.Create(location)
    if createErr != nil {
        return nil, errors.New("执行函数 os.Create() 失败, 错误为:" + createErr.Error())
    }

    defer newFile.Close()

    _, copyErr := io.Copy(newFile, stream)
    if copyErr != nil {
        return nil, errors.New("写入文件流失败, 错误为:" + copyErr.Error())
    }

    result := map[string]interface{}{
        "type": "file",
        "path": path,
    }

    if visibility := conf.Get("visibility"); visibility != nil {
        result["visibility"] = visibility.(string)
        this.SetVisibility(location, visibility.(string))
    }

    return result, nil
}

// 更新
func (this *Local) Update(path string, contents string, conf interfaces.Config) (map[string]interface{}, error) {
    location := this.ApplyPathPrefix(path)

    out, createErr := os.Create(location)
    if createErr != nil {
        return nil, errors.New("执行函数 os.Create() 失败, 错误为:" + createErr.Error())
    }

    defer out.Close()

    _, writeErr := out.WriteString(contents)
    if writeErr != nil {
        return nil, errors.New("执行函数 os.WriteString() 失败, 错误为:" + writeErr.Error())
    }

    size, sizeErr := this.FileSize(location)
    if sizeErr != nil {
        return nil, errors.New("获取文件大小失败, 错误为:" + writeErr.Error())
    }

    result := map[string]interface{}{
        "type": "file",
        "size": size,
        "path": path,
        "contents": contents,
    }

    if visibility := conf.Get("visibility"); visibility != nil {
        result["visibility"] = visibility.(string)
        this.SetVisibility(location, visibility.(string))
    }

    return result, nil
}

// 更新
func (this *Local) UpdateStream(path string, stream io.Reader, config interfaces.Config) (map[string]interface{}, error) {
    return this.WriteStream(path, stream, config)
}

// 读取
func (this *Local) Read(path string) (map[string]interface{}, error) {
    location := this.ApplyPathPrefix(path)

    file, openErr := os.Open(location)
    if openErr != nil {
        return nil, errors.New("执行函数 os.Open() 失败, 错误为:" + openErr.Error())
    }
    defer file.Close()

    data, readAllErr := io.ReadAll(file)
    if readAllErr != nil {
        return nil, errors.New("执行函数 io.ReadAll() 失败, 错误为:" + readAllErr.Error())
    }

    contents := fmt.Sprintf("%s", data)

    return map[string]interface{}{
        "type": "file",
        "path": path,
        "contents": contents,
    }, nil
}

// 读取成文件流
// 打开文件需要手动关闭
func (this *Local) ReadStream(path string) (map[string]interface{}, error) {
    location := this.ApplyPathPrefix(path)

    stream, err := os.Open(location)
    if err != nil {
        return nil, errors.New("执行函数 os.Open() 失败, 错误为:" + err.Error())
    }

    // defer stream.Close()

    return map[string]interface{}{
        "type": "file",
        "path": path,
        "stream": stream,
    }, nil
}

// 重命名
func (this *Local) Rename(path string, newpath string) error {
    location := this.ApplyPathPrefix(path)
    destination := this.ApplyPathPrefix(newpath)
    parentDirectory := this.ApplyPathPrefix(filepath.Dir(newpath))
    this.EnsureDirectory(parentDirectory)

    err := os.Rename(location, destination)
    if err != nil {
        return errors.New("执行函数 os.Rename() 失败, 错误为:" + err.Error())
    }

    return nil
}

// 复制
func (this *Local) Copy(path string, newpath string) error {
    location := this.ApplyPathPrefix(path)
    destination := this.ApplyPathPrefix(newpath)
    this.EnsureDirectory(filepath.Dir(destination))

    locationStat, e := os.Stat(location)
    if e != nil {
        return e
    }

    if !locationStat.Mode().IsRegular() {
        return fmt.Errorf("%s 不是一个正常的文件", path)
    }

    src, openErr := os.Open(location)
    if openErr != nil {
        return openErr
    }
    defer src.Close()

    dsc, createErr := os.Create(destination)
    if createErr != nil {
        return createErr
    }
    defer dsc.Close()

    _, copyErr := io.Copy(dsc, src)
    if copyErr != nil {
        return errors.New("复制失败, 错误为:" + copyErr.Error())
    }

    return nil
}

// 删除
func (this *Local) Delete(path string) error {
    location := this.ApplyPathPrefix(path)

    if !this.IsFile(location) {
        return errors.New("文件删除失败, 当前文件不是文件类型")
    }

    if err := os.Remove(location); err != nil {
        return errors.New("文件删除失败, 错误为:" + err.Error())
    }

    return nil
}

// 删除文件夹
func (this *Local) DeleteDir(dirname string) error {
    location := this.ApplyPathPrefix(dirname)

    if !this.IsDir(location) {
        return errors.New("文件夹删除失败, 当前文件不是文件夹类型")
    }

    if err := os.RemoveAll(location); err != nil {
        return errors.New("文件夹删除失败, 错误为:" + err.Error())
    }

    return nil
}

// 创建文件夹
func (this *Local) CreateDir(dirname string, config interfaces.Config) (map[string]string, error) {
    location := this.ApplyPathPrefix(dirname)

    visibility := config.GetDefault("visibility", "public").(string)

    err := os.MkdirAll(location, this.FormatPerm(permissionMap["dir"][visibility]))
    if err != nil {
        return nil, errors.New("执行函数 os.MkdirAll() 失败, 错误为:" + err.Error())
    }

    if !this.IsDir(location) {
        return nil, errors.New("文件夹创建失败")
    }

    data := map[string]string{
        "path": dirname,
        "type": "dir",
    }

    return data, nil
}

// 列出内容
func (this *Local) ListContents(directory string, recursive ...bool) ([]map[string]interface{}, error) {
    location := this.ApplyPathPrefix(directory)

    if !this.IsDir(location) {
        return []map[string]interface{}{}, nil
    }

    var iterator []map[string]interface{}
    if len(recursive) > 0 && recursive[0] {
        iterator, _ = this.GetRecursiveDirectoryIterator(location)
    } else {
        iterator, _ = this.GetDirectoryIterator(location)
    }

    var result []map[string]interface{}
    for _, file := range iterator {
        path, _ := this.NormalizeFileInfo(file)

        result = append(result, path)
    }

    return result, nil
}

func (this *Local) GetMetadata(path string) (map[string]interface{}, error) {
    location := this.ApplyPathPrefix(path)

    info := this.FileInfo(location)

    return this.NormalizeFileInfo(info)
}

func (this *Local) GetSize(path string) (map[string]interface{}, error) {
    return this.GetMetadata(path)
}

func (this *Local) GetMimetype(path string) (map[string]interface{}, error) {
    location := this.ApplyPathPrefix(path)

    f, err := os.Open(location)
    if err != nil {
        return nil, err
    }
    defer f.Close()

    // 头部字节
    buffer := make([]byte, 32)
    if _, err := f.Read(buffer); err != nil {
        return nil, err
    }

    mimetype := http.DetectContentType(buffer)

    return map[string]interface{}{
        "path": path,
        "type": "file",
        "mimetype": mimetype,
    }, nil
}

func (this *Local) GetTimestamp(path string) (map[string]interface{}, error) {
    return this.GetMetadata(path)
}

// 设置文件的权限
func (this *Local) GetVisibility(path string) (map[string]string, error) {
    location := this.ApplyPathPrefix(path)

    pathType := "file"
    if !this.IsFile(location) {
        pathType = "dir"
    }

    permissions, _ := this.FileMode(location)

    for visibility, visibilityPermissions := range permissionMap[pathType] {
        if visibilityPermissions == permissions {
            return map[string]string{
                "path": path,
                "visibility": visibility,
            }, nil
        }
    }

    permission := fmt.Sprintf("%o", permissions)

    data := map[string]string{
        "path": path,
        "visibility": permission,
    }

    return data, nil
}

// 设置文件的权限
func (this *Local) SetVisibility(path string, visibility string) (map[string]string, error) {
    location := this.ApplyPathPrefix(path)

    pathType := "file"
    if !this.IsFile(location) {
        pathType = "dir"
    }

    if visibility != "private" {
        visibility = "public"
    }

    e := os.Chmod(location, this.FormatPerm(permissionMap[pathType][visibility]))
    if e != nil {
        return nil, errors.New("设置文件权限失败")
    }

    data := map[string]string{
        "path": path,
        "visibility": visibility,
    }

    return data, nil
}

// NormalizeFileInfo
func (this *Local) NormalizeFileInfo(file map[string]interface{}) (map[string]interface{}, error) {
    return this.MapFileInfo(file)
}

// 是否可读
func (this *Local) GuardAgainstUnreadableFileInfo(fp string) error {
    _, err := os.ReadFile(fp)
    if err != nil {
        return err
    }

    return nil
}

// 获取全部文件
func (this *Local) GetRecursiveDirectoryIterator(path string) ([]map[string]interface{}, error) {
    var files []map[string]interface{}
    err := filepath.Walk(path, func(wpath string, info os.FileInfo, err error) error {
        var fileType string
        if info.IsDir() {
            fileType = "dir"
        } else {
            fileType = "file"
        }

        files = append(files, map[string]interface{}{
            "type": fileType,
            "path": path,
            "filename": info.Name(),
            "pathname": path + "/" + info.Name(),
            "timestamp": info.ModTime().Unix(),
            "info": info,
        })
        return nil
    })

    if err != nil {
        return nil, errors.New("获取文件夹列表失败")
    }

    return files, nil
}

// 一级目录索引
func (this *Local) GetDirectoryIterator(path string) ([]map[string]interface{}, error) {
    fs, err := os.ReadDir(path)
    if err != nil {
        return []map[string]interface{}{}, err
    }

    sz := len(fs)
    if sz == 0 {
        return []map[string]interface{}{}, nil
    }

    ret := make([]map[string]interface{}, 0, sz)
    for i := 0; i < sz; i++ {
        info := fs[i]
        name := info.Name()
        // type := info.Type()
        stat, _ := info.Info()
        if name != "." && name != ".." {
            var fileType string
            if info.IsDir() {
                fileType = "dir"
            } else {
                fileType = "file"
            }

            ret = append(ret, map[string]interface{}{
                "type": fileType,
                "path": path,
                "filename": name,
                "pathname": path + "/" + name,
                "timestamp": stat.ModTime().Unix(),
                "info": info,
            })
        }
    }

    return ret, nil
}

func (this *Local) FileInfo(path string) map[string]interface{} {
    info, e := os.Stat(path)
    if e != nil {
        return nil
    }

    var fileType string
    if info.IsDir() {
        fileType = "dir"
    } else {
        fileType = "file"
    }

    return map[string]interface{}{
        "type": fileType,
        "path": filepath.Dir(path),
        "filename": info.Name(),
        "pathname": path,
        "timestamp": info.ModTime().Unix(),
        "info": info,
    }
}

func (this *Local) GetFilePath(file map[string]interface{}) string {
    location := file["pathname"].(string)
    path := this.RemovePathPrefix(location)
    return strings.Trim(strings.Replace(path, "\\", "/", -1), "/")
}

// 获取全部文件
func (this *Local) MapFileInfo(data map[string]interface{}) (map[string]interface{}, error) {
    normalized := map[string]interface{}{
        "type": data["type"],
        "path": this.GetFilePath(data),
        "timestamp": data["timestamp"],
    }

    if data["type"] == "file" {
        normalized["size"] = data["info"].(os.FileInfo).Size()
    }

    return normalized, nil
}

func (this *Local) IsFile(fp string) bool {
    return !this.IsDir(fp)
}

func (this *Local) IsDir(fp string) bool {
    f, e := os.Stat(fp)
    if e != nil {
        return false
    }

    return f.IsDir()
}

func (this *Local) FileSize(fp string) (int64, error) {
    f, e := os.Stat(fp)
    if e != nil {
        return 0, e
    }
    return f.Size(), nil
}

// 文件权限
func (this *Local) FileMode(fp string) (uint32, error) {
    f, e := os.Stat(fp)
    if e != nil {
        return 0, e
    }

    perm := f.Mode().Perm()

    return uint32(perm), nil
}

/**
 * 权限格式化
 */
func (this *Local) FormatPerm(i uint32) os.FileMode {
    // 八进制转成十进制
    // p, _ := strconv.ParseInt(strconv.Itoa(i), 8, 0)
    return os.FileMode(i)
}

// 软链接
func (this *Local) Symlink(target, link string) error {
    return os.Symlink(target, link)
}

// 读取链接
func (this *Local) Readlink(link string) (string, error) {
    return os.Readlink(link)
}

// 是否为软链接
func (this *Local) IsSymlink(m os.FileMode) bool {
    return m&os.ModeSymlink != 0
}
