package local

import (
    "io"
    "os"
    "fmt"
    "errors"
    "strings"
    "net/http"
    "path/filepath"

    "github.com/deatil/go-filesystem/filesystem/adapter"
    "github.com/deatil/go-filesystem/filesystem/interfaces"
)

// 权限列表
var permissionMap map[string]map[string]uint32 = map[string]map[string]uint32{
    "file": {
        "public":  0644,
        "private": 0600,
    },
    "dir": {
        "public":  0755,
        "private": 0700,
    },
}

/**
 * 本地文件适配器 / Local adapter
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

// 本地文件适配器
func New(root string) *Local {
    local := &Local{}

    local.EnsureDirectory(root)
    local.SetPathPrefix(root)

    return local
}

// 确认文件夹
func (this *Local) EnsureDirectory(root string) error {
    err := os.MkdirAll(root, this.formatPerm(permissionMap["dir"]["public"]))
    if err != nil {
        return errors.New("go-filesystem: exec os.MkdirAll() fail, error: " + err.Error())
    }

    if !this.isFile(root) {
        return errors.New("go-filesystem: create dir fail" )
    }

    return nil
}

// 判断是否存在
func (this *Local) Has(path string) bool {
    location := this.ApplyPathPrefix(path)

    _, err := os.Stat(location)
    return err == nil || os.IsExist(err)
}

// 上传
func (this *Local) Write(path string, contents []byte, conf interfaces.Config) (map[string]any, error) {
    location := this.ApplyPathPrefix(path)
    this.EnsureDirectory(filepath.Dir(location))

    out, createErr := os.Create(location)
    if createErr != nil {
        return nil, errors.New("go-filesystem: exec os.Create() fail, error: " + createErr.Error())
    }

    defer out.Close()

    _, writeErr := out.Write(contents)
    if writeErr != nil {
        return nil, errors.New("go-filesystem: exec os.Write() fail, error: " + writeErr.Error())
    }

    size, sizeErr := this.fileSize(location)
    if sizeErr != nil {
        return nil, errors.New("go-filesystem: get file size fail, error: " + writeErr.Error())
    }

    result := map[string]any{
        "type":     "file",
        "size":     size,
        "path":     path,
        "contents": contents,
    }

    if visibility := conf.Get("visibility"); visibility != nil {
        result["visibility"] = visibility.(string)
        this.SetVisibility(location, visibility.(string))
    }

    return result, nil
}

// 上传 Stream 文件类型
func (this *Local) WriteStream(path string, stream io.Reader, conf interfaces.Config) (map[string]any, error) {
    location := this.ApplyPathPrefix(path)
    this.EnsureDirectory(filepath.Dir(location))

    newFile, createErr := os.Create(location)
    if createErr != nil {
        return nil, errors.New("go-filesystem: exec os.Create() fail, error: " + createErr.Error())
    }

    defer newFile.Close()

    _, copyErr := io.Copy(newFile, stream)
    if copyErr != nil {
        return nil, errors.New("go-filesystem: write stream fail, error: " + copyErr.Error())
    }

    result := map[string]any{
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
func (this *Local) Update(path string, contents []byte, conf interfaces.Config) (map[string]any, error) {
    location := this.ApplyPathPrefix(path)

    out, createErr := os.Create(location)
    if createErr != nil {
        return nil, errors.New("go-filesystem: exec os.Create() fail, error: " + createErr.Error())
    }

    defer out.Close()

    _, writeErr := out.Write(contents)
    if writeErr != nil {
        return nil, errors.New("go-filesystem: exec os.Write() fail, error: " + writeErr.Error())
    }

    size, sizeErr := this.fileSize(location)
    if sizeErr != nil {
        return nil, errors.New("go-filesystem: get file size fail, error: " + writeErr.Error())
    }

    result := map[string]any{
        "type":     "file",
        "size":     size,
        "path":     path,
        "contents": contents,
    }

    if visibility := conf.Get("visibility"); visibility != nil {
        result["visibility"] = visibility.(string)
        this.SetVisibility(location, visibility.(string))
    }

    return result, nil
}

// 更新
func (this *Local) UpdateStream(path string, stream io.Reader, config interfaces.Config) (map[string]any, error) {
    return this.WriteStream(path, stream, config)
}

// 读取
func (this *Local) Read(path string) (map[string]any, error) {
    location := this.ApplyPathPrefix(path)

    file, err := os.Open(location)
    if err != nil {
        return nil, errors.New("go-filesystem: exec os.Open() fail, error: " + err.Error())
    }
    defer file.Close()

    contents, err := io.ReadAll(file)
    if err != nil {
        return nil, errors.New("go-filesystem: exec io.ReadAll() fail, error: " + err.Error())
    }

    return map[string]any{
        "type":     "file",
        "path":     path,
        "contents": contents,
    }, nil
}

// 读取成文件流
// 打开文件需要手动关闭
func (this *Local) ReadStream(path string) (map[string]any, error) {
    location := this.ApplyPathPrefix(path)

    stream, err := os.Open(location)
    if err != nil {
        return nil, errors.New("go-filesystem: exec os.Open() fail, error: " + err.Error())
    }

    // defer stream.Close()

    return map[string]any{
        "type":   "file",
        "path":   path,
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
        return errors.New("go-filesystem: exec os.Rename() fail, error: " + err.Error())
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
        return fmt.Errorf("go-filesystem: %s not right file", path)
    }

    src, err := os.Open(location)
    if err != nil {
        return err
    }
    defer src.Close()

    dst, err := os.Create(destination)
    if err != nil {
        return err
    }
    defer dst.Close()

    _, err = io.Copy(dst, src)
    if err != nil {
        return errors.New("go-filesystem: copy fail, error: " + err.Error())
    }

    return nil
}

// 删除
func (this *Local) Delete(path string) error {
    location := this.ApplyPathPrefix(path)

    if !this.isFile(location) {
        return errors.New("go-filesystem: file delete fail, not file type")
    }

    if err := os.Remove(location); err != nil {
        return errors.New("go-filesystem: file delete fail, error: " + err.Error())
    }

    return nil
}

// 删除文件夹
func (this *Local) DeleteDir(dirname string) error {
    location := this.ApplyPathPrefix(dirname)

    if !this.isDir(location) {
        return errors.New("go-filesystem: file delete fail, not file type")
    }

    if err := os.RemoveAll(location); err != nil {
        return errors.New("go-filesystem: file delete fail, error: " + err.Error())
    }

    return nil
}

// 创建文件夹
func (this *Local) CreateDir(dirname string, config interfaces.Config) (map[string]string, error) {
    location := this.ApplyPathPrefix(dirname)

    visibility := config.Get("visibility", "public").(string)

    err := os.MkdirAll(location, this.formatPerm(permissionMap["dir"][visibility]))
    if err != nil {
        return nil, errors.New("go-filesystem: exec os.MkdirAll() fail, error: " + err.Error())
    }

    if !this.isDir(location) {
        return nil, errors.New("go-filesystem: make dir fail")
    }

    data := map[string]string{
        "path": dirname,
        "type": "dir",
    }

    return data, nil
}

// 列出内容
func (this *Local) ListContents(directory string, recursive ...bool) ([]map[string]any, error) {
    location := this.ApplyPathPrefix(directory)

    if !this.isDir(location) {
        return []map[string]any{}, nil
    }

    var iterator []map[string]any
    if len(recursive) > 0 && recursive[0] {
        iterator, _ = this.getRecursiveDirectoryIterator(location)
    } else {
        iterator, _ = this.getDirectoryIterator(location)
    }

    var result []map[string]any
    for _, file := range iterator {
        path, _ := this.normalizeFileInfo(file)

        result = append(result, path)
    }

    return result, nil
}

func (this *Local) GetMetadata(path string) (map[string]any, error) {
    location := this.ApplyPathPrefix(path)

    info := this.fileInfo(location)

    return this.normalizeFileInfo(info)
}

func (this *Local) GetSize(path string) (map[string]any, error) {
    return this.GetMetadata(path)
}

func (this *Local) GetMimetype(path string) (map[string]any, error) {
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

    return map[string]any{
        "path":     path,
        "type":     "file",
        "mimetype": mimetype,
    }, nil
}

func (this *Local) GetTimestamp(path string) (map[string]any, error) {
    return this.GetMetadata(path)
}

// 设置文件的权限
func (this *Local) GetVisibility(path string) (map[string]string, error) {
    location := this.ApplyPathPrefix(path)

    pathType := "file"
    if !this.isFile(location) {
        pathType = "dir"
    }

    permissions, _ := this.fileMode(location)

    for visibility, visibilityPermissions := range permissionMap[pathType] {
        if visibilityPermissions == permissions {
            return map[string]string{
                "path":       path,
                "visibility": visibility,
            }, nil
        }
    }

    permission := fmt.Sprintf("%o", permissions)

    data := map[string]string{
        "path":       path,
        "visibility": permission,
    }

    return data, nil
}

// 设置文件的权限
func (this *Local) SetVisibility(path string, visibility string) (map[string]string, error) {
    location := this.ApplyPathPrefix(path)

    pathType := "file"
    if !this.isFile(location) {
        pathType = "dir"
    }

    if visibility != "private" {
        visibility = "public"
    }

    e := os.Chmod(location, this.formatPerm(permissionMap[pathType][visibility]))
    if e != nil {
        return nil, errors.New("go-filesystem: set permission fail")
    }

    data := map[string]string{
        "path":       path,
        "visibility": visibility,
    }

    return data, nil
}

// normalizeFileInfo
func (this *Local) normalizeFileInfo(file map[string]any) (map[string]any, error) {
    return this.mapFileInfo(file)
}

// 获取全部文件
func (this *Local) getRecursiveDirectoryIterator(path string) ([]map[string]any, error) {
    var files []map[string]any
    err := filepath.Walk(path, func(wpath string, info os.FileInfo, err error) error {
        var fileType string
        if info.IsDir() {
            fileType = "dir"
        } else {
            fileType = "file"
        }

        files = append(files, map[string]any{
            "type":      fileType,
            "path":      path,
            "filename":  info.Name(),
            "pathname":  path + "/" + info.Name(),
            "timestamp": info.ModTime().Unix(),
            "info":      info,
        })
        return nil
    })

    if err != nil {
        return nil, errors.New("go-filesystem: get dir list fail")
    }

    return files, nil
}

// 一级目录索引
// dir index
func (this *Local) getDirectoryIterator(path string) ([]map[string]any, error) {
    fs, err := os.ReadDir(path)
    if err != nil {
        return []map[string]any{}, err
    }

    sz := len(fs)
    if sz == 0 {
        return []map[string]any{}, nil
    }

    ret := make([]map[string]any, 0, sz)
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

            ret = append(ret, map[string]any{
                "type":      fileType,
                "path":      path,
                "filename":  name,
                "pathname":  path + "/" + name,
                "timestamp": stat.ModTime().Unix(),
                "info":      info,
            })
        }
    }

    return ret, nil
}

func (this *Local) fileInfo(path string) map[string]any {
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

    return map[string]any{
        "type":      fileType,
        "path":      filepath.Dir(path),
        "filename":  info.Name(),
        "pathname":  path,
        "timestamp": info.ModTime().Unix(),
        "info":      info,
    }
}

func (this *Local) getFilePath(file map[string]any) string {
    location := file["pathname"].(string)
    path := this.RemovePathPrefix(location)
    return strings.Trim(strings.Replace(path, "\\", "/", -1), "/")
}

// 获取全部文件
// get all file
func (this *Local) mapFileInfo(data map[string]any) (map[string]any, error) {
    normalized := map[string]any{
        "type":      data["type"],
        "path":      this.getFilePath(data),
        "timestamp": data["timestamp"],
    }

    if data["type"] == "file" {
        switch infoType := data["info"].(type) {
            case os.DirEntry:
                info, err := infoType.Info()
                if err == nil {
                    normalized["size"] = info.Size()
                } else {
                    normalized["size"] = 0
                }
            case os.FileInfo:
                normalized["size"] = infoType.Size()
        }
    }

    return normalized, nil
}

func (this *Local) isFile(fp string) bool {
    return !this.isDir(fp)
}

func (this *Local) isDir(fp string) bool {
    f, e := os.Stat(fp)
    if e != nil {
        return false
    }

    return f.IsDir()
}

func (this *Local) fileSize(fp string) (int64, error) {
    f, e := os.Stat(fp)
    if e != nil {
        return 0, e
    }

    return f.Size(), nil
}

// 文件权限
// return File Mode
func (this *Local) fileMode(fp string) (uint32, error) {
    f, e := os.Stat(fp)
    if e != nil {
        return 0, e
    }

    perm := f.Mode().Perm()

    return uint32(perm), nil
}

// 权限格式化
// Format Perm
func (this *Local) formatPerm(i uint32) os.FileMode {
    // 八进制转成十进制
    // p, _ := strconv.ParseInt(strconv.Itoa(i), 8, 0)
    return os.FileMode(i)
}
