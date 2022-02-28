package filesystem

import (
    "io"
    "os"
    "fmt"
    "time"
    "bufio"
    "errors"
    "strings"
    "net/http"
    "path/filepath"
    "crypto/md5"

    "github.com/h2non/filetype"
)

func New() *Filesystem {
    return &Filesystem{}
}

/**
 * 本地文件管理器
 *
 * @create 2022-2-27
 * @author deatil
 */
type Filesystem struct{}

// 判断
func (this *Filesystem) Exists(path string) bool {
    _, err := os.Stat(path)

    return err == nil || os.IsExist(err)
}

// 判断
func (this *Filesystem) Missing(path string) bool {
    return !this.Exists(path)
}

// 获取数据
func (this *Filesystem) Get(path string, lock bool) (string, error) {
    if lock {
        file, err := os.Open(path)
        if err != nil {
            return "", err
        }
        defer file.Close()

        data, err2 := io.ReadAll(file)
        if err2 != nil {
            return "", err2
        }

        return string(data), nil
    } else {
        return this.SharedGet(path)
    }
}

// 获取数据
func (this *Filesystem) SharedGet(path string) (string, error) {
    file, err := os.Open(path)
    if err != nil {
        return "", err
    }
    defer file.Close()

    data, err2 := io.ReadAll(file)
    if err2 != nil {
        return "", err2
    }

    return string(data), nil
}

// md5 值
func (this *Filesystem) Hash(path string) (string, error) {
    if info, err := os.Stat(path); err != nil {
        return "", err
    } else if info.IsDir() {
        return "", errors.New("不是文件无法计算")
    }

    openfile, err := os.Open(path)
    if err != nil {
        return "", err
    }
    defer openfile.Close()

    const bufferSize = 65536

    hash := md5.New()
    for buf, reader := make([]byte, bufferSize), bufio.NewReader(openfile); ; {
        n, err := reader.Read(buf)
        if err != nil {
            if err == io.EOF {
                break
            }
            return "", err
        }

        hash.Write(buf[:n])
    }

    checksum := fmt.Sprintf("%x", hash.Sum(nil))
    return checksum, nil
}

// 添加数据
func (this *Filesystem) Put(path string, contents string, lock bool) error {
    out, createErr := os.Create(path)
    if createErr != nil {
        return errors.New("执行函数 os.Create() 失败, 错误为:" + createErr.Error())
    }

    defer out.Close()

    _, writeErr := out.WriteString(contents)
    if writeErr != nil {
        return errors.New("执行函数 os.WriteString() 失败, 错误为:" + writeErr.Error())
    }

    return nil
}

// 替换
func (this *Filesystem) Replace(path string, contents string) error {
    f, err := os.CreateTemp("", "ReplaceTemp")
    if err != nil {
        return err
    }

    if _, err := f.Write([]byte(contents)); err != nil {
        return err
    }

    defer f.Close()

    return os.Rename(f.Name(), path)
}

// 替换
func (this *Filesystem) ReplaceInFile(search string, replace string, path string) error {
    data, _ := this.SharedGet(path)
    newData := strings.Replace(data, search, replace, -1)

    return this.Put(path, newData, false)
}

// 文件头添加
func (this *Filesystem) Prepend(path string, data string) error {
    if this.Exists(path) {
        newData, _ := this.Get(path, false)

        return this.Put(path, data + newData, false)
    }

    return this.Put(path, data, false)
}

// 尾部添加
func (this *Filesystem) Append(path string, data string) error {
    if this.Exists(path) {
        newData, _ := this.Get(path, false)

        return this.Put(path, newData + data, false)
    }

    return this.Put(path, data, false)
}

// 设置权限
func (this *Filesystem) Chmod(path string, mode uint32) error {
    e := os.Chmod(path, os.FileMode(mode))
    if e != nil {
        return errors.New("设置文件权限失败")
    }

    return nil
}

// 获取权限
func (this *Filesystem) Perm(path string) (uint32, error) {
    f, err := os.Stat(path)
    if err != nil {
        return 0, err
    }

    perm := f.Mode().Perm()

    return uint32(perm), nil
}

// 删除
func (this *Filesystem) Delete(path string) error {
    return os.Remove(path)
}

// get
func (this *Filesystem) Move(path string, target string) error {
    return os.Rename(path, target)
}

// 文件复制
func (this *Filesystem) Copy(path string, target string) error {
    srcFile, err := os.Open(path)

    if err != nil {
        return err
    }
    defer srcFile.Close()

    // 文件目录
    destPath, _ := filepath.Split(target)

    // 目录不存在时
    if !this.Exists(destPath) {
        // 创建目录
        err = os.MkdirAll(destPath, os.ModePerm)
        if err != nil {
            return err
        }
    }

    dstFile, err := os.Create(target)
    if err != nil {
        return err
    }
    defer dstFile.Close()

    _, err2 := io.Copy(dstFile, srcFile)
    if err2 != nil {
        return err2
    }

    return nil
}

// 设置软链接
func (this *Filesystem) Link(target string, link string) error {
    return os.Symlink(target, link)
}

// 相对链接
func (this *Filesystem) RelativeLink(basepath string, targpath string) error {
    return nil
}

// 文件名称
func (this *Filesystem) Name(path string) string {
    filenameAll := filepath.Base(path)
    fileSuffix := filepath.Ext(path)
    filePrefix := filenameAll[0:len(filenameAll) - len(fileSuffix)]

    return filePrefix
}

// 文件目录名称
func (this *Filesystem) Basename(path string) string {
    return filepath.Base(path)
}

// 获取文件夹名称
func (this *Filesystem) Dirname(path string) string {
    return filepath.Dir(path)
}

// get
func (this *Filesystem) Extension(path string) string {
    return filepath.Ext(path)[1:]
}

// get
func (this *Filesystem) GuessExtension(path string) string {
    file, err := os.Open(path)
    if err != nil {
        return ""
    }
    defer file.Close()

    buf, err2 := io.ReadAll(file)
    if err2 != nil {
        return "Unknown"
    }

    kind, _ := filetype.Match(buf)
    if kind == filetype.Unknown {
        return "Unknown"
    }

    return kind.Extension
}

// get
func (this *Filesystem) Type(path string) string {
    file, err := os.Open(path)
    if err != nil {
        return ""
    }
    defer file.Close()

    buf, err2 := io.ReadAll(file)
    if err2 != nil {
        return "Unknown"
    }

    kind, _ := filetype.Match(buf)
    if kind == filetype.Unknown {
        return "Unknown"
    }

    return kind.MIME.Type
}

// MimeType
func (this *Filesystem) MimeType(path string) string {
    f, err := os.Open(path)
    if err != nil {
        return "Unknown"
    }
    defer f.Close()

    // 头部字节
    buffer := make([]byte, 32)
    if _, err := f.Read(buffer); err != nil {
        return "Unknown"
    }

    mimetype := http.DetectContentType(buffer)

    return mimetype
}

// 文件大小
func (this *Filesystem) Size(path string) int64 {
    f, err := os.Stat(path)
    if err != nil {
        return 0
    }

    return f.Size()
}

// 文件最后更新时间
func (this *Filesystem) LastModified(path string) int64 {
    f, err := os.Stat(path)
    if err != nil {
        return 0
    }

    return f.ModTime().Unix()
}

// 是否为文件夹
func (this *Filesystem) IsDirectory(path string) bool {
    fd, err := os.Stat(path)
    if err != nil {
        return false
    }

    fm := fd.Mode()
    return fm.IsDir()
}

// 是否可读
func (this *Filesystem) IsReadable(path string) bool {
    _, err := os.ReadFile(path)
    if err != nil {
        return false
    }

    return true
}

// get
func (this *Filesystem) IsWritable(path string) bool {
    f, e := os.Stat(path)
    if e != nil {
        return false
    }

    perm := f.Mode().Perm()

    return len(strings.Split(perm.String(), "w")) == 4
}

// 是否是文件
func (this *Filesystem) IsFile(path string) bool {
    _, err := os.Stat(path)
    if err != nil && os.IsNotExist(err) {
        return false
    }

    return true
}

// 查询
func (this *Filesystem) Glob(pattern string) ([]string, error) {
    return filepath.Glob(pattern)
}

// 列出文件
func (this *Filesystem) Files(directory string) ([]string, error) {
    if !this.Exists(directory) {
        return []string{}, nil
    }

    fs, err := os.ReadDir(directory)
    if err != nil {
        return []string{}, err
    }

    sz := len(fs)
    if sz == 0 {
        return []string{}, nil
    }

    ret := make([]string, 0, sz)
    for i := 0; i < sz; i++ {
        if !fs[i].IsDir() {
            ret = append(ret, fs[i].Name())
        }
    }

    return ret, nil
}

// 全部文件
func (this *Filesystem) AllFiles(directory string) ([]string, error) {
    if !this.Exists(directory) {
        return []string{}, nil
    }

    ret := make([]string, 0)

    err := filepath.Walk(directory, func(path string, f os.FileInfo, err error) error {
        if f == nil {
            return err
        }

        if !f.IsDir() {
            ret = append(ret, path)
        }

        return nil
    })

    return ret, err
}

// 列出文件夹
func (this *Filesystem) Directories(directory string) ([]string, error) {
    if !this.Exists(directory) {
        return []string{}, nil
    }

    fs, err := os.ReadDir(directory)
    if err != nil {
        return []string{}, err
    }

    sz := len(fs)
    if sz == 0 {
        return []string{}, nil
    }

    ret := make([]string, 0, sz)
    for i := 0; i < sz; i++ {
        if fs[i].IsDir() {
            name := fs[i].Name()
            if name != "." && name != ".." {
                ret = append(ret, name)
            }
        }
    }

    return ret, nil
}

// 创建文件夹
func (this *Filesystem) EnsureDirectoryExists(
    directory string,
    mode uint32,
    recursive bool,
) error {
    err := this.MakeDirectory(directory, mode, recursive)
    if err != nil {
        return err
    }

    checkFile := fmt.Sprintf("%s/rw.%d", directory, time.Now().UnixNano())

    fd, err := os.Create(checkFile)
    if err != nil {
        if os.IsPermission(err) {
            return fmt.Errorf("%s 没有读写权限", directory)
        }

        return err
    }

    if err := fd.Close(); err != nil {
        return fmt.Errorf("关闭失败: %s", err)
    }

    if err := os.Remove(checkFile); err != nil {
        return fmt.Errorf("删除失败: %s", err)
    }

    return nil
}

// 创建文件夹
func (this *Filesystem) MakeDirectory(directory string, mode uint32, recursive bool) error {
    if recursive {
        return os.MkdirAll(directory, os.FileMode(mode))
    } else {
        return os.Mkdir(directory, os.FileMode(mode))
    }
}

// 移动文件夹
func (this *Filesystem) MoveDirectory(
    from string,
    to string,
    overwrite bool,
) error {
    if overwrite && this.IsDirectory(to) {
        err := this.DeleteDirectory(to, false)
        if err != nil {
            return errors.New("覆盖旧文件操作失败")
        }
    }

    return os.Rename(from, to)
}

// 复制文件夹
func (this *Filesystem) CopyDirectory(directory string, destination string) error {
    // 检测目录正确性
    if srcInfo, err := os.Stat(directory); err != nil {
        return err
    } else {
        if !srcInfo.IsDir() {
            e := errors.New("原始目录不是一个正确的目录！")
            return e
        }
    }

    if destInfo, err := os.Stat(destination); err != nil {
        return err
    } else {
        if !destInfo.IsDir() {
            e := errors.New("目标目录不是一个正确的目录！")
            return e
        }
    }

    // 统一路径
    srcPath, _ := filepath.Abs(directory)
    destPath, _ := filepath.Abs(destination)

    err := filepath.Walk(srcPath, func(path string, f os.FileInfo, err error) error {
        if f == nil {
            return err
        }

        if !f.IsDir() {
            // 重设为新路径
            destNewPath := strings.Replace(path, srcPath, destPath, -1)

            this.Copy(path, destNewPath)
        }

        return nil
    })

    return err
}

// 删除文件夹
func (this *Filesystem) DeleteDirectory(directory string, preserve bool) error {
    if !this.IsDirectory(directory) {
        return errors.New("文件夹删除失败, 当前文件不是文件夹类型")
    }

    if err := os.RemoveAll(directory); err != nil {
        return errors.New("文件夹删除失败, 错误为:" + err.Error())
    }

    if !preserve {
        this.Delete(directory)
    }

    return nil
}

// 删除文件夹
func (this *Filesystem) DeleteDirectories(directory string) bool {
    allDirectories, _ := this.Directories(directory)

    if len(allDirectories) > 0 {
        for _, directoryName := range allDirectories {
            this.DeleteDirectory(directoryName, false)
        }

        return true
    }

    return false
}

// 清空文件夹
func (this *Filesystem) CleanDirectory(directory string) error {
    return this.DeleteDirectory(directory, true)
}

