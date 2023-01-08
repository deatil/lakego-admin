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
    "crypto/md5"
    "path/filepath"

    "github.com/h2non/filetype"
)

// 文件信息
type FileInfo = os.FileInfo

// 文件权限
type FileMode = os.FileMode

const (
    ModeDir        = os.ModeDir        // d: is a directory
    ModeAppend     = os.ModeAppend     // a: append-only
    ModeExclusive  = os.ModeExclusive  // l: exclusive use
    ModeTemporary  = os.ModeTemporary  // T: temporary file; Plan 9 only
    ModeSymlink    = os.ModeSymlink    // L: symbolic link
    ModeDevice     = os.ModeDevice     // D: device file
    ModeNamedPipe  = os.ModeNamedPipe  // p: named pipe (FIFO)
    ModeSocket     = os.ModeSocket     // S: Unix domain socket
    ModeSetuid     = os.ModeSetuid     // u: setuid
    ModeSetgid     = os.ModeSetgid     // g: setgid
    ModeCharDevice = os.ModeCharDevice // c: Unix character device, when ModeDevice is set
    ModeSticky     = os.ModeSticky     // t: sticky
    ModeIrregular  = os.ModeIrregular  // ?: non-regular file; nothing else is known about this file

    // Mask for the type bits. For regular files, none will be set.
    ModeType = os.ModeType

    // Unix permission bits, 0o777
    ModePerm = os.ModePerm
)

// Flags 列表
const (
    // 只读模式
    O_RDONLY int = os.O_RDONLY
    // 只写模式
    O_WRONLY int = os.O_WRONLY
    // 可读可写
    O_RDWR   int = os.O_RDWR
    // 追加内容
    O_APPEND int = os.O_APPEND
    // 创建文件，如果文件不存在
    O_CREATE int = os.O_CREATE
    // 与创建文件一同使用，文件必须存在
    O_EXCL   int = os.O_EXCL
    // 打开一个同步的文件流
    O_SYNC   int = os.O_SYNC
    // 如果可能，打开时缩短文件
    O_TRUNC  int = os.O_TRUNC
)

// 默认
var defaultFilesystem *Filesystem

// 初始化
func init() {
    defaultFilesystem = New()
}

// 构造函数
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

// 创建
func (this *Filesystem) Create(name string) (*os.File, error) {
    return os.Create(name)
}

// 创建
func Create(name string) (*os.File, error) {
    return defaultFilesystem.Create(name)
}

// 关闭
func (this *Filesystem) Close(fd *os.File) error {
    return fd.Close()
}

// 关闭
func Close(fd *os.File) error {
    return defaultFilesystem.Close(fd)
}

// 判断
func (this *Filesystem) Exists(path string) bool {
    _, err := os.Stat(path)

    return err == nil || os.IsExist(err)
}

// 判断
func Exists(path string) bool {
    return defaultFilesystem.Exists(path)
}

// 判断
func (this *Filesystem) Missing(path string) bool {
    return !this.Exists(path)
}

// 判断
func Missing(path string) bool {
    return defaultFilesystem.Missing(path)
}

// 获取数据
func (this *Filesystem) Get(path string, lock ...bool) (string, error) {
    if len(lock) > 0 && lock[0] {
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
func Get(path string, lock ...bool) (string, error) {
    return defaultFilesystem.Get(path, lock...)
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

// 获取数据
func SharedGet(path string) (string, error) {
    return defaultFilesystem.SharedGet(path)
}

// 行读取
func (this *Filesystem) Lines(path string) ([]string, error) {
    openFile, err := os.Open(path)
    if err != nil {
        return []string{}, err
    }

    defer openFile.Close()

    reader := bufio.NewReader(openFile)

    data := make([]string, 0)
    for {
        line, err := reader.ReadString('\n')
        data = append(data, line)

        if err != nil {
            if err == io.EOF {
                break
            }

            return data, err
        }
    }

    return data, err
}

// 行读取
func Lines(path string) ([]string, error) {
    return defaultFilesystem.Lines(path)
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

// md5 值
func Hash(path string) (string, error) {
    return defaultFilesystem.Hash(path)
}

// 添加数据
func (this *Filesystem) Put(path string, contents string, lock ...bool) error {
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

// 添加数据
func Put(path string, contents string, lock ...bool) error {
    return defaultFilesystem.Put(path, contents, lock...)
}

// 替换
func (this *Filesystem) Replace(path string, contents string) error {
    f, err := os.CreateTemp("", "ReplaceTemp")
    if err != nil {
        return err
    }

    if _, err := f.Write([]byte(contents)); err != nil {
        f.Close()
        return err
    }
    f.Close()

    srcFile, err := os.Open(f.Name())
    if err != nil {
        return err
    }

    desFile, err := os.Create(path)
    if err != nil {
        return err
    }

    _, err2 := io.Copy(desFile, srcFile)
    if err2 != nil {
        return err2
    }

    defer func() {
        srcFile.Close()
        desFile.Close()
        os.Remove(f.Name())
    }()

    return nil
}

// 替换
func Replace(path string, contents string) error {
    return defaultFilesystem.Replace(path, contents)
}

// 替换
func (this *Filesystem) ReplaceInFile(search string, replace string, path string) error {
    data, _ := this.SharedGet(path)
    newData := strings.Replace(data, search, replace, -1)

    return this.Put(path, newData, false)
}

// 替换
func ReplaceInFile(search string, replace string, path string) error {
    return defaultFilesystem.ReplaceInFile(search, replace, path)
}

// 文件头添加
func (this *Filesystem) Prepend(path string, data string) error {
    if this.Exists(path) {
        newData, _ := this.Get(path, false)

        return this.Put(path, data + newData, false)
    }

    return this.Put(path, data, false)
}

// 文件头添加
func Prepend(path string, data string) error {
    return defaultFilesystem.Prepend(path, data)
}

// 尾部添加
func (this *Filesystem) Append(path string, data string) error {
    if this.Exists(path) {
        newData, _ := this.Get(path, false)

        return this.Put(path, newData + data, false)
    }

    return this.Put(path, data, false)
}

// 尾部添加
func Append(path string, data string) error {
    return defaultFilesystem.Append(path, data)
}

// 设置权限
func (this *Filesystem) Chmod(path string, mode uint32) error {
    e := os.Chmod(path, os.FileMode(mode))
    if e != nil {
        return errors.New("设置文件权限失败")
    }

    return nil
}

// 设置权限
func Chmod(path string, mode uint32) error {
    return defaultFilesystem.Chmod(path, mode)
}

// 创建文件
func (this *Filesystem) Touch(filename string) error {
    fd, err := os.OpenFile(filename, os.O_RDONLY|os.O_CREATE, 0666)
    if err != nil {
        return err
    }

    fd.Close()
    return nil
}

// 创建文件
func Touch(filename string) error {
    return defaultFilesystem.Touch(filename)
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

// 获取权限
func Perm(path string) (uint32, error) {
    return defaultFilesystem.Perm(path)
}

// 权限数字转为字符
func (this *Filesystem) PermIntString(path string) (string, error) {
    perm, err := this.Perm(path)
    if err != nil {
        return "", err
    }

    return fmt.Sprintf("%o", perm), nil
}

// 权限数字转为字符
func PermIntString(path string) (string, error) {
    return defaultFilesystem.PermIntString(path)
}

// 获取权限 - 字符
func (this *Filesystem) PermString(path string) (string, error) {
    f, err := os.Stat(path)
    if err != nil {
        return "", err
    }

    perm := f.Mode().Perm()

    return perm.String(), nil
}

// 获取权限 - 字符
func PermString(path string) (string, error) {
    return defaultFilesystem.PermString(path)
}

// 删除
func (this *Filesystem) Delete(path string) error {
    return os.Remove(path)
}

// 删除
func Delete(path string) error {
    return defaultFilesystem.Delete(path)
}

// 移动
func (this *Filesystem) Move(path string, target string) error {
    return os.Rename(path, target)
}

// 移动
func Move(path string, target string) error {
    return defaultFilesystem.Move(path, target)
}

// 重命名
func (this *Filesystem) Rename(path string, target string) error {
    return os.Rename(path, target)
}

// 重命名
func Rename(path string, target string) error {
    return defaultFilesystem.Rename(path, target)
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

// 文件复制
func Copy(path string, target string) error {
    return defaultFilesystem.Copy(path, target)
}

// 设置软链接
func (this *Filesystem) Link(target string, link string) error {
    return os.Symlink(target, link)
}

// 设置软链接
func Link(target string, link string) error {
    return defaultFilesystem.Link(target, link)
}

// 读取软链接于原始路径的相对地址
func (this *Filesystem) Readlink(path string) (string, error) {
    return os.Readlink(path)
}

// 读取软链接于原始路径的相对地址
func Readlink(path string) (string, error) {
    return defaultFilesystem.Readlink(path)
}

// 读取软链接的原始地址
func (this *Filesystem) EvalSymlinks(path string) (string, error) {
    return filepath.EvalSymlinks(path)
}

// 读取软链接的原始地址
func EvalSymlinks(path string) (string, error) {
    return defaultFilesystem.EvalSymlinks(path)
}

// 是否为软链接
func (this *Filesystem) IsSymlink(m os.FileMode) bool {
    return m&os.ModeSymlink != 0
}

// 是否为软链接
func IsSymlink(m os.FileMode) bool {
    return defaultFilesystem.IsSymlink(m)
}

// 返回路径是否是一个绝对路径
func (this *Filesystem) IsAbs(path string) bool {
    return filepath.IsAbs(path)
}

// 返回路径是否是一个绝对路径
func IsAbs(path string) bool {
    return defaultFilesystem.IsAbs(path)
}

// 返回 path 代表的绝对路径
func (this *Filesystem) Abs(path string) (string, error) {
    return filepath.Abs(path)
}

// 返回 path 代表的绝对路径
func Abs(path string) (string, error) {
    return defaultFilesystem.Abs(path)
}

// 返回一个相对路径
func (this *Filesystem) Rel(basepath, targpath string) (string, error) {
    return filepath.Rel(basepath, targpath)
}

// 返回一个相对路径
func Rel(basepath, targpath string) (string, error) {
    return defaultFilesystem.Rel(basepath, targpath)
}

// 绝对路径
func (this *Filesystem) Realpath(path string) (string, error) {
    return filepath.Abs(path)
}

// 绝对路径
func Realpath(path string) (string, error) {
    return defaultFilesystem.Realpath(path)
}

// 规整化路径
func (this *Filesystem) Clean(path string) string {
    return filepath.Clean(path)
}

// 规整化路径
func Clean(path string) string {
    return defaultFilesystem.Clean(path)
}

// 函数根据最后一个路径分隔符将路径 path 分隔为目录和文件名两部分（dir 和 file）
func (this *Filesystem) Split(path string) (string, string) {
    return filepath.Split(path)
}

// 函数根据最后一个路径分隔符将路径 path 分隔为目录和文件名两部分（dir 和 file）
func Split(path string) (string, string) {
    return defaultFilesystem.Split(path)
}

// 分割 PATH 或 GOPATH 之类的环境变量
func (this *Filesystem) SplitList(path string) []string {
    return filepath.SplitList(path)
}

// 分割 PATH 或 GOPATH 之类的环境变量
func SplitList(path string) []string {
    return defaultFilesystem.SplitList(path)
}

// 将 path 中的 ‘/’ 转换为系统相关的路径分隔符
func (this *Filesystem) FromSlash(s string) string {
    return filepath.FromSlash(s)
}

// 将 path 中的 ‘/’ 转换为系统相关的路径分隔符
func FromSlash(s string) string {
    return defaultFilesystem.FromSlash(s)
}

// 将 path 中平台相关的路径分隔符转换为 ‘/’
func (this *Filesystem) ToSlash(s string) string {
    return filepath.ToSlash(s)
}

// 将 path 中平台相关的路径分隔符转换为 ‘/’
func ToSlash(s string) string {
    return defaultFilesystem.ToSlash(s)
}

// 函数可以将任意数量的路径元素放入一个单一路径里，会根据需要添加路径分隔符
func (this *Filesystem) Join(elem ...string) string {
    return filepath.Join(elem...)
}

// 将函数可以将任意数量的路径元素放入一个单一路径里，会根据需要添加路径分隔符
func Join(elem ...string) string {
    return defaultFilesystem.Join(elem...)
}

// 文件名称
func (this *Filesystem) Name(path string) string {
    filenameAll := filepath.Base(path)
    fileSuffix := filepath.Ext(path)
    filePrefix := filenameAll[0:len(filenameAll) - len(fileSuffix)]

    return filePrefix
}

// 文件名称
func Name(path string) string {
    return defaultFilesystem.Name(path)
}

// 文件目录名称
func (this *Filesystem) Basename(path string) string {
    return filepath.Base(path)
}

// 文件目录名称
func Basename(path string) string {
    return defaultFilesystem.Basename(path)
}

// 获取文件夹名称
func (this *Filesystem) Dirname(path string) string {
    return filepath.Dir(path)
}

// 获取文件夹名称
func Dirname(path string) string {
    return defaultFilesystem.Dirname(path)
}

// 后缀
func (this *Filesystem) Extension(path string) string {
    ext := filepath.Ext(path)

    return strings.TrimPrefix(ext, ".")
}

// 后缀
func Extension(path string) string {
    return defaultFilesystem.Extension(path)
}

// 后缀
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

// 后缀
func GuessExtension(path string) string {
    return defaultFilesystem.GuessExtension(path)
}

// 类型，大类
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

// 类型，大类
func Type(path string) string {
    return defaultFilesystem.Type(path)
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

// MimeType
func MimeType(path string) string {
    return defaultFilesystem.MimeType(path)
}

// 文件大小
func (this *Filesystem) Size(path string) int64 {
    f, err := os.Stat(path)
    if err != nil {
        return 0
    }

    return f.Size()
}

// 文件大小
func Size(path string) int64 {
    return defaultFilesystem.Size(path)
}

// 文件最后更新时间
func (this *Filesystem) LastModified(path string) int64 {
    f, err := os.Stat(path)
    if err != nil {
        return 0
    }

    return f.ModTime().Unix()
}

// 文件最后更新时间
func LastModified(path string) int64 {
    return defaultFilesystem.LastModified(path)
}

// 是否是文件
func (this *Filesystem) IsFile(path string) bool {
    fd, err := os.Stat(path)
    if err != nil && os.IsNotExist(err) {
        return false
    }

    fm := fd.Mode()
    return !fm.IsDir()
}

// 是否是文件
func IsFile(path string) bool {
    return defaultFilesystem.IsFile(path)
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

// 是否为文件夹
func IsDirectory(path string) bool {
    return defaultFilesystem.IsDirectory(path)
}

// 是否可读
func (this *Filesystem) IsReadable(path string) bool {
    _, err := os.ReadFile(path)
    if err != nil {
        return false
    }

    return true
}

// 是否可读
func IsReadable(path string) bool {
    return defaultFilesystem.IsReadable(path)
}

// 是否可写
func (this *Filesystem) IsWritable(path string) bool {
    perm, err := this.PermString(path)
    if err != nil {
        return false
    }

    return len(strings.Split(perm, "w")) == 4
}

// 是否可写
func IsWritable(path string) bool {
    return defaultFilesystem.IsWritable(path)
}

// 文件路径匹配
func (this *Filesystem) Match(pattern, name string) (bool, error) {
    return filepath.Match(pattern, name)
}

// 文件路径匹配
func Match(pattern, name string) (bool, error) {
    return defaultFilesystem.Match(pattern, name)
}

// 查询
func (this *Filesystem) Glob(pattern string) ([]string, error) {
    return filepath.Glob(pattern)
}

// 查询
func Glob(pattern string) ([]string, error) {
    return defaultFilesystem.Glob(pattern)
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

// 列出文件
func Files(directory string) ([]string, error) {
    return defaultFilesystem.Files(directory)
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

// 全部文件
func AllFiles(directory string) ([]string, error) {
    return defaultFilesystem.AllFiles(directory)
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

// 列出文件夹
func Directories(directory string) ([]string, error) {
    return defaultFilesystem.Directories(directory)
}

// 创建文件夹
func (this *Filesystem) EnsureDirectoryExists(
    directory string,
    mode uint32,
    recursive ...bool,
) error {
    newRecursive := true
    if len(recursive) > 0 {
        newRecursive = recursive[0]
    }

    err := this.MakeDirectory(directory, mode, newRecursive)
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
func EnsureDirectoryExists(
    directory string,
    mode uint32,
    recursive ...bool,
) error {
    return defaultFilesystem.EnsureDirectoryExists(directory, mode, recursive...)
}

// 创建文件夹
func (this *Filesystem) MakeDirectory(
    directory string,
    mode uint32,
    recursive ...bool,
) error {
    if len(recursive) > 0 && recursive[0] {
        return os.MkdirAll(directory, os.FileMode(mode))
    } else {
        return os.Mkdir(directory, os.FileMode(mode))
    }
}

// 创建文件夹
func MakeDirectory(
    directory string,
    mode uint32,
    recursive ...bool,
) error {
    return defaultFilesystem.MakeDirectory(directory, mode, recursive...)
}

// 移动文件夹
func (this *Filesystem) MoveDirectory(
    from string,
    to string,
    overwrite ...bool,
) error {
    if len(overwrite) > 0 && overwrite[0] && this.IsDirectory(to) {
        err := this.DeleteDirectory(to, false)
        if err != nil {
            return errors.New("覆盖旧文件操作失败")
        }
    }

    return os.Rename(from, to)
}

// 移动文件夹
func MoveDirectory(
    from string,
    to string,
    overwrite ...bool,
) error {
    return defaultFilesystem.MoveDirectory(from, to, overwrite...)
}

// 复制文件夹
func (this *Filesystem) CopyDirectory(directory string, destination string) error {
    // 检测目录正确性
    if srcInfo, err := os.Stat(directory); err != nil {
        return errors.New("原始目录不是一个正确的目录！原因为：" + err.Error())
    } else {
        if !srcInfo.IsDir() {
            e := errors.New("原始目录不是一个正确的目录！")
            return e
        }
    }

    // 目录不存在时
    if !this.Exists(destination) {
        // 创建目录
        err := os.MkdirAll(destination, os.ModePerm)
        if err != nil {
            return errors.New("创建目录失败！原因为：" + err.Error())
        }
    }

    if destInfo, err := os.Stat(destination); err != nil {
        return errors.New("目标目录不是一个正确的目录！原因为：" + err.Error())
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

// 复制文件夹
func CopyDirectory(directory string, destination string) error {
    return defaultFilesystem.CopyDirectory(directory, destination)
}

// 删除文件夹
func (this *Filesystem) DeleteDirectory(directory string, preserve ...bool) error {
    if !this.IsDirectory(directory) {
        return errors.New("文件夹删除失败, 当前文件不是文件夹类型")
    }

    if err := os.RemoveAll(directory); err != nil {
        return errors.New("文件夹删除失败, 错误为:" + err.Error())
    }

    newPreserve := false
    if len(preserve) > 0 {
        newPreserve = preserve[0]
    }

    if !newPreserve {
        this.Delete(directory)
    }

    return nil
}

// 删除文件夹
func DeleteDirectory(directory string, preserve ...bool) error {
    return defaultFilesystem.DeleteDirectory(directory, preserve...)
}

// 删除文件夹
func (this *Filesystem) DeleteDirectories(directory string) bool {
    allDirectories, _ := this.Directories(directory)

    if len(allDirectories) > 0 {
        for _, directoryName := range allDirectories {
            this.DeleteDirectory(filepath.Join(directory, directoryName), false)
        }

        return true
    }

    return false
}

// 删除文件夹
func DeleteDirectories(directory string) bool {
    return defaultFilesystem.DeleteDirectories(directory)
}

// 清空文件夹
func (this *Filesystem) CleanDirectory(directory string) error {
    return this.DeleteDirectory(directory, true)
}

// 清空文件夹
func CleanDirectory(directory string) error {
    return defaultFilesystem.CleanDirectory(directory)
}

