package adapter

import(
    "os"

    "github.com/deatil/go-filesystem/filesystem/interfaces"
)

/**
 * 空适配器
 *
 * @create 2021-8-1
 * @author deatil
 */
type Adapter struct {
    Abstract
}

// 初始化
func (this *Adapter) Init(config ...map[string]interface{}) {
    // todo
}

// 确认文件夹
func (this *Adapter) EnsureDirectory(root string) error {
    panic("接口没有实现")
}

// 判断
func (this *Adapter) Has(string) bool {
    return false
}

// 上传
func (this *Adapter) Write(path string, contents string, conf interfaces.Config) (map[string]interface{}, error) {
    panic("接口没有实现")
}

// 上传 Stream 文件类型
func (this *Adapter) WriteStream(path string, stream *os.File, conf interfaces.Config) (map[string]interface{}, error) {
    panic("接口没有实现")
}

// 更新
func (this *Adapter) Update(path string, contents string, conf interfaces.Config) (map[string]interface{}, error) {
    panic("接口没有实现")
}

// 更新
func (this *Adapter) UpdateStream(path string, stream *os.File, conf interfaces.Config) (map[string]interface{}, error) {
    panic("接口没有实现")
}

//
func (this *Adapter) Read(path string) (map[string]interface{}, error) {
    panic("接口没有实现")
}

//
func (this *Adapter) ReadStream(path string) (map[string]interface{}, error) {
    panic("接口没有实现")
}

// 重命名
func (this *Adapter) Rename(path string, newpath string) error {
    panic("接口没有实现")
}

// 复制
func (this *Adapter) Copy(path string, newpath string) error {
    panic("接口没有实现")
}

// 删除
func (this *Adapter) Delete(path string) error {
    panic("接口没有实现")
}

// 删除文件夹
func (this *Adapter) DeleteDir(dirname string) error {
    panic("接口没有实现")
}

// 创建文件夹
func (this *Adapter) CreateDir(dirname string, conf interfaces.Config) (map[string]string, error) {
    panic("接口没有实现")
}

// 列出内容
func (this *Adapter) ListContents(directory string, recursive ...bool) ([]map[string]interface{}, error) {
    panic("接口没有实现")
}

//
func (this *Adapter) GetMetadata(path string) (map[string]interface{}, error) {
    panic("接口没有实现")
}

//
func (this *Adapter) GetSize(path string) (map[string]interface{}, error) {
    panic("接口没有实现")
}

//
func (this *Adapter) GetMimetype(path string) (map[string]interface{}, error) {
    panic("接口没有实现")
}

//
func (this *Adapter) GetTimestamp(path string) (map[string]interface{}, error) {
    panic("接口没有实现")
}

// 获取文件的权限
func (this *Adapter) GetVisibility(path string) (map[string]string, error) {
    panic("接口没有实现")
}

// 设置文件的权限
func (this *Adapter) SetVisibility(path string, visibility string) (map[string]string, error) {
    panic("接口没有实现")
}
