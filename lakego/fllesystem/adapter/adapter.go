package adapter

import(
    "os"

    "lakego-admin/lakego/fllesystem/interfaces"
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
func (ap *Adapter) Init(config ...map[string]interface{}) {
    // todo
}

// 确认文件夹
func (ap *Adapter) EnsureDirectory(root string) error {
    panic("接口没有实现")
}

// 判断
func (ap *Adapter) Has(string) bool {
    return false
}

// 上传
func (ap *Adapter) Write(path string, contents string, conf interfaces.Config) (map[string]interface{}, error) {
    panic("接口没有实现")
}

// 上传 Stream 文件类型
func (ap *Adapter) WriteStream(path string, stream *os.File, conf interfaces.Config) (map[string]interface{}, error) {
    panic("接口没有实现")
}

// 更新
func (ap *Adapter) Update(path string, contents string, conf interfaces.Config) (map[string]interface{}, error) {
    panic("接口没有实现")
}

// 更新
func (ap *Adapter) UpdateStream(path string, stream *os.File, conf interfaces.Config) (map[string]interface{}, error) {
    panic("接口没有实现")
}

//
func (ap *Adapter) Read(path string) (map[string]interface{}, error) {
    panic("接口没有实现")
}

//
func (ap *Adapter) ReadStream(path string) (map[string]interface{}, error) {
    panic("接口没有实现")
}

// 重命名
func (ap *Adapter) Rename(path string, newpath string) error {
    panic("接口没有实现")
}

// 复制
func (ap *Adapter) Copy(path string, newpath string) error {
    panic("接口没有实现")
}

// 删除
func (ap *Adapter) Delete(path string) error {
    panic("接口没有实现")
}

// 删除文件夹
func (ap *Adapter) DeleteDir(dirname string) error {
    panic("接口没有实现")
}

// 创建文件夹
func (ap *Adapter) CreateDir(dirname string, conf interfaces.Config) (map[string]string, error) {
    panic("接口没有实现")
}

// 列出内容
func (ap *Adapter) ListContents(directory string, recursive ...bool) ([]map[string]interface{}, error) {
    panic("接口没有实现")
}

//
func (ap *Adapter) GetMetadata(path string) (map[string]interface{}, error) {
    panic("接口没有实现")
}

//
func (ap *Adapter) GetSize(path string) (map[string]interface{}, error) {
    panic("接口没有实现")
}

//
func (ap *Adapter) GetMimetype(path string) (map[string]interface{}, error) {
    panic("接口没有实现")
}

//
func (ap *Adapter) GetTimestamp(path string) (map[string]interface{}, error) {
    panic("接口没有实现")
}

// 获取文件的权限
func (ap *Adapter) GetVisibility(path string) (map[string]string, error) {
    panic("接口没有实现")
}

// 设置文件的权限
func (ap *Adapter) SetVisibility(path string, visibility string) (map[string]string, error) {
    panic("接口没有实现")
}
