package adapter

import(
    "os"

    "lakego-admin/lakego/fllesystem/interfaces"
)

type Adapter struct {
    Abstract
}

// 初始化
func (ap *Adapter) Init(config ...map[string]interface{}) {
    // todo
}

// 确认文件夹
func (ap *Adapter) EnsureDirectory(root string) error {
    return nil
}

// 判断
func (ap *Adapter) Has(string) bool {
    return false
}

// 上传
func (ap *Adapter) Write(path string, contents string, conf interfaces.Config) (map[string]interface{}, error) {
    return map[string]interface{}{}, nil
}

// 上传 Stream 文件类型
func (ap *Adapter) WriteStream(path string, stream *os.File, conf interfaces.Config) (map[string]interface{}, error) {
    return map[string]interface{}{}, nil
}

// 更新
func (ap *Adapter) Update(path string, contents string, conf interfaces.Config) (map[string]interface{}, error) {
    return map[string]interface{}{}, nil
}

// 更新
func (ap *Adapter) UpdateStream(path string, stream *os.File, conf interfaces.Config) (map[string]interface{}, error) {
    return map[string]interface{}{}, nil
}

//
func (ap *Adapter) Read(path string) (map[string]interface{}, error) {
    return map[string]interface{}{}, nil
}

//
func (ap *Adapter) ReadStream(path string) (map[string]interface{}, error) {
    return map[string]interface{}{}, nil
}

// 重命名
func (ap *Adapter) Rename(path string, newpath string) error {
    return nil
}

// 复制
func (ap *Adapter) Copy(path string, newpath string) error {
    return nil
}

// 删除
func (ap *Adapter) Delete(path string) error {
    return nil
}

// 删除文件夹
func (ap *Adapter) DeleteDir(dirname string) error {
    return nil
}

// 创建文件夹
func (ap *Adapter) CreateDir(dirname string, conf interfaces.Config) (map[string]string, error) {
    return map[string]string{}, nil
}

// 列出内容
func (ap *Adapter) ListContents(directory string, recursive ...bool) ([]map[string]interface{}, error) {
    return make([]map[string]interface{}, 0), nil
}

//
func (ap *Adapter) GetMetadata(path string) (map[string]interface{}, error) {
    return map[string]interface{}{}, nil
}

//
func (ap *Adapter) GetSize(path string) (map[string]interface{}, error) {
    return map[string]interface{}{}, nil
}

//
func (ap *Adapter) GetMimetype(path string) (map[string]interface{}, error) {
    return map[string]interface{}{}, nil
}

//
func (ap *Adapter) GetTimestamp(path string) (map[string]interface{}, error) {
    return map[string]interface{}{}, nil
}

// 获取文件的权限
func (ap *Adapter) GetVisibility(path string) (map[string]string, error) {
    return map[string]string{}, nil
}

// 设置文件的权限
func (ap *Adapter) SetVisibility(path string, visibility string) (map[string]string, error) {
    return map[string]string{}, nil
}
