package request

import (
    "io"
    "mime/multipart"

    cast "github.com/deatil/go-goch/goch"

    "github.com/deatil/lakego-doak/lakego/router"
)

// 使用
func New() *Request {
    request := &Request{}

    return request
}

/**
 * 请求
 *
 * @create 2021-9-15
 * @author deatil
 */
type Request struct {
    // 上下文
    ctx *router.Context
}

// 设置上下文
func (this *Request) WithContext(ctx *router.Context) *Request {
    this.ctx = ctx

    return this
}

// 获取上下文
func (this *Request) GetContext() *router.Context {
    return this.ctx
}

// 完整匹配路径
func (this *Request) FullPath() string {
    return this.ctx.FullPath()
}

// 查询数据
func (this *Request) Param(key string) string {
    return this.ctx.Param(key)
}

// 查询数据
func (this *Request) Query(key string) string {
    return this.ctx.Query(key)
}

// 带默认
func (this *Request) DefaultQuery(key string, def any) string {
    return this.ctx.DefaultQuery(key, cast.ToString(def))
}

// 查询数据
func (this *Request) GetQuery(key string) (string, bool) {
    return this.ctx.GetQuery(key)
}

// 获取数组
func (this *Request) QueryArray(key string) []string {
    return this.ctx.QueryArray(key)
}

// 获取数组
func (this *Request) GetQueryArray(key string) ([]string, bool) {
    return this.ctx.GetQueryArray(key)
}

// map
func (this *Request) QueryMap(key string) map[string]string {
    return this.ctx.QueryMap(key)
}

// GetQueryMap
func (this *Request) GetQueryMap(key string) (map[string]string, bool) {
    return this.ctx.GetQueryMap(key)
}

// 表单请求
func (this *Request) PostForm(key string) string {
    return this.ctx.PostForm(key)
}

// 表单请求
func (this *Request) DefaultPostForm(key, defaultValue string) string {
    return this.ctx.DefaultPostForm(key, defaultValue)
}

// 表单请求
func (this *Request) GetPostForm(key string) (string, bool) {
    return this.ctx.GetPostForm(key)
}

// 表单请求
func (this *Request) PostFormArray(key string) []string {
    return this.ctx.PostFormArray(key)
}

// 表单请求
func (this *Request) GetPostFormArray(key string) ([]string, bool) {
    return this.ctx.GetPostFormArray(key)
}

// 表单请求
func (this *Request) PostFormMap(key string) map[string]string {
    return this.ctx.PostFormMap(key)
}

// 表单请求
func (this *Request) GetPostFormMap(key string) (map[string]string, bool) {
    return this.ctx.GetPostFormMap(key)
}

// 表单文件上传
func (this *Request) FormFile(name string) (*multipart.FileHeader, error) {
    return this.ctx.FormFile(name)
}

// 表单批量返回
func (this *Request) MultipartForm() (*multipart.Form, error) {
    return this.ctx.MultipartForm()
}

// 绑定
func (this *Request) Bind(obj any) error {
    return this.ctx.Bind(obj)
}

// 绑定 json
func (this *Request) BindJSON(i any) error {
    return this.ctx.BindJSON(i)
}

// 绑定 xml
func (this *Request) BindXML(obj any) error {
    return this.ctx.BindXML(obj)
}

// 绑定 query
func (this *Request) BindQuery(obj any) error {
    return this.ctx.BindQuery(obj)
}

// 绑定 BindYAML
func (this *Request) BindYAML(obj any) error {
    return this.ctx.BindYAML(obj)
}

// 绑定 BindHeader
func (this *Request) BindHeader(obj any) error {
    return this.ctx.BindHeader(obj)
}

// 绑定 BindUri
func (this *Request) BindUri(obj any) error {
    return this.ctx.BindUri(obj)
}

// 绑定 MustBindWith
func (this *Request) MustBindWith(obj any, b router.Binding) error {
    return this.ctx.MustBindWith(obj, b)
}

// json
func (this *Request) JSON(code int, data any) {
    this.ctx.JSON(code, data)
}

func (this *Request) ShouldBind(obj any) error {
    return this.ctx.ShouldBind(obj)
}

func (this *Request) ShouldBindJSON(obj any) error {
    return this.ctx.ShouldBindJSON(obj)
}

func (this *Request) ShouldBindXML(obj any) error {
    return this.ctx.ShouldBindXML(obj)
}

func (this *Request) ShouldBindQuery(obj any) error {
    return this.ctx.ShouldBindQuery(obj)
}

func (this *Request) ShouldBindYAML(obj any) error {
    return this.ctx.ShouldBindYAML(obj)
}

func (this *Request) ShouldBindHeader(obj any) error {
    return this.ctx.ShouldBindHeader(obj)
}

func (this *Request) ShouldBindUri(obj any) error {
    return this.ctx.ShouldBindUri(obj)
}

func (this *Request) ShouldBindWith(obj any, b router.Binding) error {
    return this.ctx.ShouldBindWith(obj, b)
}

func (this *Request) ShouldBindBodyWith(obj any, bb router.BindingBody) error {
    return this.ctx.ShouldBindBodyWith(obj, bb)
}

func (this *Request) ShouldBindJSONWith(obj any) error {
    return this.ctx.ShouldBindBodyWith(obj, router.BindJSON)
}

// 客户端IP
func (this *Request) ClientIP() string {
    return this.ctx.ClientIP()
}

// RemoteIP
func (this *Request) RemoteIP() string {
    return this.ctx.RemoteIP()
}

// ContentType
func (this *Request) ContentType() string {
    return this.ctx.ContentType()
}

// IsWebsocket
func (this *Request) IsWebsocket() bool {
    return this.ctx.IsWebsocket()
}

// GetHeader
func (this *Request) GetHeader(key string) string {
    return this.ctx.GetHeader(key)
}

// GetRawData
func (this *Request) GetRawData() ([]byte, error) {
    return this.ctx.GetRawData()
}

// 获取 cookie
func (this *Request) Cookie(name string) (string, error) {
    return this.ctx.Cookie(name)
}

// Stream
func (this *Request) Stream(step func(w io.Writer) bool) bool {
    return this.ctx.Stream(step)
}

// Value
func (this *Request) Value(key any) any {
    return this.ctx.Value(key)
}

