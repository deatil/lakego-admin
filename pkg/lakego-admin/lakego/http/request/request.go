package request

import (
    "github.com/gin-gonic/gin"

    "github.com/deatil/lakego-admin/lakego/support/cast"
)

// 使用
func New() *Request {
    request := &Request{}

    return request
}

type JSONWriter interface {
    JSON(code int, data interface{})
}

type QueryReader interface {
    Query(key string) string
    DefaultQuery(key string, def string) string
}

type PathParamReader interface {
    Param(key string) string
}

type Writer interface {
    JSONWriter
}

type Reader interface {
    BindJSON(i interface{}) error
    ShouldBind(i interface{}) error
    PostForm(key string) string
}

type HandlerFunc func(request *Request)

/**
 * 请求
 *
 * @create 2021-9-15
 * @author deatil
 */
type Request struct {
    // 上下文
    ctx *gin.Context
}

// 设置上下文
func (this *Request) WithContext(ctx *gin.Context) *Request {
    this.ctx = ctx

    return this
}

// 查询数据
func (this *Request) Query(key string) string {
    return this.ctx.Query(key)
}

// 带默认
func (this *Request) DefaultQuery(key string, def interface{}) string {
    return this.ctx.DefaultQuery(key, cast.ToString(def))
}

// 查询数据
func (this *Request) Param(key string) string {
    return this.ctx.Param(key)
}

// json
func (this *Request) JSON(code int, data interface{}) {
    this.ctx.JSON(code, data)
}

// 绑定 json
func (this *Request) BindJSON(i interface{}) error {
    return this.ctx.BindJSON(i)
}

func (this *Request) ShouldBind(i interface{}) error {
    return this.ctx.ShouldBind(i)
}

func (this *Request) ShouldBindQuery(i interface{}) error {
    return this.ctx.ShouldBindQuery(i)
}

func (this *Request) GetQueryArray(key string) ([]string, bool) {
    return this.ctx.GetQueryArray(key)
}

// 表单请求
func (this *Request) PostForm(key string) string {
    return this.ctx.PostForm(key)
}
