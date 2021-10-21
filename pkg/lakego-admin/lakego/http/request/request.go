package request

import (
    "net/http"
    "github.com/gin-gonic/gin"

    "github.com/deatil/lakego-admin/lakego/support/cast"
)

func Context(Ctx *gin.Context) *ContextWrapper {
    return &ContextWrapper{
        Ctx: Ctx,
    }
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

type HandlerFunc func(wrapper *ContextWrapper)

/**
 * 请求
 *
 * @create 2021-9-15
 * @author deatil
 */
type ContextWrapper struct {
    Ctx *gin.Context
}

func (this *ContextWrapper) ResponseJson(json interface{}) {
    this.Ctx.JSON(http.StatusAccepted, &json)
}

func (this *ContextWrapper) ResponseString(str string) {
    this.Ctx.String(http.StatusAccepted, str)
}

func (this *ContextWrapper) Unauthorized() {
    this.Ctx.AbortWithStatus(http.StatusUnauthorized)
}

func (this *ContextWrapper) Forbidden() {
    this.Ctx.AbortWithStatus(http.StatusForbidden)
}

func (this *ContextWrapper) Query(key string) string {
    return this.Ctx.Query(key)
}

func (this *ContextWrapper) DefaultQuery(key string, def interface{}) string {
    return this.Ctx.DefaultQuery(key, cast.ToString(def))
}

func (this *ContextWrapper) Param(key string) string {
    return this.Ctx.Param(key)
}

func (this *ContextWrapper) JSON(code int, data interface{}) {
    this.Ctx.JSON(code, data)
}

func (this *ContextWrapper) BindJSON(i interface{}) error {
    return this.Ctx.BindJSON(i)
}

func (this *ContextWrapper) ShouldBind(i interface{}) error {
    return this.Ctx.ShouldBind(i)
}

func (this *ContextWrapper) ShouldBindQuery(i interface{}) error {
    return this.Ctx.ShouldBindQuery(i)
}

func (this *ContextWrapper) GetQueryArray(key string) ([]string, bool) {
    return this.Ctx.GetQueryArray(key)
}

func (this *ContextWrapper) PostForm(key string) string {
    return this.Ctx.PostForm(key)
}
