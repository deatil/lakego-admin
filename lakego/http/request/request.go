package request

import (
	"net/http"
	"github.com/spf13/cast"
	"github.com/gin-gonic/gin"
)

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

type ContextWrapper struct {
	Ctx *gin.Context
}

func Context(Ctx *gin.Context) *ContextWrapper {
	return &ContextWrapper{
		Ctx: Ctx,
	}
}

func (that *ContextWrapper) ResponseJson(json interface{}) {
	that.Ctx.JSON(http.StatusAccepted, &json)
}

func (that *ContextWrapper) ResponseString(str string) {
	that.Ctx.String(http.StatusAccepted, str)
}

func (that *ContextWrapper) Unauthorized() {
	that.Ctx.AbortWithStatus(http.StatusUnauthorized)
}

func (that *ContextWrapper) Forbidden() {
	that.Ctx.AbortWithStatus(http.StatusForbidden)
}

func (that *ContextWrapper) Query(key string) string {
	return that.Ctx.Query(key)
}

func (that *ContextWrapper) DefaultQuery(key string, def interface{}) string {
	return that.Ctx.DefaultQuery(key, cast.ToString(def))
}

func (that *ContextWrapper) Param(key string) string {
	return that.Ctx.Param(key)
}

func (that *ContextWrapper) JSON(code int, data interface{}) {
	that.Ctx.JSON(code, data)
}

func (that *ContextWrapper) BindJSON(i interface{}) error {
	return that.Ctx.BindJSON(i)
}

func (that *ContextWrapper) ShouldBind(i interface{}) error {
	return that.Ctx.ShouldBind(i)
}

func (that *ContextWrapper) ShouldBindQuery(i interface{}) error {
	return that.Ctx.ShouldBindQuery(i)
}

func (that *ContextWrapper) GetQueryArray(key string) ([]string, bool) {
	return that.Ctx.GetQueryArray(key)
}

func (that *ContextWrapper) PostForm(key string) string {
	return that.Ctx.PostForm(key)
}
