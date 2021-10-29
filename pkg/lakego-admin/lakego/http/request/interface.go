package request

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
