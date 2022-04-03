package request

// json 输出
type JSONWriter interface {
    JSON(code int, data interface{})
}

// 查询读
type QueryReader interface {
    Query(key string) string
    DefaultQuery(key string, def string) string
}

// 路径数据读
type PathParamReader interface {
    Param(key string) string
}

// 写接口
type Writer interface {
    JSONWriter
}

// 读接口
type Reader interface {
    BindJSON(i interface{}) error
    ShouldBind(i interface{}) error
    PostForm(key string) string
}
