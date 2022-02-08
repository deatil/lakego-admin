package interfaces

// Hub 接口
type Hub interface {
    // Pipe
    Pipe(interface{}, ...string) interface{}
}
