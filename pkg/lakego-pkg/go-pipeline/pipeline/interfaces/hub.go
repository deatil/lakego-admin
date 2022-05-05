package interfaces

// Hub 接口
type Hub interface {
    // Pipe
    Pipe(any, ...string) any
}
