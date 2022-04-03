package interfaces

/**
 * 适配器接口
 *
 * @create 2022-1-9
 * @author deatil
 */
type Adapter interface {
    // 获取渲染
    Render() Render
}

