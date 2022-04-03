package html

import (
    "github.com/deatil/lakego-doak/lakego/view/html/interfaces"
)

// 构造函数
func New(adapter interfaces.Adapter) *Html {
    html := &Html{}
    html.WithAdapter(adapter)

    return html
}

/**
 * 模板
 *
 * @create 2022-1-9
 * @author deatil
 */
type Html struct {
    // 适配器
    Adapter interfaces.Adapter
}

// 设置适配器
func (this *Html) WithAdapter(adapter interfaces.Adapter) *Html {
    this.Adapter = adapter

    return this
}

// 获取适配器
func (this *Html) GetAdapter() interfaces.Adapter {
    return this.Adapter
}

// 获取渲染
func (this *Html) GetRender() interfaces.Render {
    return this.Adapter.Render()
}

