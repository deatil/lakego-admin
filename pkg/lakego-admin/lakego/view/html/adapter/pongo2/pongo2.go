package pongo2

import (
    "github.com/deatil/lakego-admin/lakego/view/html/interfaces"
    "github.com/deatil/lakego-admin/lakego/view/html/adapter/pongo2/render"
)

// 构造函数
func New(path string) *Pongo2 {
    pongo2 := &Pongo2{}
    pongo2.WithPath(path)

    return pongo2
}

/**
 * pongo2 模板
 *
 * @create 2022-1-9
 * @author deatil
 */
type Pongo2 struct {
    path string
}

// 目录
func (this *Pongo2) WithPath(path string) {
    this.path = path
}

// 渲染
func (this *Pongo2) Render() interfaces.Render {
    return render.TemplatePath(this.path)
}
