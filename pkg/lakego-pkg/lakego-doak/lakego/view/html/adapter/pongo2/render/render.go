package render

import (
    "path"
    "path/filepath"
    "net/http"

    "github.com/flosch/pongo2/v4"

    "github.com/gin-gonic/gin"
    "github.com/gin-gonic/gin/render"
)

// TemplatePath html files path
func TemplatePath(tmplDir string) *PongoRender {
    return &PongoRender{
        TmplDir: tmplDir,
    }
}

// PongoRender struct init
type PongoRender struct {
    TmplDir string
}

// Instance init
func (this *PongoRender) Instance(name string, data any) render.Render {
    var template *pongo2.Template
    var fileName string

    // 判断相对路径
    if !filepath.IsAbs(name) {
        fileName = path.Join(this.TmplDir, name)

        // 相对路径
        fileName, _ = filepath.Abs(fileName)
    } else {
        fileName = name
    }

    if gin.Mode() == gin.DebugMode {
        template = pongo2.Must(pongo2.FromFile(fileName))
    } else {
        template = pongo2.Must(pongo2.FromCache(fileName))
    }

    return &PongoHTML{
        Template: template,
        Name:     name,
        Data:     data,
    }
}

// PongoHTML strcut
type PongoHTML struct {
    Template *pongo2.Template
    Name     string
    Data     any
}

// 输出
func (this *PongoHTML) Render(w http.ResponseWriter) error {
    this.WriteContentType(w)

    // 数据兼容处理
    data := pongo2.Context{}
    switch this.Data.(type) {
        // 兼容通用数据
        case map[string]any:
            for k, v := range this.Data.(map[string]any) {
                data[k] = v
            }

        // 兼容 gin 数据
        case gin.H:
            for k, v := range this.Data.(gin.H) {
                data[k] = v
            }

        // 兼容 pongo2 数据
        case pongo2.Context:
            for k, v := range this.Data.(pongo2.Context) {
                data[k] = v
            }

        // 不清楚结构直接赋值为 data
        default:
            data["data"] = this.Data
    }

    return this.Template.ExecuteWriter(data, w)
}

// WriteContentType  for gin interface  WriteContentType override
func (this *PongoHTML) WriteContentType(w http.ResponseWriter) {
    header := w.Header()
    if val := header["Content-Type"]; len(val) == 0 {
        header["Content-Type"] = []string{"text/html; charset=utf-8"}
    }
}
