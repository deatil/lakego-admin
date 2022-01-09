package render

import (
    "path"
    "strings"
    "net/http"

    "github.com/flosch/pongo2/v4"

    "github.com/gin-gonic/gin"
    "github.com/gin-gonic/gin/render"

    "github.com/deatil/lakego-admin/lakego/view"
)

// TemplatePath html files path
func TemplatePath(tmplDir string) *PongoRender {
    return &PongoRender{
        TmplDir: tmplDir,
    }
}

var HintPathDelimiter string = "::"

// PongoRender struct init
type PongoRender struct {
    TmplDir string
}

// Instance init
func (p *PongoRender) Instance(name string, data interface{}) render.Render {
    var template *pongo2.Template
    var fileName string

    // 判断
    if strings.Contains(name, HintPathDelimiter) {
        fileName = view.NewViewFinderInstance().Find(name)
    } else {
        fileName = path.Join(p.TmplDir, name)
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
    Data     interface{}
}

// Render for gin interface  render override
func (p *PongoHTML) Render(w http.ResponseWriter) error {
    p.WriteContentType(w)

    data := pongo2.Context{}
    switch p.Data.(type) {
        case map[string]string:
            for k, v := range p.Data.(map[string]string) {
                data[k] = v
            }
    }

    return p.Template.ExecuteWriter(data, w)
}

// WriteContentType  for gin interface  WriteContentType override
func (p *PongoHTML) WriteContentType(w http.ResponseWriter) {
    header := w.Header()
    if val := header["Content-Type"]; len(val) == 0 {
        header["Content-Type"] = []string{"text/html; charset=utf-8"}
    }
}
