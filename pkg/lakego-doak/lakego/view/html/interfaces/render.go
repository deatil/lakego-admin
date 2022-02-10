package interfaces

import (
    "github.com/gin-gonic/gin/render"
)

/**
 * 渲染接口
 *
 * @create 2022-1-9
 * @author deatil
 */
type Render interface {
    // Instance init
    Instance(name string, data interface{}) render.Render
}

