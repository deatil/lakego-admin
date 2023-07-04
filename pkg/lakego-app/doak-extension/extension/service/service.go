package service

import (
    "fmt"
    "errors"

    "github.com/deatil/lakego-doak-extension/extension/model"
    "github.com/deatil/lakego-doak-extension/extension/version"
)

// 检测依赖
func CheckExtensionRequire(requires map[string]string) (bool, error) {
    if len(requires) == 0 {
        return true, nil
    }

    exts := make([]string, 0)
    for _, require := range requires {
        exts = append(exts, require)
    }

    requireExts := make([]map[string]any, 0)

    model.NewExtension().
        Where("name IN", exts).
        Order("listorder DESC").
        Find(&requireExts)
    if len(requireExts) == 0 {
        return false, errors.New("需要的依赖扩展需要安装")
    }

    for _, requireExt := range requireExts {
        extName := requireExt["name"].(string)
        extVersion := requireExt["version"].(string)

        if ver, ok := requires[extName]; ok {
            err := version.VersionCheck(extVersion, ver)
            if err != nil {
                return false, errors.New(fmt.Sprintf("依赖扩展[%s]所需安装版本[%s]错误", ver, extVersion))
            }
        }
    }

    return true, nil
}
