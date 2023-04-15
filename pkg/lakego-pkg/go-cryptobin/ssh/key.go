package ssh

import (
    "errors"
    "reflect"
)

// 反射获取结构体名称
func GetStructName(s any) (name string) {
    p := reflect.TypeOf(s)

    if p.Kind() == reflect.Pointer {
        p = p.Elem()
        name = "*"
    }

    pkgPath := p.PkgPath()

    if pkgPath != "" {
        name += pkgPath + "."
    }

    return name + p.Name()
}

// 检测 padding
func checkOpenSSHKeyPadding(pad []byte) error {
    for i, b := range pad {
        if int(b) != i+1 {
            return errors.New("error decoding key: padding not as expected")
        }
    }

    return nil
}
