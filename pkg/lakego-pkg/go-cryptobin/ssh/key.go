package ssh

import (
    "errors"
    "reflect"
)

// 反射获取结构体名称
func GetStructName(name any) string {
    elem := reflect.TypeOf(name).Elem()

    return elem.PkgPath() + "." + elem.Name()
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
