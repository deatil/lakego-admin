package controller

import (
    "strings"

    "lakego-admin/lakego/support/time"
    "lakego-admin/lakego/http/controller"
)

/**
 * 基类
 *
 * @create 2021-8-31
 * @author deatil
 */
type Base struct {
    controller.Base
}

// 状态通用转换
func (ctl *Base) SwitchStatus(name string) int {
    statusList := map[string]int{
        "open": 1,
        "close": 0,
    }

    if value, ok := statusList[name]; ok {
        return value
    }

    return -1
}

// 时间格式化到时间戳
func (ctl *Base) FormatDate(date string) int64 {
    return time.StringToTimestamp(date)
}

// 状态通用转换
func (ctl *Base) FormatOrderBy(order string, defaulter ...string) string {
    newDefault := "ASC"
    if len(defaulter) > 0 {
        newDefault = defaulter[0]
    }

    if order == "" {
        return newDefault
    }

    orderList := []string{
        "ASC",
        "DESC",
    }

    order = strings.ToUpper(order)

    for k, v := range orderList {
        if order == v {
            return order
        }
    }

    return newDefault
}

