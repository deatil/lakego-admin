package controller

import (
    "strings"

    "github.com/deatil/go-datebin/datebin"

    "github.com/deatil/lakego-doak-admin/admin/support/controller"
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
func (this *Base) SwitchStatus(name string) int {
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
func (this *Base) FormatDate(date string) int64 {
    return datebin.StringToTimestamp(date)
}

// 格式化排序
func (this *Base) FormatOrderBy(order string, def ...string) []string {
    newDefault := "add_time__DESC"
    if len(def) > 0 {
        newDefault = def[0]
    }

    if order == "" {
        order = newDefault
    }

    orders := strings.SplitN(order, "__", 2)
    if len(orders) != 2 {
        orders = []string{"add_time", "DESC"}
    }

    orders[1] = strings.ToUpper(orders[1])
    if orders[1] != "ASC" && orders[1] != "DESC" {
        orders[1] = "DESC"
    }

    return orders
}

