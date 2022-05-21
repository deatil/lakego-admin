package scope

import (
    "gorm.io/gorm"

    "github.com/deatil/lakego-doak/lakego/router"
    "github.com/deatil/lakego-doak-admin/admin/auth/admin"
)

// 权限检测
func AdminWithAccess(ctx *router.Context, gadb *gorm.DB, ids ...[]string) func(*gorm.DB) *gorm.DB {
    return func(db *gorm.DB) *gorm.DB {
        adminInfo, _ := ctx.Get("admin")

        adminData := adminInfo.(*admin.Admin)
        if adminData.IsSuperAdministrator() {
            return db
        }

        newIds := make([]string, 0)

        groupids := adminData.GetGroupChildrenIds()
        if len(groupids) > 0 {
            newIds = append(newIds, groupids...)
        }

        if len(ids) > 0 {
            newIds = append(newIds, ids[0]...)
        }

        // 规则列表
        var adminIds []string
        gadb.Where("group_id in ?", newIds).
            Pluck("admin_id", &adminIds)

        return db.Where("id in ?", adminIds)
    }
}

