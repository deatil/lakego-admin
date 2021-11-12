package scope

import (
    "gorm.io/gorm"
    
    "github.com/deatil/lakego-admin/lakego/router"
    "github.com/deatil/lakego-admin/admin/auth/admin"
)

// 权限检测
func AdminWithAccess(ctx *router.Context, ids ...[]string) func(*gorm.DB) *gorm.DB {
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

        if len(newIds) > 0 {
            return db.Preload("GroupAccesses", "group_id IN (?)", newIds)
        } else {
            return db.Preload("GroupAccesses")
        }
    }
}

