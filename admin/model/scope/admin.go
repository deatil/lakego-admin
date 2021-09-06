package scope

import (
    "gorm.io/gorm"
    "github.com/gin-gonic/gin"

    "lakego-admin/admin/auth/admin"
)

// 权限检测
func AdminWithAccess(ctx *gin.Context, ids []string) func(*gorm.DB) *gorm.DB {
    return func(db *gorm.DB) *gorm.DB {
        adminInfo, _ := ctx.Get("admin")

        adminData := adminInfo.(*admin.Admin)
        if adminData.IsSuperAdministrator() {
            return db
        }

        groupids := adminData.GetGroupChildrenIds()
        if len(groupids) > 0 {
            ids = append(ids, groupids...)
        }

        return db.Preload("GroupAccesses", "group_id IN (?)", ids)
    }
}

