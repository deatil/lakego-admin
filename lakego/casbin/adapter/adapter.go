package adapter

import (
    "time"
    "errors"
    "strconv"
    "strings"

    "gorm.io/gorm"
    "github.com/casbin/casbin/v2/model"
    "github.com/casbin/casbin/v2/persist"

    "lakego-admin/lakego/support/hash"
    "lakego-admin/lakego/support/random"
)

type Rules struct {
    ID    string `gorm:"primaryKey;autoIncrement:false;size:32"`
    Ptype string `gorm:"size:250;"`
    V0    string `gorm:"size:250;"`
    V1    string `gorm:"size:250;"`
    V2    string `gorm:"size:250;"`
    V3    string `gorm:"size:250;"`
    V4    string `gorm:"size:250;"`
    V5    string `gorm:"size:250;"`
}

func (rules *Rules) BeforeCreate(db *gorm.DB) error {
    id := hash.MD5(strconv.FormatInt(time.Now().Unix(), 10) + random.String(10))
    rules.ID = id

    return nil
}

type Filter struct {
    PType []string
    V0    []string
    V1    []string
    V2    []string
    V3    []string
    V4    []string
    V5    []string
}

// gorm 适配器
type Adapter struct {
    db             *gorm.DB
    isFiltered     bool
}

// 自定义模型
func NewAdapterByDB(db *gorm.DB) (*Adapter, error) {
    a := &Adapter{}

    model := a.getDefaultModel()
    a.db = db.Scopes(a.ruleTable(model)).
        Session(&gorm.Session{Context: db.Statement.Context})

    return a, nil
}

// 关闭
func (a *Adapter) close() error {
    a.db = nil
    return nil
}

// 默认模型
func (a *Adapter) getDefaultModel() *Rules {
    return &Rules{}
}

// 规则表格
func (a *Adapter) ruleTable(model interface{}) func(db *gorm.DB) *gorm.DB {
    return func(db *gorm.DB) *gorm.DB {
        return db.Model(model)
    }
}

func loadPolicyLine(line Rules, model model.Model) {
    var p = []string{
        line.Ptype,
        line.V0,
        line.V1,
        line.V2,
        line.V3,
        line.V4,
        line.V5,
    }

    var lineText string
    if line.V5 != "" {
        lineText = strings.Join(p, ", ")
    } else if line.V4 != "" {
        lineText = strings.Join(p[:6], ", ")
    } else if line.V3 != "" {
        lineText = strings.Join(p[:5], ", ")
    } else if line.V2 != "" {
        lineText = strings.Join(p[:4], ", ")
    } else if line.V1 != "" {
        lineText = strings.Join(p[:3], ", ")
    } else if line.V0 != "" {
        lineText = strings.Join(p[:2], ", ")
    }

    persist.LoadPolicyLine(lineText, model)
}

// LoadPolicy loads policy from database.
func (a *Adapter) LoadPolicy(model model.Model) error {
    var lines []Rules
    if err := a.db.Order("ID").Find(&lines).Error; err != nil {
        return err
    }

    for _, line := range lines {
        loadPolicyLine(line, model)
    }

    return nil
}

// LoadFilteredPolicy loads only policy rules that match the filter.
func (a *Adapter) LoadFilteredPolicy(model model.Model, filter interface{}) error {
    var lines []Rules

    filterValue, ok := filter.(Filter)
    if !ok {
        return errors.New("invalid filter type")
    }

    if err := a.db.Scopes(a.filterQuery(a.db, filterValue)).Order("ID").Find(&lines).Error; err != nil {
        return err
    }

    for _, line := range lines {
        loadPolicyLine(line, model)
    }
    a.isFiltered = true

    return nil
}

// IsFiltered returns true if the loaded policy has been filtered.
func (a *Adapter) IsFiltered() bool {
    return a.isFiltered
}

// filterQuery builds the gorm query to match the rule filter to use within a scope.
func (a *Adapter) filterQuery(db *gorm.DB, filter Filter) func(db *gorm.DB) *gorm.DB {
    return func(db *gorm.DB) *gorm.DB {
        if len(filter.PType) > 0 {
            db = db.Where("ptype in (?)", filter.PType)
        }
        if len(filter.V0) > 0 {
            db = db.Where("v0 in (?)", filter.V0)
        }
        if len(filter.V1) > 0 {
            db = db.Where("v1 in (?)", filter.V1)
        }
        if len(filter.V2) > 0 {
            db = db.Where("v2 in (?)", filter.V2)
        }
        if len(filter.V3) > 0 {
            db = db.Where("v3 in (?)", filter.V3)
        }
        if len(filter.V4) > 0 {
            db = db.Where("v4 in (?)", filter.V4)
        }
        if len(filter.V5) > 0 {
            db = db.Where("v5 in (?)", filter.V5)
        }
        return db
    }
}

func (a *Adapter) savePolicyLine(ptype string, rule []string) Rules {
    line := a.getDefaultModel()

    line.Ptype = ptype
    if len(rule) > 0 {
        line.V0 = rule[0]
    }
    if len(rule) > 1 {
        line.V1 = rule[1]
    }
    if len(rule) > 2 {
        line.V2 = rule[2]
    }
    if len(rule) > 3 {
        line.V3 = rule[3]
    }
    if len(rule) > 4 {
        line.V4 = rule[4]
    }
    if len(rule) > 5 {
        line.V5 = rule[5]
    }

    return *line
}

// SavePolicy saves policy to database.
func (a *Adapter) SavePolicy(model model.Model) error {
    for ptype, ast := range model["p"] {
        for _, rule := range ast.Policy {
            line := a.savePolicyLine(ptype, rule)
            err := a.db.Create(&line).Error
            if err != nil {
                return err
            }
        }
    }

    for ptype, ast := range model["g"] {
        for _, rule := range ast.Policy {
            line := a.savePolicyLine(ptype, rule)
            err := a.db.Create(&line).Error
            if err != nil {
                return err
            }
        }
    }

    return nil
}

// AddPolicy adds a policy rule to the storage.
func (a *Adapter) AddPolicy(sec string, ptype string, rule []string) error {
    line := a.savePolicyLine(ptype, rule)
    err := a.db.Create(&line).Error
    return err
}

// RemovePolicy removes a policy rule from the storage.
func (a *Adapter) RemovePolicy(sec string, ptype string, rule []string) error {
    line := a.savePolicyLine(ptype, rule)
    err := a.rawDelete(a.db, line) //can't use db.Delete as we're not using primary key http://jinzhu.me/gorm/crud.html#delete
    return err
}

// AddPolicies adds multiple policy rules to the storage.
func (a *Adapter) AddPolicies(sec string, ptype string, rules [][]string) error {
    return a.db.Transaction(func(tx *gorm.DB) error {
        for _, rule := range rules {
            line := a.savePolicyLine(ptype, rule)
            if err := tx.Create(&line).Error; err != nil {
                return err
            }
        }
        return nil
    })
}

// RemovePolicies removes multiple policy rules from the storage.
func (a *Adapter) RemovePolicies(sec string, ptype string, rules [][]string) error {
    return a.db.Transaction(func(tx *gorm.DB) error {
        for _, rule := range rules {
            line := a.savePolicyLine(ptype, rule)
            if err := a.rawDelete(tx, line); err != nil { //can't use db.Delete as we're not using primary key http://jinzhu.me/gorm/crud.html#delete
                return err
            }
        }
        return nil
    })
}

// RemoveFilteredPolicy removes policy rules that match the filter from the storage.
func (a *Adapter) RemoveFilteredPolicy(sec string, ptype string, fieldIndex int, fieldValues ...string) error {
    line := a.getDefaultModel()

    line.Ptype = ptype
    if fieldIndex <= 0 && 0 < fieldIndex+len(fieldValues) {
        line.V0 = fieldValues[0-fieldIndex]
    }
    if fieldIndex <= 1 && 1 < fieldIndex+len(fieldValues) {
        line.V1 = fieldValues[1-fieldIndex]
    }
    if fieldIndex <= 2 && 2 < fieldIndex+len(fieldValues) {
        line.V2 = fieldValues[2-fieldIndex]
    }
    if fieldIndex <= 3 && 3 < fieldIndex+len(fieldValues) {
        line.V3 = fieldValues[3-fieldIndex]
    }
    if fieldIndex <= 4 && 4 < fieldIndex+len(fieldValues) {
        line.V4 = fieldValues[4-fieldIndex]
    }
    if fieldIndex <= 5 && 5 < fieldIndex+len(fieldValues) {
        line.V5 = fieldValues[5-fieldIndex]
    }
    err := a.rawDelete(a.db, *line)
    return err
}

func (a *Adapter) rawDelete(db *gorm.DB, line Rules) error {
    queryArgs := []interface{}{line.Ptype}

    queryStr := "ptype = ?"
    if line.V0 != "" {
        queryStr += " and v0 = ?"
        queryArgs = append(queryArgs, line.V0)
    }
    if line.V1 != "" {
        queryStr += " and v1 = ?"
        queryArgs = append(queryArgs, line.V1)
    }
    if line.V2 != "" {
        queryStr += " and v2 = ?"
        queryArgs = append(queryArgs, line.V2)
    }
    if line.V3 != "" {
        queryStr += " and v3 = ?"
        queryArgs = append(queryArgs, line.V3)
    }
    if line.V4 != "" {
        queryStr += " and v4 = ?"
        queryArgs = append(queryArgs, line.V4)
    }
    if line.V5 != "" {
        queryStr += " and v5 = ?"
        queryArgs = append(queryArgs, line.V5)
    }
    args := append([]interface{}{queryStr}, queryArgs...)
    err := db.Delete(a.getDefaultModel(), args...).Error
    return err
}

func appendWhere(line Rules) (string, []interface{}) {
    queryArgs := []interface{}{line.Ptype}

    queryStr := "ptype = ?"
    if line.V0 != "" {
        queryStr += " and v0 = ?"
        queryArgs = append(queryArgs, line.V0)
    }
    if line.V1 != "" {
        queryStr += " and v1 = ?"
        queryArgs = append(queryArgs, line.V1)
    }
    if line.V2 != "" {
        queryStr += " and v2 = ?"
        queryArgs = append(queryArgs, line.V2)
    }
    if line.V3 != "" {
        queryStr += " and v3 = ?"
        queryArgs = append(queryArgs, line.V3)
    }
    if line.V4 != "" {
        queryStr += " and v4 = ?"
        queryArgs = append(queryArgs, line.V4)
    }
    if line.V5 != "" {
        queryStr += " and v5 = ?"
        queryArgs = append(queryArgs, line.V5)
    }
    return queryStr, queryArgs
}

// UpdatePolicy updates a new policy rule to DB.
func (a *Adapter) UpdatePolicy(sec string, ptype string, oldRule, newPolicy []string) error {
    oldLine := a.savePolicyLine(ptype, oldRule)
    queryStr, queryArgs := appendWhere(oldLine)
    newLine := a.savePolicyLine(ptype, newPolicy)
    err := a.db.Where(queryStr, queryArgs...).Updates(newLine).Error
    return err
}
