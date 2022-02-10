package database

// Model base model
type Model struct {
    Id  uint              `gorm:"column:record_id;primaryKey;autoIncrement;" json:"-"`
    CreatedAt Datetime    `gorm:"column:created_at;autoCreateTime;" json:"created_at"`
    UpdatedAt Datetime    `gorm:"column:updated_at;autoUpdateTime;" json:"updated_at"`
}
