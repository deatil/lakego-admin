package database

import (
    "errors"
    "fmt"

    "database/sql/driver"

    "github.com/google/uuid"
)

// binary uuid wrapper over uuid.UUID
// example - gorm:"type:binary(16);default:(UUID_TO_BIN(UUID()));
type BinaryUUID uuid.UUID

func (this BinaryUUID) String() string {
    return uuid.UUID(this).String()
}

// convert to json string
func (this BinaryUUID) MarshalJSON() ([]byte, error) {
    s := uuid.UUID(this)
    str := "\"" + s.String() + "\""
    return []byte(str), nil
}

// convert from json string
func (this *BinaryUUID) UnmarshalJSON(by []byte) error {
    s, err := uuid.ParseBytes(by)
    *this = BinaryUUID(s)
    return err
}

// sql data type for gorm
func (this BinaryUUID) GormDataType() string {
    return "binary(16)"
}

// scan value into BinaryUUID
func (this *BinaryUUID) Scan(value any) error {
    bytes, ok := value.([]byte)
    if !ok {
        return errors.New(fmt.Sprint("Failed to unmarshal JSONB value:", value))
    }

    data, err := uuid.FromBytes(bytes)
    *this = BinaryUUID(data)
    return err
}

// return BinaryUUID to []bytes binary(16)
func (this BinaryUUID) Value() (driver.Value, error) {
    return uuid.UUID(this).MarshalBinary()
}
