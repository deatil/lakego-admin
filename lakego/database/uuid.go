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

func (a BinaryUUID) String() string {
	return uuid.UUID(a).String()
}

// convert to json string
func (a BinaryUUID) MarshalJSON() ([]byte, error) {
	s := uuid.UUID(a)
	str := "\"" + s.String() + "\""
	return []byte(str), nil
}

// convert from json string
func (a *BinaryUUID) UnmarshalJSON(by []byte) error {
	s, err := uuid.ParseBytes(by)
	*a = BinaryUUID(s)
	return err
}

// sql data type for gorm
func (a BinaryUUID) GormDataType() string {
	return "binary(16)"
}

// scan value into BinaryUUID
func (a *BinaryUUID) Scan(value interface{}) error {
	bytes, ok := value.([]byte)
	if !ok {
		return errors.New(fmt.Sprint("Failed to unmarshal JSONB value:", value))
	}

	data, err := uuid.FromBytes(bytes)
	*a = BinaryUUID(data)
	return err
}

// return BinaryUUID to []bytes binary(16)
func (a BinaryUUID) Value() (driver.Value, error) {
	return uuid.UUID(a).MarshalBinary()
}
