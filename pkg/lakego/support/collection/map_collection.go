package collection

import (
	"fmt"
	"encoding/json"
    
	"github.com/deatil/lakego-admin/lakego/support/mapstructure"
)

type MapCollection struct {
	value map[string]interface{}
	BaseCollection
}

// Only returns the items in the collection with the specified keys.
func (c MapCollection) Only(keys []string) Collection {
	var (
		d MapCollection
		m = make(map[string]interface{}, 0)
	)

	for _, k := range keys {
		m[k] = c.value[k]
	}
	d.value = m
	d.length = len(m)

	return d
}

// ToStruct turn the collection to the specified struct using mapstructure.
// https://github.com/mitchellh/mapstructure
func (c MapCollection) ToStruct(dist interface{}) {
	if err := mapstructure.Decode(c.value, dist); err != nil {
		panic(err)
	}
}

// Select select the keys of collection and delete others.
func (c MapCollection) Select(keys ...string) Collection {
	n := copyMap(c.value)

	for key := range n {
		exist := false
		for i := 0; i < len(keys); i++ {
			if keys[i] == key {
				exist = true
				break
			}
		}
		if !exist {
			delete(n, key)
		}
	}

	return MapCollection{
		value: n,
	}
}

// Prepend adds an item to the beginning of the collection.
func (c MapCollection) Prepend(values ...interface{}) Collection {

	var m = copyMap(c.value)
	m[values[0].(string)] = values[1]

	return MapCollection{m, BaseCollection{length: len(m)}}
}

// ToMap converts the collection into a plain golang map.
func (c MapCollection) ToMap() map[string]interface{} {
	return c.value
}

// Contains determines whether the collection contains a given item.
func (c MapCollection) Contains(value ...interface{}) bool {
	if callback, ok := value[0].(CB); ok {
		for k, v := range c.value {
			if callback(k, v) {
				return true
			}
		}
		return false
	}

	for _, v := range c.value {
		if v == value[0] {
			return true
		}
	}
	return false
}

// Dd dumps the collection's items and ends execution of the script.
func (c MapCollection) Dd() {
	dd(c)
}

// Dump dumps the collection's items.
func (c MapCollection) Dump() {
	dump(c)
}

// DiffAssoc compares the collection against another collection or a plain PHP  array based on its keys and values.
// This method will return the key / value pairs in the original collection that are not present in the given collection.
func (c MapCollection) DiffAssoc(m map[string]interface{}) Collection {
	var d = make(map[string]interface{}, 0)
	for key, value := range m {
		if v, ok := c.value[key]; ok {
			if v != value {
				d[key] = value
			}
		}
	}
	return MapCollection{
		value: d,
	}
}

// DiffKeys compares the collection against another collection or a plain PHP array based on its keys.
// This method will return the key / value pairs in the original collection that are not present in the given collection.
func (c MapCollection) DiffKeys(m map[string]interface{}) Collection {
	var d = make(map[string]interface{}, 0)
	for key, value := range c.value {
		if _, ok := m[key]; !ok {
			d[key] = value
		}
	}
	return MapCollection{
		value: d,
	}
}

// Each iterates over the items in the collection and passes each item to a callback.
func (c MapCollection) Each(cb func(item, value interface{}) (interface{}, bool)) Collection {
	var d = make(map[string]interface{}, 0)
	var (
		newValue interface{}
		stop     = false
	)
	for key, value := range c.value {
		if !stop {
			newValue, stop = cb(key, value)
			d[key] = newValue
		} else {
			d[key] = value
		}
	}
	return MapCollection{
		value: d,
	}
}

// Every may be used to verify that all elements of a collection pass a given truth test.
func (c MapCollection) Every(cb CB) bool {
	for key, value := range c.value {
		if !cb(key, value) {
			return false
		}
	}
	return true
}

// Except returns all items in the collection except for those with the specified keys.
func (c MapCollection) Except(keys []string) Collection {
	var d = copyMap(c.value)

	for _, key := range keys {
		delete(d, key)
	}
	return MapCollection{
		value: d,
	}
}

// FlatMap iterates through the collection and passes each value to the given callback.
func (c MapCollection) FlatMap(cb func(value interface{}) interface{}) Collection {
	var d = make(map[string]interface{}, 0)
	for key, value := range c.value {
		d[key] = cb(value)
	}
	return MapCollection{
		value: d,
	}
}

// Flip swaps the collection's keys with their corresponding values.
func (c MapCollection) Flip() Collection {
	var d = make(map[string]interface{}, 0)
	for key, value := range c.value {
		d[fmt.Sprintf("%v", value)] = key
	}
	return MapCollection{
		value: d,
	}
}

// Forget removes an item from the collection by its key.
func (c MapCollection) Forget(k string) Collection {
	var d = copyMap(c.value)

	for key := range c.value {
		if key == k {
			delete(d, key)
		}
	}

	return MapCollection{
		value: d,
	}
}

// Get returns the item at a given key. If the key does not exist, null is returned.
func (c MapCollection) Get(k string, v ...interface{}) interface{} {
	if len(v) > 0 {
		if value, ok := c.value[k]; ok {
			return value
		} else {
			return v[0]
		}
	} else {
		return c.value[k]
	}
}

// Has determines if a given key exists in the collection.
func (c MapCollection) Has(keys ...string) bool {
	for _, key := range keys {
		exist := false
		for kk := range c.value {
			if key == kk {
				exist = true
				break
			}
		}
		if !exist {
			return false
		}
	}
	return true
}

// IntersectByKeys removes any keys from the original collection that are not present in the given array or collection.
func (c MapCollection) IntersectByKeys(m map[string]interface{}) Collection {
	var d = make(map[string]interface{}, 0)
	for key, value := range c.value {
		for kk := range m {
			if kk == key {
				d[kk] = value
			}
		}
	}
	return MapCollection{
		value: d,
	}
}

// IsEmpty returns true if the collection is empty; otherwise, false is returned.
func (c MapCollection) IsEmpty() bool {
	return len(c.value) == 0
}

// IsNotEmpty returns true if the collection is not empty; otherwise, false is returned.
func (c MapCollection) IsNotEmpty() bool {
	return len(c.value) != 0
}

// Keys returns all of the collection's keys.
func (c MapCollection) Keys() Collection {
	var d = make([]string, 0)
	for key := range c.value {
		d = append(d, key)
	}
	return StringArrayCollection{
		value: d,
	}
}

// Merge merges the given array or collection with the original collection. If a string key in the given items
// matches a string key in the original collection, the given items's value will overwrite the value in the
// original collection.
func (c MapCollection) Merge(i interface{}) Collection {
	m := i.(map[string]interface{})
	var d = copyMap(c.value)

	for key, value := range m {
		d[key] = value
	}

	return MapCollection{
		value: d,
	}
}

// ToJson converts the collection into a json string.
func (c MapCollection) ToJson() string {
	s, err := json.Marshal(c.value)
	if err != nil {
		panic(err)
	}
	return string(s)
}
