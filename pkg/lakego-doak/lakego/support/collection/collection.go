package collection

import (
	"encoding/json"
	"fmt"
	"strings"
	"bytes"
	"encoding/gob"

	"github.com/deatil/lakego-doak/lakego/support/decimal"
)

// code from "github.com/chenhg5/collection"
// Collect transforms src into Collection. The src could be json string, []string,
// []map[string]interface{}, map[string]interface{}, []int, []int16, []int32, []int64,
// []float32, []float64, []interface{}.
func Collect(src interface{}) Collection {
	switch val := src.(type) {
	case string:
		jsonStr := strings.TrimSpace(val)
		if jsonStr[0] == '[' {
			var p []interface{}
			if err := json.Unmarshal([]byte(jsonStr), &p); err != nil {
				panic(err)
			}
			return Collect(p)
		}
		if jsonStr[0] == '{' {
			var p map[string]interface{}
			if err := json.Unmarshal([]byte(jsonStr), &p); err != nil {
				panic(err)
			}
			var c MapCollection
			c.value = p
			c.length = len(p)
			return c
		}
		panic("invalid type")
	case []string:
		var c StringArrayCollection
		c.value = val
		c.length = len(val)
		return c
	case []map[string]interface{}:
		var c MapArrayCollection
		c.value = val
		c.length = len(val)
		return c
	case map[string]interface{}:
		var c MapCollection
		c.value = val
		c.length = len(val)
		return c
	case []int:
		var c NumberArrayCollection
		var d = make([]decimal.Decimal, len(val))
		for k, v := range val {
			d[k] = decimal.New(int64(v), 0)
		}
		c.value = d
		c.length = len(val)
		return c
	case []int8:
		var c NumberArrayCollection
		var d = make([]decimal.Decimal, len(val))
		for k, v := range val {
			d[k] = decimal.New(int64(v), 0)
		}
		c.value = d
		c.length = len(val)
		return c
	case []int16:
		var c NumberArrayCollection
		var d = make([]decimal.Decimal, len(val))
		for k, v := range val {
			d[k] = decimal.New(int64(v), 0)
		}
		c.value = d
		c.length = len(val)
		return c
	case []int32:
		var c NumberArrayCollection
		var d = make([]decimal.Decimal, len(val))
		for k, v := range val {
			d[k] = decimal.New(int64(v), 0)
		}
		c.value = d
		c.length = len(val)
		return c
	case []int64:
		var c NumberArrayCollection
		var d = make([]decimal.Decimal, len(val))
		for k, v := range val {
			d[k] = decimal.New(v, 0)
		}
		c.value = d
		c.length = len(val)
		return c
	case []float32:
		var c NumberArrayCollection
		var f = make([]decimal.Decimal, len(val))
		for k, v := range val {
			f[k] = decimal.NewFromFloat32(v)
		}
		c.value = f
		c.length = len(val)
		return c
	case []float64:
		var c NumberArrayCollection
		var f = make([]decimal.Decimal, len(val))
		for k, v := range val {
			f[k] = decimal.NewFromFloat(v)
		}
		c.value = f
		c.length = len(val)
		return c
	case []interface{}:
		if len(val) == 0 {
			panic("wrong value")
		}
		switch val[0].(type) {
		case map[string]interface{}:
			var c MapArrayCollection
			var f = make([]map[string]interface{}, len(val))
			for k, v := range val {
				f[k] = v.(map[string]interface{})
			}
			c.value = f
			c.length = len(val)
			return c
		case decimal.Decimal:
			var c NumberArrayCollection
			var f = make([]decimal.Decimal, len(val))
			for k, v := range val {
				f[k] = v.(decimal.Decimal)
			}
			c.value = f
			c.length = len(val)
			return c
		case string:
			var c StringArrayCollection
			var f = make([]string, len(val))
			for k, v := range val {
				f[k] = v.(string)
			}
			c.value = f
			c.length = len(val)
			return c
		case uint8:
			var c StringArrayCollection
			var f = make([]string, len(val))
			for k, v := range val {
				f[k] = string(v.([]uint8))
			}
			c.value = f
			c.length = len(val)
			return c
		case int:
			var c NumberArrayCollection
			var d = make([]decimal.Decimal, len(val))
			for k, v := range val {
				d[k] = decimal.New(int64(v.(int)), 0)
			}
			c.value = d
			c.length = len(val)
			return c
		case int8:
			var c NumberArrayCollection
			var d = make([]decimal.Decimal, len(val))
			for k, v := range val {
				d[k] = decimal.New(int64(v.(int8)), 0)
			}
			c.value = d
			c.length = len(val)
			return c
		case int16:
			var c NumberArrayCollection
			var d = make([]decimal.Decimal, len(val))
			for k, v := range val {
				d[k] = decimal.New(int64(v.(int16)), 0)
			}
			c.value = d
			c.length = len(val)
			return c
		case int32:
			var c NumberArrayCollection
			var d = make([]decimal.Decimal, len(val))
			for k, v := range val {
				d[k] = decimal.New(int64(v.(int32)), 0)
			}
			c.value = d
			c.length = len(val)
			return c
		case int64:
			var c NumberArrayCollection
			var d = make([]decimal.Decimal, len(val))
			for k, v := range val {
				d[k] = decimal.New(v.(int64), 0)
			}
			c.value = d
			c.length = len(val)
			return c
		case float32:
			var c NumberArrayCollection
			var f = make([]decimal.Decimal, len(val))
			for k, v := range val {
				f[k] = decimal.NewFromFloat32(v.(float32))
			}
			c.value = f
			c.length = len(val)
			return c
		case float64:
			var c NumberArrayCollection
			var f = make([]decimal.Decimal, len(val))
			for k, v := range val {
				f[k] = decimal.NewFromFloat(v.(float64))
			}
			c.value = f
			c.length = len(val)
			return c
		default:
			panic("wrong type")
		}
	default:
		panic("wrong type")
	}
}

type Collection interface {
	Value() interface{}

	// All returns the underlying array represented by the collection.
	All() []interface{}

	// Length return the length of the collection.
	Length() int

	// ToStruct turn the collection to the specified struct using mapstructure.
	// https://github.com/mitchellh/mapstructure
	ToStruct(dist interface{})

	// Select select the keys of collection and delete others.
	Select(keys ...string) Collection

	// Avg returns the average value of a given key.
	Avg(key ...string) decimal.Decimal

	// Sum returns the sum of all items in the collection.
	Sum(key ...string) decimal.Decimal

	// Min returns the minimum value of a given key.
	Min(key ...string) decimal.Decimal

	// Max returns the maximum value of a given key.
	Max(key ...string) decimal.Decimal

	// Join joins the collection's values with a string.
	Join(delimiter string) string

	// Combine combines the values of the collection, as keys, with the values of another array or collection.
	Combine(value []interface{}) Collection

	// Count returns the total number of items in the collection.
	Count() int

	// Pluck retrieves all of the values for a given key.
	Pluck(key string) Collection

	// Mode returns the mode value of a given key.
	Mode(key ...string) []interface{}

	// Only returns the items in the collection with the specified keys.
	Only(keys []string) Collection

	// Prepend adds an item to the beginning of the collection.
	Prepend(values ...interface{}) Collection

	// Pull removes and returns an item from the collection by its key.
	Pull(key interface{}) Collection

	// Put sets the given key and value in the collection:.
	Put(key string, value interface{}) Collection

	// SortBy sorts the collection by the given key.
	SortBy(key string) Collection

	// Take returns a new collection with the specified number of items.
	Take(num int) Collection

	// Chunk breaks the collection into multiple, smaller collections of a given size.
	Chunk(num int) MultiDimensionalArrayCollection

	// Collapse collapses a collection of arrays into a single, flat collection.
	Collapse() Collection

	// Concat appends the given array or collection values onto the end of the collection.
	Concat(value interface{}) Collection

	// Contains determines whether the collection contains a given item.
	Contains(value ...interface{}) bool

	// CountBy counts the occurrences of values in the collection. By default, the method counts the occurrences of every element.
	CountBy(callback ...interface{}) map[interface{}]int

	// CrossJoin cross joins the collection's values among the given arrays or collections, returning a Cartesian product with all possible permutations.
	CrossJoin(array ...[]interface{}) MultiDimensionalArrayCollection

	// Dd dumps the collection's items and ends execution of the script.
	Dd()

	// Diff compares the collection against another collection or a plain PHP array based on its values.
	// This method will return the values in the original collection that are not present in the given collection.
	Diff(interface{}) Collection

	// DiffAssoc compares the collection against another collection or a plain PHP  array based on its keys and values.
	// This method will return the key / value pairs in the original collection that are not present in the given collection.
	DiffAssoc(map[string]interface{}) Collection

	// DiffKeys compares the collection against another collection or a plain PHP array based on its keys.
	// This method will return the key / value pairs in the original collection that are not present in the given collection.
	DiffKeys(map[string]interface{}) Collection

	// Dump dumps the collection's items.
	Dump()

	// Each iterates over the items in the collection and passes each item to a callback.
	Each(func(item, value interface{}) (interface{}, bool)) Collection

	// Every may be used to verify that all elements of a collection pass a given truth test.
	Every(CB) bool

	// Except returns all items in the collection except for those with the specified keys.
	Except([]string) Collection

	// Filter filters the collection using the given callback, keeping only those items that pass a given truth test.
	Filter(CB) Collection

	// First returns the first element in the collection that passes a given truth test.
	First(...CB) interface{}

	// FirstWhere returns the first element in the collection with the given key / value pair.
	FirstWhere(key string, values ...interface{}) map[string]interface{}

	// FlatMap iterates through the collection and passes each value to the given callback.
	FlatMap(func(value interface{}) interface{}) Collection

	// Flip swaps the collection's keys with their corresponding values.
	Flip() Collection

	// Forget removes an item from the collection by its key.
	Forget(string) Collection

	// ForPage returns a new collection containing the items that would be present on a given page number.
	ForPage(int, int) Collection

	// Get returns the item at a given key. If the key does not exist, null is returned.
	Get(string, ...interface{}) interface{}

	// GroupBy groups the collection's items by a given key.
	GroupBy(string) Collection

	// Has determines if a given key exists in the collection.
	Has(...string) bool

	// Implode joins the items in a collection. Its arguments depend on the type of items in the collection.
	Implode(string, string) string

	// Intersect removes any values from the original collection that are not present in the given array or collection.
	Intersect([]string) Collection

	// IntersectByKeys removes any keys from the original collection that are not present in the given array or collection.
	IntersectByKeys(map[string]interface{}) Collection

	// IsEmpty returns true if the collection is empty; otherwise, false is returned.
	IsEmpty() bool

	// IsNotEmpty returns true if the collection is not empty; otherwise, false is returned.
	IsNotEmpty() bool

	// KeyBy keys the collection by the given key. If multiple items have the same key, only the last one will
	// appear in the new collection.
	KeyBy(interface{}) Collection

	// Keys returns all of the collection's keys.
	Keys() Collection

	// Last returns the last element in the collection that passes a given truth test.
	Last(...CB) interface{}

	// MapToGroups groups the collection's items by the given callback.
	MapToGroups(MapCB) Collection

	// MapWithKeys iterates through the collection and passes each value to the given callback.
	MapWithKeys(MapCB) Collection

	// Median returns the median value of a given key.
	Median(...string) decimal.Decimal

	// Merge merges the given array or collection with the original collection. If a string key in the given items
	// matches a string key in the original collection, the given items's value will overwrite the value in the
	// original collection.
	Merge(interface{}) Collection

	// Pad will fill the array with the given value until the array reaches the specified size.
	Pad(int, interface{}) Collection

	// Partition separate elements that pass a given truth test from those that do not.
	Partition(PartCB) (Collection, Collection)

	// Pop removes and returns the last item from the collection.
	Pop() interface{}

	// Push appends an item to the end of the collection.
	Push(interface{}) Collection

	// Random returns a random item from the collection.
	Random(...int) Collection

	// Reduce reduces the collection to a single value, passing the result of each iteration into the subsequent iteration.
	Reduce(ReduceCB) interface{}

	// Reject filters the collection using the given callback.
	Reject(CB) Collection

	// Reverse reverses the order of the collection's items, preserving the original keys.
	Reverse() Collection

	// Search searches the collection for the given value and returns its key if found. If the item is not found,
	// -1 is returned.
	Search(interface{}) int

	// Shift removes and returns the first item from the collection.
	Shift() Collection

	// Shuffle randomly shuffles the items in the collection.
	Shuffle() Collection

	// Slice returns a slice of the collection starting at the given index.
	Slice(...int) Collection

	// Sort sorts the collection.
	Sort() Collection

	// SortByDesc has the same signature as the sortBy method, but will sort the collection in the opposite order.
	SortByDesc() Collection

	// Splice removes and returns a slice of items starting at the specified index.
	Splice(index ...int) Collection

	// Split breaks a collection into the given number of groups.
	Split(int) Collection

	// Unique returns all of the unique items in the collection.
	Unique() Collection

	// WhereIn filters the collection by a given key / value contained within the given array.
	WhereIn(string, []interface{}) Collection

	// WhereNotIn filters the collection by a given key / value not contained within the given array.
	WhereNotIn(string, []interface{}) Collection

	// ToJson converts the collection into a json string.
	ToJson() string

	// ToNumberArray converts the collection into a plain golang slice which contains decimal.Decimal.
	ToNumberArray() []decimal.Decimal

	// ToIntArray converts the collection into a plain golang slice which contains int.
	ToIntArray() []int

	// ToInt64Array converts the collection into a plain golang slice which contains int.
	ToInt64Array() []int64

	// ToStringArray converts the collection into a plain golang slice which contains string.
	ToStringArray() []string

	// ToMultiDimensionalArray converts the collection into a multi dimensional array.
	ToMultiDimensionalArray() [][]interface{}

	// ToMap converts the collection into a plain golang map.
	ToMap() map[string]interface{}

	// ToMapArray converts the collection into a plain golang slice which contains map.
	ToMapArray() []map[string]interface{}

	// Where filters the collection by a given key / value pair.
	Where(key string, values ...interface{}) Collection
}

func newDecimalFromInterface(a interface{}) decimal.Decimal {
	var d decimal.Decimal

	switch a.(type) {
	case uint:
		d = decimal.New(int64(a.(uint)), 0)
	case uint8:
		d = decimal.New(int64(a.(uint8)), 0)
	case uint16:
		d = decimal.New(int64(a.(uint16)), 0)
	case uint32:
		d = decimal.New(int64(a.(uint32)), 0)
	case uint64:
		d = decimal.New(int64(a.(uint64)), 0)
	case int:
		d = decimal.New(int64(a.(int)), 0)
	case int8:
		d = decimal.New(int64(a.(int8)), 0)
	case int16:
		d = decimal.New(int64(a.(int16)), 0)
	case int32:
		d = decimal.New(int64(a.(int32)), 0)
	case int64:
		d = decimal.New(a.(int64), 0)
	case float32:
		d = decimal.NewFromFloat32(a.(float32))
	case float64:
		d = decimal.NewFromFloat(a.(float64))
	default:
		panic("wrong type")
	}

	return d
}

func isTrue(a interface{}) bool {
	switch a.(type) {
	case uint:
		return a.(uint) != uint(0)
	case uint8:
		return a.(uint8) != uint8(0)
	case uint16:
		return a.(uint16) != uint16(0)
	case uint32:
		return a.(uint32) != uint32(0)
	case uint64:
		return a.(uint64) != uint64(0)
	case int:
		return a.(int) != int(0)
	case int8:
		return a.(int8) != int8(0)
	case int16:
		return a.(int16) != int16(0)
	case int32:
		return a.(int32) != int32(0)
	case int64:
		return a.(int64) != int64(0)
	case float32:
		return a.(float32) != float32(0)
	case float64:
		return a.(float64) != float64(0)
	case string:
		return a.(string) != ""
	case bool:
		return a.(bool)
	default:
		return false
	}
}

func nd(a interface{}) decimal.Decimal {
	return newDecimalFromInterface(a)
}

type CB func(item, value interface{}) bool
type FilterFun func(value interface{}) interface{}
type MapCB func(map[string]interface{}) (string, interface{})
type PartCB func(int) bool
type ReduceCB func(interface{}, interface{}) interface{}

func copyMap(m map[string]interface{}) map[string]interface{} {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	dec := gob.NewDecoder(&buf)
	err := enc.Encode(m)
	if err != nil {
		panic(err)
	}
	var cm map[string]interface{}
	err = dec.Decode(&cm)
	if err != nil {
		panic(err)
	}
	return cm
}

func dd(c Collection) {
	fmt.Println(c)
}

func dump(c Collection) {
	fmt.Println(c)
}

func newDecimalArray(src interface{}) []decimal.Decimal {
	switch src.(type) {
	case []int:
		var d = make([]decimal.Decimal, len(src.([]int)))
		for k, v := range src.([]int) {
			d[k] = decimal.New(int64(v), 0)
		}
		return d
	case []int8:
		var d = make([]decimal.Decimal, len(src.([]int8)))
		for k, v := range src.([]int8) {
			d[k] = decimal.New(int64(v), 0)
		}
		return d
	case []int16:
		var d = make([]decimal.Decimal, len(src.([]int16)))
		for k, v := range src.([]int16) {
			d[k] = decimal.New(int64(v), 0)
		}
		return d
	case []int32:
		var d = make([]decimal.Decimal, len(src.([]int32)))
		for k, v := range src.([]int32) {
			d[k] = decimal.New(int64(v), 0)
		}
		return d
	case []int64:
		var d = make([]decimal.Decimal, len(src.([]int64)))
		for k, v := range src.([]int64) {
			d[k] = decimal.New(v, 0)
		}
		return d
	case []float32:
		var f = make([]decimal.Decimal, len(src.([]float32)))
		for k, v := range src.([]float32) {
			f[k] = decimal.NewFromFloat32(v)
		}
		return f
	case []float64:
		var f = make([]decimal.Decimal, len(src.([]float64)))
		for k, v := range src.([]float64) {
			f[k] = decimal.NewFromFloat(v)
		}
		return f
	default:
		return nil
	}
}

func qsort(arr []decimal.Decimal, order bool) []decimal.Decimal {
	if len(arr) < 2 {
		return arr
	} else {
		pivot := arr[0]
		var less []decimal.Decimal
		var greater []decimal.Decimal
		for _, value := range arr[1:] {
			if value.LessThanOrEqual(pivot) {
				less = append(less, value)
			} else {
				greater = append(greater, value)
			}
		}

		var result []decimal.Decimal
		if order {
			result = append(result, qsort(less, order)...)
			result = append(result, pivot)
			result = append(result, qsort(greater, order)...)
		} else {
			result = append(result, qsort(greater, order)...)
			result = append(result, pivot)
			result = append(result, qsort(less, order)...)
		}

		return result
	}
}
