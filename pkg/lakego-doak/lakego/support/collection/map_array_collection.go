package collection

import (
	"fmt"
	"math"
	"math/rand"
	"time"
	"encoding/json"
    
	"github.com/deatil/lakego-doak/lakego/support/decimal"
	"github.com/deatil/lakego-doak/lakego/support/mapstructure"
)

type MapArrayCollection struct {
	value []map[string]interface{}
	BaseCollection
}

// Sum returns the sum of all items in the collection.
func (c MapArrayCollection) Sum(key ...string) decimal.Decimal {
	var sum = decimal.New(0, 0)

	for i := 0; i < len(c.value); i++ {
		sum = sum.Add(nd(c.value[i][key[0]]))
	}

	return sum
}

// Length return the length of the collection.
func (c MapArrayCollection) Length() int {
	return len(c.value)
}

// ToStruct turn the collection to the specified struct using mapstructure.
// https://github.com/mitchellh/mapstructure
func (c MapArrayCollection) ToStruct(dist interface{}) {
	if err := mapstructure.Decode(c.value, dist); err != nil {
		panic(err)
	}
}

// Select select the keys of collection and delete others.
func (c MapArrayCollection) Select(keys ...string) Collection {
	var n = make([]map[string]interface{}, len(c.value))
	copy(n, c.value)

	for _, value := range n {
		for k := range value {
			exist := false
			for i := 0; i < len(keys); i++ {
				if keys[i] == k {
					exist = true
					break
				}
			}
			if !exist {
				delete(value, k)
			}
		}
	}

	return MapArrayCollection{
		value: n,
	}
}

// Sum returns the sum of all items in the collection.
func (c MapArrayCollection) Avg(key ...string) decimal.Decimal {
	var sum = decimal.New(0, 0)

	for i := 0; i < len(c.value); i++ {
		sum = sum.Add(nd(c.value[i][key[0]]))
	}

	return sum.Div(nd(len(c.value)))
}

// Median returns the median value of a given key.
func (c MapArrayCollection) Median(key ...string) decimal.Decimal {
	var f = make([]decimal.Decimal, len(c.value))
	for i := 0; i < len(c.value); i++ {
		f = append(f, nd(c.value[i][key[0]]))
	}
	f = qsort(f, true)
	return f[len(f)/2].Add(f[len(f)/2-1]).Div(nd(2))
}

// Min returns the minimum value of a given key.
func (c MapArrayCollection) Min(key ...string) decimal.Decimal {

	var (
		smallest = decimal.New(0, 0)
		number   decimal.Decimal
	)

	for i := 0; i < len(c.value); i++ {
		number = nd(c.value[i][key[0]])
		if i == 0 {
			smallest = number
			continue
		}
		if smallest.GreaterThan(number) {
			smallest = number
		}
	}

	return smallest
}

// Max returns the maximum value of a given key.
func (c MapArrayCollection) Max(key ...string) decimal.Decimal {

	var (
		biggest = decimal.New(0, 0)
		number  decimal.Decimal
	)

	for i := 0; i < len(c.value); i++ {
		number = nd(c.value[i][key[0]])
		if i == 0 {
			biggest = number
			continue
		}
		if biggest.LessThan(number) {
			biggest = number
		}
	}

	return biggest
}

// Pluck retrieves all of the values for a given key.
func (c MapArrayCollection) Pluck(key string) Collection {
	var s = make([]interface{}, 0)
	for i := 0; i < len(c.value); i++ {
		s = append(s, c.value[i][key])
	}
	return Collect(s)
}

// Each iterates over the items in the collection and passes each item to a callback.
func (c MapArrayCollection) Each(cb func(item, value interface{}) (interface{}, bool)) Collection {
	var d = make([]map[string]interface{}, 0)
	var (
		newValue interface{}
		stop     = false
	)
	for key, value := range c.value {
		if !stop {
			newValue, stop = cb(key, value)
			d = append(d, newValue.(map[string]interface{}))
		} else {
			d = append(d, value)
		}
	}
	return MapArrayCollection{
		value: d,
	}
}

// Prepend adds an item to the beginning of the collection.
func (c MapArrayCollection) Prepend(values ...interface{}) Collection {

	var d MapArrayCollection

	var n = make([]map[string]interface{}, len(c.value))
	copy(n, c.value)

	d.value = append([]map[string]interface{}{values[0].(map[string]interface{})}, n...)
	d.length = len(d.value)

	return d
}

// Only returns the items in the collection with the specified keys.
func (c MapArrayCollection) Only(keys []string) Collection {
	var d MapArrayCollection

	var ma = make([]map[string]interface{}, 0)
	for _, k := range keys {
		m := make(map[string]interface{}, 0)
		for _, v := range c.value {
			m[k] = v[k]
		}
		ma = append(ma, m)
	}
	d.value = ma
	d.length = len(ma)

	return d
}

// Splice removes and returns a slice of items starting at the specified index.
func (c MapArrayCollection) Splice(index ...int) Collection {

	if len(index) == 1 {
		var n = make([]map[string]interface{}, len(c.value))
		copy(n, c.value)
		n = n[index[0]:]

		return MapArrayCollection{n, BaseCollection{length: len(n)}}
	} else if len(index) > 1 {
		var n = make([]map[string]interface{}, len(c.value))
		copy(n, c.value)
		n = n[index[0] : index[0]+index[1]]

		return MapArrayCollection{n, BaseCollection{length: len(n)}}
	} else {
		panic("invalid argument")
	}
}

// Take returns a new collection with the specified number of items.
func (c MapArrayCollection) Take(num int) Collection {
	var d MapArrayCollection
	if num > c.length {
		panic("not enough elements to take")
	}

	if num >= 0 {
		d.value = c.value[:num]
		d.length = num
	} else {
		d.value = c.value[len(c.value)+num:]
		d.length = 0 - num
	}

	return d
}

// All returns the underlying array represented by the collection.
func (c MapArrayCollection) All() []interface{} {
	s := make([]interface{}, len(c.value))
	for i := 0; i < len(c.value); i++ {
		s[i] = c.value[i]
	}

	return s
}

// Mode returns the mode value of a given key.
func (c MapArrayCollection) Mode(key ...string) []interface{} {
	valueCount := make(map[interface{}]int)
	for i := 0; i < c.length; i++ {
		if v, ok := c.value[i][key[0]]; ok {
			valueCount[v]++
		}
	}

	maxCount := 0
	maxValue := make([]interface{}, len(valueCount))
	for v, c := range valueCount {
		switch {
		case c < maxCount:
			continue
		case c == maxCount:
			maxValue = append(maxValue, v)
		case c > maxCount:
			maxValue = append([]interface{}{}, v)
			maxCount = c
		}
	}
	return maxValue
}

// ToMapArray converts the collection into a plain golang slice which contains map.
func (c MapArrayCollection) ToMapArray() []map[string]interface{} {
	return c.value
}

// Chunk breaks the collection into multiple, smaller collections of a given size.
func (c MapArrayCollection) Chunk(num int) MultiDimensionalArrayCollection {
	var d MultiDimensionalArrayCollection
	d.length = c.length/num + 1
	d.value = make([][]interface{}, d.length)

	count := 0
	for i := 1; i <= c.length; i++ {
		switch {
		case i == c.length:
			if i%num == 0 {
				d.value[count] = c.All()[i-num:]
				d.value = d.value[:d.length-1]
			} else {
				d.value[count] = c.All()[i-i%num:]
			}
		case i%num != 0 || i < num:
			continue
		default:
			d.value[count] = c.All()[i-num : i]
			count++
		}
	}

	return d
}

// Concat appends the given array or collection values onto the end of the collection.
func (c MapArrayCollection) Concat(value interface{}) Collection {
	return MapArrayCollection{
		value:          append(c.value, value.([]map[string]interface{})...),
		BaseCollection: BaseCollection{length: c.length + len(value.([]map[string]interface{}))},
	}
}

// CrossJoin cross joins the collection's values among the given arrays or collections, returning a Cartesian product with all possible permutations.
func (c MapArrayCollection) CrossJoin(array ...[]interface{}) MultiDimensionalArrayCollection {
	var d MultiDimensionalArrayCollection

	// A two-dimensional-slice's initial
	length := len(c.value)
	for _, s := range array {
		length *= len(s)
	}
	value := make([][]interface{}, length)
	for i := range value {
		value[i] = make([]interface{}, len(array)+1)
	}

	offset := length / c.length
	for i := 0; i < length; i++ {
		value[i][0] = c.value[i/offset]
	}
	assignmentToValue(value, array, length, 1, 0, offset)

	d.value = value
	d.length = length
	return d
}

// vl: length of value
// ai: index of array
// si: index of value's sub-array
func assignmentToValue(value, array [][]interface{}, vl, si, ai, preOffset int) {
	offset := preOffset / len(array[ai])
	times := 0

	for i := 0; i < vl; i++ {
		if i >= preOffset && i%preOffset == 0 {
			times++
		}
		value[i][si] = array[ai][(i-preOffset*times)/offset]
	}

	if ai < len(array)-1 {
		assignmentToValue(value, array, vl, si+1, ai+1, offset)
	}
}

// Dd dumps the collection's items and ends execution of the script.
func (c MapArrayCollection) Dd() {
	dd(c)
}

// Dump dumps the collection's items.
func (c MapArrayCollection) Dump() {
	dump(c)
}

// Every may be used to verify that all elements of a collection pass a given truth test.
func (c MapArrayCollection) Every(cb CB) bool {
	for key, value := range c.value {
		if !cb(key, value) {
			return false
		}
	}
	return true
}

// Filter filters the collection using the given callback, keeping only those items that pass a given truth test.
func (c MapArrayCollection) Filter(cb CB) Collection {
	var d = make([]map[string]interface{}, 0)
	copy(d, c.value)
	for key, value := range c.value {
		if !cb(key, value) {
			d = append(d[:key], d[key+1:]...)
		}
	}
	return MapArrayCollection{
		value: d,
	}
}

// First returns the first element in the collection that passes a given truth test.
func (c MapArrayCollection) First(cbs ...CB) interface{} {
	if len(cbs) > 0 {
		for key, value := range c.value {
			if cbs[0](key, value) {
				return value
			}
		}
		return nil
	} else {
		if len(c.value) > 0 {
			return c.value[0]
		} else {
			return nil
		}
	}
}

// FirstWhere returns the first element in the collection with the given key / value pair.
func (c MapArrayCollection) FirstWhere(key string, values ...interface{}) map[string]interface{} {
	if len(values) < 1 {
		for _, value := range c.value {
			if isTrue(value[key]) {
				return value
			}
		}
	} else if len(values) < 2 {
		for _, value := range c.value {
			if value[key] == values[0] {
				return value
			}
		}
	} else {
		switch values[0].(string) {
		case ">":
			for _, value := range c.value {
				if nd(value[key]).GreaterThan(nd(values[1])) {
					return value
				}
			}
		case ">=":
			for _, value := range c.value {
				if nd(value[key]).GreaterThanOrEqual(nd(values[1])) {
					return value
				}
			}
		case "<":
			for _, value := range c.value {
				if nd(value[key]).LessThan(nd(values[1])) {
					return value
				}
			}
		case "<=":
			for _, value := range c.value {
				if nd(value[key]).LessThanOrEqual(nd(values[1])) {
					return value
				}
			}
		case "=":
			for _, value := range c.value {
				if value[key] == values[1] {
					return value
				}
			}
		}
	}
	return map[string]interface{}{}
}

// GroupBy groups the collection's items by a given key.
func (c MapArrayCollection) GroupBy(k string) Collection {
	var d = make(map[string]interface{}, 0)
	for _, value := range c.value {
		for kk, vv := range value {
			if kk == k {
				vvKey := fmt.Sprintf("%v", vv)
				if _, ok := d[vvKey]; ok {
					am := d[vvKey].([]map[string]interface{})
					am = append(am, value)
					d[vvKey] = am
				} else {
					d[vvKey] = []map[string]interface{}{value}
				}
			}
		}
	}
	return MapCollection{
		value: d,
	}
}

// Implode joins the items in a collection. Its arguments depend on the type of items in the collection.
func (c MapArrayCollection) Implode(key string, delimiter string) string {
	var res = ""
	for _, value := range c.value {
		for kk, vv := range value {
			if kk == key {
				res += fmt.Sprintf("%v", vv) + delimiter
			}
		}
	}
	return res[:len(res)-1]
}

// IsEmpty returns true if the collection is empty; otherwise, false is returned.
func (c MapArrayCollection) IsEmpty() bool {
	return len(c.value) == 0
}

// IsNotEmpty returns true if the collection is not empty; otherwise, false is returned.
func (c MapArrayCollection) IsNotEmpty() bool {
	return len(c.value) != 0
}

// KeyBy keys the collection by the given key. If multiple items have the same key, only the last one will
// appear in the new collection.
func (c MapArrayCollection) KeyBy(v interface{}) Collection {
	var d = make(map[string]interface{}, 0)
	if k, ok := v.(string); ok {
		for _, value := range c.value {
			for kk, vv := range value {
				if kk == k {
					d[fmt.Sprintf("%v", vv)] = []map[string]interface{}{value}
				}
			}
		}
	} else {
		vb := v.(FilterFun)
		for _, value := range c.value {
			for kk, vv := range value {
				if kk == k {
					d[fmt.Sprintf("%v", vb(vv))] = []map[string]interface{}{value}
				}
			}
		}
	}
	return MapCollection{
		value: d,
	}
}

// Last returns the last element in the collection that passes a given truth test.
func (c MapArrayCollection) Last(cbs ...CB) interface{} {
	if len(cbs) > 0 {
		var last interface{}
		for key, value := range c.value {
			if cbs[0](key, value) {
				last = value
			}
		}
		return last
	} else {
		if len(c.value) > 0 {
			return c.value[len(c.value)-1]
		} else {
			return nil
		}
	}
}

// MapToGroups groups the collection's items by the given callback.
func (c MapArrayCollection) MapToGroups(cb MapCB) Collection {
	var d = make(map[string]interface{}, 0)
	for _, value := range c.value {
		nk, nv := cb(value)
		if _, ok := d[nk]; ok {
			am := d[nk].([]interface{})
			am = append(am, nv)
			d[nk] = am
		} else {
			d[nk] = []interface{}{nv}
		}
	}
	return MapCollection{
		value: d,
	}
}

// MapWithKeys iterates through the collection and passes each value to the given callback.
func (c MapArrayCollection) MapWithKeys(cb MapCB) Collection {
	var d = make(map[string]interface{}, 0)
	for _, value := range c.value {
		nk, nv := cb(value)
		d[nk] = nv
	}
	return MapCollection{
		value: d,
	}
}

// Partition separate elements that pass a given truth test from those that do not.
func (c MapArrayCollection) Partition(cb PartCB) (Collection, Collection) {
	var d1 = make([]map[string]interface{}, 0)
	var d2 = make([]map[string]interface{}, 0)

	for i := 0; i < len(c.value); i++ {
		if cb(i) {
			d1 = append(d1, c.value[i])
		} else {
			d2 = append(d2, c.value[i])
		}
	}

	return MapArrayCollection{
		value: d1,
	}, MapArrayCollection{
		value: d2,
	}
}

// Pop removes and returns the last item from the collection.
func (c MapArrayCollection) Pop() interface{} {
	last := c.value[len(c.value)-1]
	c.value = c.value[:len(c.value)-1]
	return last
}

// Push appends an item to the end of the collection.
func (c MapArrayCollection) Push(v interface{}) Collection {
	var d = make([]map[string]interface{}, len(c.value)+1)
	for i := 0; i < len(d); i++ {
		if i < len(c.value) {
			d[i] = c.value[i]
		} else {
			d[i] = v.(map[string]interface{})
		}
	}

	return MapArrayCollection{
		value: d,
	}
}

// Random returns a random item from the collection.
func (c MapArrayCollection) Random(num ...int) Collection {
	if len(num) == 0 {
		return BaseCollection{
			value: c.value[rand.Intn(len(c.value))],
		}
	} else {
		if num[0] > len(c.value) {
			panic("wrong num")
		}
		var d = make([]map[string]interface{}, len(c.value))
		copy(d, c.value)
		for i := 0; i < len(c.value)-num[0]; i++ {
			index := rand.Intn(len(d))
			d = append(d[:index], d[index+1:]...)
		}
		return MapArrayCollection{
			value: d,
		}
	}
}

// Reduce reduces the collection to a single value, passing the result of each iteration into the subsequent iteration.
func (c MapArrayCollection) Reduce(cb ReduceCB) interface{} {
	var res interface{}

	for i := 0; i < len(c.value); i++ {
		res = cb(res, c.value[i])
	}

	return res
}

// Reject filters the collection using the given callback.
func (c MapArrayCollection) Reject(cb CB) Collection {
	var d = make([]map[string]interface{}, 0)
	for key, value := range c.value {
		if !cb(key, value) {
			d = append(d, value)
		}
	}
	return MapArrayCollection{
		value: d,
	}
}

// Reverse reverses the order of the collection's items, preserving the original keys.
func (c MapArrayCollection) Reverse() Collection {
	var d = make([]map[string]interface{}, len(c.value))
	j := 0
	for i := len(c.value) - 1; i > -1; i-- {
		d[j] = c.value[i]
		j++
	}
	return MapArrayCollection{
		value: d,
	}
}

// Search searches the collection for the given value and returns its key if found. If the item is not found,
// -1 is returned.
func (c MapArrayCollection) Search(v interface{}) int {
	cb := v.(CB)
	for i := 0; i < len(c.value); i++ {
		if cb(i, c.value[i]) {
			return i
		}
	}
	return -1
}

// Shift removes and returns the first item from the collection.
func (c MapArrayCollection) Shift() Collection {
	var d = make([]map[string]interface{}, len(c.value))
	copy(d, c.value)
	d = d[1:]
	return MapArrayCollection{
		value: d,
	}
}

// Shuffle randomly shuffles the items in the collection.
func (c MapArrayCollection) Shuffle() Collection {
	var d = make([]map[string]interface{}, len(c.value))
	copy(d, c.value)
	rand.Seed(time.Now().UnixNano())
	rand.Shuffle(len(c.value), func(i, j int) { d[i], d[j] = d[j], d[i] })
	return MapArrayCollection{
		value: d,
	}
}

// Slice returns a slice of the collection starting at the given index.
func (c MapArrayCollection) Slice(keys ...int) Collection {
	var d = make([]map[string]interface{}, len(c.value))
	copy(d, c.value)
	if len(keys) == 1 {
		return MapArrayCollection{
			value: d[keys[0]:],
		}
	} else {
		return MapArrayCollection{
			value: d[keys[0] : keys[0]+keys[1]],
		}
	}
}

// Split breaks a collection into the given number of groups.
func (c MapArrayCollection) Split(num int) Collection {
	var d = make([][]interface{}, int(math.Ceil(float64(len(c.value))/float64(num))))

	j := -1
	for i := 0; i < len(c.value); i++ {
		if i%num == 0 {
			j++
			if i+num <= len(c.value) {
				d[j] = make([]interface{}, num)
			} else {
				d[j] = make([]interface{}, len(c.value)-i)
			}
			d[j][i%num] = c.value[i]
		} else {
			d[j][i%num] = c.value[i]
		}
	}

	return MultiDimensionalArrayCollection{
		value: d,
	}
}

// WhereIn filters the collection by a given key / value contained within the given array.
func (c MapArrayCollection) WhereIn(key string, in []interface{}) Collection {
	var d = make([]map[string]interface{}, 0)
	for i := 0; i < len(c.value); i++ {
		for j := 0; j < len(in); j++ {
			if c.value[i][key] == in[j] {
				d = append(d, copyMap(c.value[i]))
				break
			}
		}
	}
	return MapArrayCollection{
		value: d,
	}
}

// WhereNotIn filters the collection by a given key / value not contained within the given array.
func (c MapArrayCollection) WhereNotIn(key string, in []interface{}) Collection {
	var d = make([]map[string]interface{}, 0)
	for i := 0; i < len(c.value); i++ {
		isIn := false
		for j := 0; j < len(in); j++ {
			if c.value[i][key] == in[j] {
				isIn = true
				break
			}
		}
		if !isIn {
			d = append(d, copyMap(c.value[i]))
		}
	}
	return MapArrayCollection{
		value: d,
	}
}

// Where filters the collection by a given key / value pair.
func (c MapArrayCollection) Where(key string, values ...interface{}) Collection {
	var d = make([]map[string]interface{}, 0)
	if len(values) < 1 {
		for _, value := range c.value {
			if isTrue(value[key]) {
				d = append(d, copyMap(value))
			}
		}
	} else if len(values) < 2 {
		for _, value := range c.value {
			if value[key] == values[0] {
				d = append(d, copyMap(value))
			}
		}
	} else {
		switch values[0].(string) {
		case ">":
			for _, value := range c.value {
				if nd(value[key]).GreaterThan(nd(values[1])) {
					d = append(d, copyMap(value))
				}
			}
		case ">=":
			for _, value := range c.value {
				if nd(value[key]).GreaterThanOrEqual(nd(values[1])) {
					d = append(d, copyMap(value))
				}
			}
		case "<":
			for _, value := range c.value {
				if nd(value[key]).LessThan(nd(values[1])) {
					d = append(d, copyMap(value))
				}
			}
		case "<=":
			for _, value := range c.value {
				if nd(value[key]).LessThanOrEqual(nd(values[1])) {
					d = append(d, copyMap(value))
				}
			}
		case "=":
			for _, value := range c.value {
				if value[key] == values[1] {
					d = append(d, copyMap(value))
				}
			}
		}
	}
	return MapArrayCollection{
		value: d,
	}
}

// ToJson converts the collection into a json string.
func (c MapArrayCollection) ToJson() string {
	s, err := json.Marshal(c.value)
	if err != nil {
		panic(err)
	}
	return string(s)
}
