package collection

import (
	"encoding/json"
	"math"
	"math/rand"
	"time"
)

type StringArrayCollection struct {
	value []string
	BaseCollection
}

// Join joins the collection's values with a string.
func (c StringArrayCollection) Join(delimiter string) string {
	s := ""
	for i := 0; i < len(c.value); i++ {
		if i != len(c.value)-1 {
			s += c.value[i] + delimiter
		} else {
			s += c.value[i]
		}
	}
	return s
}

// Length return the length of the collection.
func (c StringArrayCollection) Length() int {
	return len(c.value)
}

// Combine combines the values of the collection, as keys, with the values of another array or collection.
func (c StringArrayCollection) Combine(value []interface{}) Collection {
	var (
		m      = make(map[string]interface{}, 0)
		length = c.length
		d      MapCollection
	)

	if length > len(value) {
		length = len(value)
	}

	for i := 0; i < length; i++ {
		m[c.value[i]] = value[i]
	}

	d.value = m
	d.length = len(m)

	return d
}

// Prepend adds an item to the beginning of the collection.
func (c StringArrayCollection) Prepend(values ...interface{}) Collection {

	var d StringArrayCollection

	var n = make([]string, len(c.value))
	copy(n, c.value)

	d.value = append([]string{values[0].(string)}, n...)
	d.length = len(d.value)

	return d
}

// Splice removes and returns a slice of items starting at the specified index.
func (c StringArrayCollection) Splice(index ...int) Collection {

	if len(index) == 1 {
		var n = make([]string, len(c.value))
		copy(n, c.value)
		n = n[index[0]:]

		return StringArrayCollection{n, BaseCollection{length: len(n)}}
	} else if len(index) > 1 {
		var n = make([]string, len(c.value))
		copy(n, c.value)
		n = n[index[0] : index[0]+index[1]]

		return StringArrayCollection{n, BaseCollection{length: len(n)}}
	} else {
		panic("invalid argument")
	}
}

// Take returns a new collection with the specified number of items.
func (c StringArrayCollection) Take(num int) Collection {
	var d StringArrayCollection
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
func (c StringArrayCollection) All() []interface{} {
	s := make([]interface{}, len(c.value))
	for i := 0; i < len(c.value); i++ {
		s[i] = c.value[i]
	}

	return s
}

// Mode returns the mode value of a given key.
func (c StringArrayCollection) Mode(key ...string) []interface{} {
	valueCount := c.CountBy()
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

// ToStringArray converts the collection into a plain golang slice which contains string.
func (c StringArrayCollection) ToStringArray() []string {
	return c.value
}

// Chunk breaks the collection into multiple, smaller collections of a given size.
func (c StringArrayCollection) Chunk(num int) MultiDimensionalArrayCollection {
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
func (c StringArrayCollection) Concat(value interface{}) Collection {
	var d = make([]string, len(c.value))
	copy(d, c.value)
	return StringArrayCollection{
		value:          append(d, value.([]string)...),
		BaseCollection: BaseCollection{length: c.length + len(value.([]string))},
	}
}

// Contains determines whether the collection contains a given item.
func (c StringArrayCollection) Contains(value ...interface{}) bool {
	if callback, ok := value[0].(CB); ok {
		for k, v := range c.value {
			if callback(k, v) {
				return true
			}
		}
		return false
	}

	for _, v := range c.value {
		if v == value[0].(string) {
			return true
		}
	}
	return false
}

// CountBy counts the occurrences of values in the collection. By default, the method counts the occurrences of every element.
func (c StringArrayCollection) CountBy(callback ...interface{}) map[interface{}]int {
	valueCount := make(map[interface{}]int)

	if len(callback) > 0 {
		if cb, ok := callback[0].(FilterFun); ok {
			for _, v := range c.value {
				valueCount[cb(v)]++
			}
		}
	} else {
		for _, v := range c.value {
			valueCount[v]++
		}
	}

	return valueCount
}

// CrossJoin cross joins the collection's values among the given arrays or collections, returning a Cartesian product with all possible permutations.
func (c StringArrayCollection) CrossJoin(array ...[]interface{}) MultiDimensionalArrayCollection {
	var d MultiDimensionalArrayCollection

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

// Dd dumps the collection's items and ends execution of the script.
func (c StringArrayCollection) Dd() {
	dd(c)
}

// Dump dumps the collection's items.
func (c StringArrayCollection) Dump() {
	dump(c)
}

// Diff compares the collection against another collection or a plain PHP array based on its values.
// This method will return the values in the original collection that are not present in the given collection.
func (c StringArrayCollection) Diff(m interface{}) Collection {
	ms := m.([]string)
	var d = make([]string, 0)
	for _, value := range c.value {
		exist := false
		for i := 0; i < len(ms); i++ {
			if ms[i] == value {
				exist = true
				break
			}
		}
		if !exist {
			d = append(d, value)
		}
	}
	return StringArrayCollection{
		value: d,
	}
}

// Each iterates over the items in the collection and passes each item to a callback.
func (c StringArrayCollection) Each(cb func(item, value interface{}) (interface{}, bool)) Collection {
	var d = make([]string, 0)
	var (
		newValue interface{}
		stop     = false
	)
	for key, value := range c.value {
		if !stop {
			newValue, stop = cb(key, value)
			d = append(d, newValue.(string))
		} else {
			d = append(d, value)
		}
	}
	return StringArrayCollection{
		value: d,
	}
}

// Every may be used to verify that all elements of a collection pass a given truth test.
func (c StringArrayCollection) Every(cb CB) bool {
	for key, value := range c.value {
		if !cb(key, value) {
			return false
		}
	}
	return true
}

// Filter filters the collection using the given callback, keeping only those items that pass a given truth test.
func (c StringArrayCollection) Filter(cb CB) Collection {
	var d = make([]string, 0)
	for key, value := range c.value {
		if cb(key, value) {
			d = append(d, value)
		}
	}
	return StringArrayCollection{
		value: d,
	}
}

// First returns the first element in the collection that passes a given truth test.
func (c StringArrayCollection) First(cbs ...CB) interface{} {
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

// Intersect removes any values from the original collection that are not present in the given array or collection.
func (c StringArrayCollection) Intersect(keys []string) Collection {
	var d = make([]string, 0)
	for _, value := range c.value {
		for _, v := range keys {
			if v == value {
				d = append(d, value)
				break
			}
		}
	}
	return StringArrayCollection{
		value: d,
	}
}

// ForPage returns a new collection containing the items that would be present on a given page number.
func (c StringArrayCollection) ForPage(page, size int) Collection {
	var d = make([]string, len(c.value))
	copy(d, c.value)
	if size > len(d) || size*(page-1) > len(d) {
		return StringArrayCollection{
			value: d,
		}
	}
	if (page+1)*size > len(d) {
		return StringArrayCollection{
			value: d[(page-1)*size:],
		}
	} else {
		return StringArrayCollection{
			value: d[(page-1)*size : (page)*size],
		}
	}
}

// IsEmpty returns true if the collection is empty; otherwise, false is returned.
func (c StringArrayCollection) IsEmpty() bool {
	return len(c.value) == 0
}

// IsNotEmpty returns true if the collection is not empty; otherwise, false is returned.
func (c StringArrayCollection) IsNotEmpty() bool {
	return len(c.value) != 0
}

// Last returns the last element in the collection that passes a given truth test.
func (c StringArrayCollection) Last(cbs ...CB) interface{} {
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

// Merge merges the given array or collection with the original collection. If a string key in the given items
// matches a string key in the original collection, the given items's value will overwrite the value in the
// original collection.
func (c StringArrayCollection) Merge(i interface{}) Collection {
	m := i.([]string)
	var d = make([]string, len(c.value))
	copy(d, c.value)

	for i := 0; i < len(m); i++ {
		exist := false
		for j := 0; j < len(d); j++ {
			if d[j] == m[i] {
				exist = true
				break
			}
		}
		if !exist {
			d = append(d, m[i])
		}
	}

	return StringArrayCollection{
		value: d,
	}
}

// Pad will fill the array with the given value until the array reaches the specified size.
func (c StringArrayCollection) Pad(num int, value interface{}) Collection {
	if len(c.value) > num {
		d := make([]string, len(c.value))
		copy(d, c.value)
		return StringArrayCollection{
			value: d,
		}
	}
	if num > 0 {
		d := make([]string, num)
		for i := 0; i < num; i++ {
			if i < len(c.value) {
				d[i] = c.value[i]
			} else {
				d[i] = value.(string)
			}
		}
		return StringArrayCollection{
			value: d,
		}
	} else {
		d := make([]string, -num)
		for i := 0; i < -num; i++ {
			if i < -num-len(c.value) {
				d[i] = value.(string)
			} else {
				d[i] = c.value[i]
			}
		}
		return StringArrayCollection{
			value: d,
		}
	}
}

// Partition separate elements that pass a given truth test from those that do not.
func (c StringArrayCollection) Partition(cb PartCB) (Collection, Collection) {
	var d1 = make([]string, 0)
	var d2 = make([]string, 0)

	for i := 0; i < len(c.value); i++ {
		if cb(i) {
			d1 = append(d1, c.value[i])
		} else {
			d2 = append(d2, c.value[i])
		}
	}

	return StringArrayCollection{
			value: d1,
		}, StringArrayCollection{
			value: d2,
		}
}

// Pop removes and returns the last item from the collection.
func (c StringArrayCollection) Pop() interface{} {
	last := c.value[len(c.value)-1]
	c.value = c.value[:len(c.value)-1]
	return last
}

// Push appends an item to the end of the collection.
func (c StringArrayCollection) Push(v interface{}) Collection {
	var d = make([]string, len(c.value)+1)
	for i := 0; i < len(d); i++ {
		if i < len(c.value) {
			d[i] = c.value[i]
		} else {
			d[i] = v.(string)
		}
	}

	return StringArrayCollection{
		value: d,
	}
}

// Random returns a random item from the collection.
func (c StringArrayCollection) Random(num ...int) Collection {
	if len(num) == 0 {
		return BaseCollection{
			value: c.value[rand.Intn(len(c.value))],
		}
	} else {
		if num[0] > len(c.value) {
			panic("wrong num")
		}
		var d = make([]string, len(c.value))
		copy(d, c.value)
		for i := 0; i < len(c.value)-num[0]; i++ {
			index := rand.Intn(len(d))
			d = append(d[:index], d[index+1:]...)
		}
		return StringArrayCollection{
			value: d,
		}
	}
}

// Reduce reduces the collection to a single value, passing the result of each iteration into the subsequent iteration.
func (c StringArrayCollection) Reduce(cb ReduceCB) interface{} {
	var res interface{}

	for i := 0; i < len(c.value); i++ {
		res = cb(res, c.value[i])
	}

	return res
}

// Reject filters the collection using the given callback.
func (c StringArrayCollection) Reject(cb CB) Collection {
	var d = make([]string, 0)
	for key, value := range c.value {
		if !cb(key, value) {
			d = append(d, value)
		}
	}
	return StringArrayCollection{
		value: d,
	}
}

// Reverse reverses the order of the collection's items, preserving the original keys.
func (c StringArrayCollection) Reverse() Collection {
	var d = make([]string, len(c.value))
	j := 0
	for i := len(c.value) - 1; i > -1; i-- {
		d[j] = c.value[i]
		j++
	}
	return StringArrayCollection{
		value: d,
	}
}

// Search searches the collection for the given value and returns its key if found. If the item is not found,
// -1 is returned.
func (c StringArrayCollection) Search(v interface{}) int {
	if s, ok := v.(string); ok {
		for i := 0; i < len(c.value); i++ {
			if s == c.value[i] {
				return i
			}
		}
	} else {
		cb := v.(CB)
		for i := 0; i < len(c.value); i++ {
			if cb(i, c.value[i]) {
				return i
			}
		}
	}
	return -1
}

// Shift removes and returns the first item from the collection.
func (c StringArrayCollection) Shift() Collection {
	var d = make([]string, len(c.value))
	copy(d, c.value)
	return StringArrayCollection{
		value: d[1:],
	}
}

// Shuffle randomly shuffles the items in the collection.
func (c StringArrayCollection) Shuffle() Collection {
	var d = make([]string, len(c.value))
	copy(d, c.value)
	rand.Seed(time.Now().UnixNano())
	rand.Shuffle(len(c.value), func(i, j int) { d[i], d[j] = d[j], d[i] })
	return StringArrayCollection{
		value: d,
	}
}

// Slice returns a slice of the collection starting at the given index.
func (c StringArrayCollection) Slice(keys ...int) Collection {
	var d = make([]string, len(c.value))
	copy(d, c.value)
	if len(keys) == 1 {
		return StringArrayCollection{
			value: d[keys[0]:],
		}
	} else {
		return StringArrayCollection{
			value: d[keys[0] : keys[0]+keys[1]],
		}
	}
}

// Split breaks a collection into the given number of groups.
func (c StringArrayCollection) Split(num int) Collection {
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

// Unique returns all of the unique items in the collection.
func (c StringArrayCollection) Unique() Collection {
	var d = make([]string, len(c.value))
	copy(d, c.value)
	x := make([]string, 0)
	for _, i := range d {
		if len(x) == 0 {
			x = append(x, i)
		} else {
			for k, v := range x {
				if i == v {
					break
				}
				if k == len(x)-1 {
					x = append(x, i)
				}
			}
		}
	}
	return StringArrayCollection{
		value: x,
	}
}

// ToJson converts the collection into a json string.
func (c StringArrayCollection) ToJson() string {
	s, err := json.Marshal(c.value)
	if err != nil {
		panic(err)
	}
	return string(s)
}
