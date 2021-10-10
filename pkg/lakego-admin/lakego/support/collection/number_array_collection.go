package collection

import (
	"time"
	"math"
	"math/rand"
	"encoding/json"
    
	"github.com/deatil/lakego-admin/lakego/support/decimal"
)

type NumberArrayCollection struct {
	value []decimal.Decimal
	BaseCollection
}

// Sum returns the sum of all items in the collection.
func (c NumberArrayCollection) Sum(key ...string) decimal.Decimal {

	var sum = decimal.New(0, 0)

	for i := 0; i < len(c.value); i++ {
		sum = sum.Add(c.value[i])
	}

	return sum
}

// Length return the length of the collection.
func (c NumberArrayCollection) Length() int {
	return len(c.value)
}

// Avg returns the average value of a given key.
func (c NumberArrayCollection) Avg(key ...string) decimal.Decimal {

	var sum = decimal.New(0, 0)

	for i := 0; i < len(c.value); i++ {
		sum = sum.Add(c.value[i])
	}

	return sum.Div(nd(len(c.value)))
}

// Min returns the minimum value of a given key.
func (c NumberArrayCollection) Min(key ...string) decimal.Decimal {

	var smallest = decimal.New(0, 0)

	for i := 0; i < len(c.value); i++ {
		if i == 0 {
			smallest = c.value[i]
			continue
		}
		if smallest.GreaterThan(c.value[i]) {
			smallest = c.value[i]
		}
	}

	return smallest
}

// Max returns the maximum value of a given key.
func (c NumberArrayCollection) Max(key ...string) decimal.Decimal {

	var biggest = decimal.New(0, 0)

	for i := 0; i < len(c.value); i++ {
		if i == 0 {
			biggest = c.value[i]
			continue
		}
		if biggest.LessThan(c.value[i]) {
			biggest = c.value[i]
		}
	}

	return biggest
}

// Prepend adds an item to the beginning of the collection.
func (c NumberArrayCollection) Prepend(values ...interface{}) Collection {
	var d NumberArrayCollection

	var n = make([]decimal.Decimal, len(c.value))
	copy(n, c.value)

	d.value = append([]decimal.Decimal{newDecimalFromInterface(values[0])}, n...)
	d.length = len(d.value)

	return d
}

// Splice removes and returns a slice of items starting at the specified index.
func (c NumberArrayCollection) Splice(index ...int) Collection {

	if len(index) == 1 {
		var n = make([]decimal.Decimal, len(c.value))
		copy(n, c.value)
		n = n[index[0]:]

		return NumberArrayCollection{n, BaseCollection{length: len(n)}}
	} else if len(index) > 1 {
		var n = make([]decimal.Decimal, len(c.value))
		copy(n, c.value)
		n = n[index[0] : index[0]+index[1]]

		return NumberArrayCollection{n, BaseCollection{length: len(n)}}
	} else {
		panic("invalid argument")
	}
}

// Take returns a new collection with the specified number of items.
func (c NumberArrayCollection) Take(num int) Collection {
	var d NumberArrayCollection
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
func (c NumberArrayCollection) All() []interface{} {
	s := make([]interface{}, len(c.value))
	for i := 0; i < len(c.value); i++ {
		s[i] = c.value[i]
	}

	return s
}

// Mode returns the mode value of a given key.
func (c NumberArrayCollection) Mode(key ...string) []interface{} {
	valueCount := c.CountBy()
	maxCount := 0
	maxValue := make([]interface{}, len(valueCount))
	for v, c := range valueCount {
		switch {
		case c < maxCount:
			continue
		case c == maxCount:
			maxValue = append(maxValue, newDecimalFromInterface(v))
		case c > maxCount:
			maxValue = append([]interface{}{}, newDecimalFromInterface(v))
			maxCount = c
		}
	}
	return maxValue
}

// ToNumberArray converts the collection into a plain golang slice which contains decimal.Decimal.
func (c NumberArrayCollection) ToNumberArray() []decimal.Decimal {
	return c.value
}

// ToIntArray converts the collection into a plain golang slice which contains int.
func (c NumberArrayCollection) ToIntArray() []int {
	var v = make([]int, len(c.value))
	for i, value := range c.value {
		v[i] = int(value.IntPart())
	}
	return v
}

// ToInt64Array converts the collection into a plain golang slice which contains int64.
func (c NumberArrayCollection) ToInt64Array() []int64 {
	var v = make([]int64, len(c.value))
	for i, value := range c.value {
		v[i] = value.IntPart()
	}
	return v
}

// Chunk breaks the collection into multiple, smaller collections of a given size.
func (c NumberArrayCollection) Chunk(num int) MultiDimensionalArrayCollection {
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
func (c NumberArrayCollection) Concat(value interface{}) Collection {
	return NumberArrayCollection{
		value:          append(c.value, value.([]decimal.Decimal)...),
		BaseCollection: BaseCollection{length: c.length + len(value.([]decimal.Decimal))},
	}
}

// Contains determines whether the collection contains a given item.
func (c NumberArrayCollection) Contains(value ...interface{}) bool {
	if callback, ok := value[0].(CB); ok {
		for k, v := range c.value {
			if callback(k, v) {
				return true
			}
		}
		return false
	}

	for _, v := range c.value {
		if v.Equal(nd(value[0])) {
			return true
		}
	}
	return false
}

// CountBy counts the occurrences of values in the collection. By default, the method counts the occurrences of every element.
func (c NumberArrayCollection) CountBy(callback ...interface{}) map[interface{}]int {
	valueCount := make(map[interface{}]int)

	if len(callback) > 0 {
		if cb, ok := callback[0].(FilterFun); ok {
			for _, v := range c.value {
				valueCount[cb(v)]++
			}
		}
	} else {
		for _, v := range c.value {
			vv, _ := v.Float64()
			valueCount[vv]++
		}
	}

	return valueCount
}

// CrossJoin cross joins the collection's values among the given arrays or collections, returning a Cartesian product with all possible permutations.
func (c NumberArrayCollection) CrossJoin(array ...[]interface{}) MultiDimensionalArrayCollection {
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

// Dd dumps the collection's items and ends execution of the script.
func (c NumberArrayCollection) Dd() {
	dd(c)
}

// Dump dumps the collection's items.
func (c NumberArrayCollection) Dump() {
	dump(c)
}

// Diff compares the collection against another collection or a plain PHP array based on its values.
// This method will return the values in the original collection that are not present in the given collection.
func (c NumberArrayCollection) Diff(m interface{}) Collection {
	ms := newDecimalArray(m)
	var d = make([]decimal.Decimal, 0)
	for _, value := range c.value {
		exist := false
		for i := 0; i < len(ms); i++ {
			if ms[i].Equal(value) {
				exist = true
				break
			}
		}
		if !exist {
			d = append(d, value)
		}
	}
	return NumberArrayCollection{
		value: d,
	}
}

// Each iterates over the items in the collection and passes each item to a callback.
func (c NumberArrayCollection) Each(cb func(item, value interface{}) (interface{}, bool)) Collection {
	var d = make([]decimal.Decimal, 0)
	var (
		newValue interface{}
		stop     = false
	)
	for key, value := range c.value {
		if !stop {
			newValue, stop = cb(key, value)
			d = append(d, newDecimalFromInterface(newValue))
		} else {
			d = append(d, value)
		}
	}
	return NumberArrayCollection{
		value: d,
	}
}

// Every may be used to verify that all elements of a collection pass a given truth test.
func (c NumberArrayCollection) Every(cb CB) bool {
	for key, value := range c.value {
		if !cb(key, value) {
			return false
		}
	}
	return true
}

// Filter filters the collection using the given callback, keeping only those items that pass a given truth test.
func (c NumberArrayCollection) Filter(cb CB) Collection {
	var d = make([]decimal.Decimal, 0)
	for key, value := range c.value {
		if cb(key, value) {
			d = append(d, value)
		}
	}
	return NumberArrayCollection{
		value: d,
	}
}

// First returns the first element in the collection that passes a given truth test.
func (c NumberArrayCollection) First(cbs ...CB) interface{} {
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

// ForPage returns a new collection containing the items that would be present on a given page number.
func (c NumberArrayCollection) ForPage(page, size int) Collection {
	var d = make([]decimal.Decimal, len(c.value))
	copy(d, c.value)
	if size > len(d) || size*(page-1) > len(d) {
		return NumberArrayCollection{
			value: d,
		}
	}
	if (page+1)*size > len(d) {
		return NumberArrayCollection{
			value: d[(page-1)*size:],
		}
	} else {
		return NumberArrayCollection{
			value: d[(page-1)*size : (page)*size],
		}
	}
}

// IsEmpty returns true if the collection is empty; otherwise, false is returned.
func (c NumberArrayCollection) IsEmpty() bool {
	return len(c.value) == 0
}

// IsNotEmpty returns true if the collection is not empty; otherwise, false is returned.
func (c NumberArrayCollection) IsNotEmpty() bool {
	return len(c.value) != 0
}

// Last returns the last element in the collection that passes a given truth test.
func (c NumberArrayCollection) Last(cbs ...CB) interface{} {
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

// Median returns the median value of a given key.
func (c NumberArrayCollection) Median(key ...string) decimal.Decimal {

	if len(c.value) < 2 {
		return c.value[0]
	}

	var f = make([]decimal.Decimal, len(c.value))
	copy(f, c.value)
	f = qsort(f, true)
	return f[len(f)/2].Add(f[len(f)/2-1]).Div(nd(2))
}

// Merge merges the given array or collection with the original collection. If a string key in the given items
// matches a string key in the original collection, the given items's value will overwrite the value in the
// original collection.
func (c NumberArrayCollection) Merge(i interface{}) Collection {
	m := newDecimalArray(i)
	var d = make([]decimal.Decimal, len(c.value))
	copy(d, c.value)
	d = append(d, m...)

	return NumberArrayCollection{
		value: d,
	}
}

// Pad will fill the array with the given value until the array reaches the specified size.
func (c NumberArrayCollection) Pad(num int, value interface{}) Collection {
	if len(c.value) > num {
		d := make([]decimal.Decimal, len(c.value))
		copy(d, c.value)
		return NumberArrayCollection{
			value: d,
		}
	}
	if num > 0 {
		d := make([]decimal.Decimal, num)
		for i := 0; i < num; i++ {
			if i < len(c.value) {
				d[i] = c.value[i]
			} else {
				d[i] = nd(value)
			}
		}
		return NumberArrayCollection{
			value: d,
		}
	} else {
		d := make([]decimal.Decimal, -num)
		for i := 0; i < -num; i++ {
			if i < -num-len(c.value) {
				d[i] = nd(value)
			} else {
				d[i] = c.value[i]
			}
		}
		return NumberArrayCollection{
			value: d,
		}
	}
}

// Partition separate elements that pass a given truth test from those that do not.
func (c NumberArrayCollection) Partition(cb PartCB) (Collection, Collection) {
	var d1 = make([]decimal.Decimal, 0)
	var d2 = make([]decimal.Decimal, 0)

	for i := 0; i < len(c.value); i++ {
		if cb(i) {
			d1 = append(d1, c.value[i])
		} else {
			d2 = append(d2, c.value[i])
		}
	}

	return NumberArrayCollection{
		value: d1,
	}, NumberArrayCollection{
		value: d2,
	}
}

// Pop removes and returns the last item from the collection.
func (c NumberArrayCollection) Pop() interface{} {
	last := c.value[len(c.value)-1]
	c.value = c.value[:len(c.value)-1]
	return last
}

// Push appends an item to the end of the collection.
func (c NumberArrayCollection) Push(v interface{}) Collection {
	var d = make([]decimal.Decimal, len(c.value)+1)
	for i := 0; i < len(d); i++ {
		if i < len(c.value) {
			d[i] = c.value[i]
		} else {
			d[i] = nd(v)
		}
	}

	return NumberArrayCollection{
		value: d,
	}
}

// Random returns a random item from the collection.
func (c NumberArrayCollection) Random(num ...int) Collection {
	if len(num) == 0 {
		return BaseCollection{
			value: c.value[rand.Intn(len(c.value))],
		}
	} else {
		if num[0] > len(c.value) {
			panic("wrong num")
		}
		var d = make([]decimal.Decimal, len(c.value))
		copy(d, c.value)
		for i := 0; i < len(c.value)-num[0]; i++ {
			index := rand.Intn(len(d))
			d = append(d[:index], d[index+1:]...)
		}
		return NumberArrayCollection{
			value: d,
		}
	}
}

// Reduce reduces the collection to a single value, passing the result of each iteration into the subsequent iteration.
func (c NumberArrayCollection) Reduce(cb ReduceCB) interface{} {
	var res interface{}

	for i := 0; i < len(c.value); i++ {
		res = cb(res, c.value[i])
	}

	return res
}

// Reject filters the collection using the given callback.
func (c NumberArrayCollection) Reject(cb CB) Collection {
	var d = make([]decimal.Decimal, 0)
	for key, value := range c.value {
		if !cb(key, value) {
			d = append(d, value)
		}
	}
	return NumberArrayCollection{
		value: d,
	}
}

// Reverse reverses the order of the collection's items, preserving the original keys.
func (c NumberArrayCollection) Reverse() Collection {
	var d = make([]decimal.Decimal, len(c.value))
	j := 0
	for i := len(c.value) - 1; i > -1; i-- {
		d[j] = c.value[i]
		j++
	}
	return NumberArrayCollection{
		value: d,
	}
}

// Search searches the collection for the given value and returns its key if found. If the item is not found,
// -1 is returned.
func (c NumberArrayCollection) Search(v interface{}) int {
	if cb, ok := v.(CB); ok {
		for i := 0; i < len(c.value); i++ {
			if cb(i, c.value[i]) {
				return i
			}
		}
	} else {
		n := nd(v)
		for i := 0; i < len(c.value); i++ {
			if n.Equal(c.value[i]) {
				return i
			}
		}
	}
	return -1
}

// Shift removes and returns the first item from the collection.
func (c NumberArrayCollection) Shift() Collection {
	var d = make([]decimal.Decimal, len(c.value))
	copy(d, c.value)
	d = d[1:]
	return NumberArrayCollection{
		value: d,
	}
}

// Shuffle randomly shuffles the items in the collection.
func (c NumberArrayCollection) Shuffle() Collection {
	var d = make([]decimal.Decimal, len(c.value))
	copy(d, c.value)
	rand.Seed(time.Now().UnixNano())
	rand.Shuffle(len(c.value), func(i, j int) { d[i], d[j] = d[j], d[i] })
	return NumberArrayCollection{
		value: d,
	}
}

// Slice returns a slice of the collection starting at the given index.
func (c NumberArrayCollection) Slice(keys ...int) Collection {
	var d = make([]decimal.Decimal, len(c.value))
	copy(d, c.value)
	if len(keys) == 1 {
		return NumberArrayCollection{
			value: d[keys[0]:],
		}
	} else {
		return NumberArrayCollection{
			value: d[keys[0] : keys[0]+keys[1]],
		}
	}
}

// Sort sorts the collection.
func (c NumberArrayCollection) Sort() Collection {
	var d = make([]decimal.Decimal, len(c.value))
	copy(d, c.value)
	d = qsort(d, true)
	return NumberArrayCollection{
		value: d,
	}
}

// SortByDesc has the same signature as the sortBy method, but will sort the collection in the opposite order.
func (c NumberArrayCollection) SortByDesc() Collection {
	var d = make([]decimal.Decimal, len(c.value))
	copy(d, c.value)
	d = qsort(d, false)
	return NumberArrayCollection{
		value: d,
	}
}

// Split breaks a collection into the given number of groups.
func (c NumberArrayCollection) Split(num int) Collection {
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
func (c NumberArrayCollection) Unique() Collection {
	var d = make([]decimal.Decimal, len(c.value))
	copy(d, c.value)
	x := make([]decimal.Decimal, 0)
	for _, i := range d {
		if len(x) == 0 {
			x = append(x, i)
		} else {
			for k, v := range x {
				if i.Equal(v) {
					break
				}
				if k == len(x)-1 {
					x = append(x, i)
				}
			}
		}
	}
	return NumberArrayCollection{
		value: x,
	}
}

// ToJson converts the collection into a json string.
func (c NumberArrayCollection) ToJson() string {
	s, err := json.Marshal(c.value)
	if err != nil {
		panic(err)
	}
	return string(s)
}
