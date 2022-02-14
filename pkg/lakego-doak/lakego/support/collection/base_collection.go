package collection

import (
    "encoding/json"

    "github.com/deatil/lakego-doak/lakego/support/decimal"
)

type BaseCollection struct {
    value  interface{}
    length int
}

func (c BaseCollection) Value() interface{} {
    return c.value
}

// Length return the length of the collection.
func (c BaseCollection) Length() int {
    return c.length
}

// Select select the keys of collection and delete others.
func (c BaseCollection) Select(keys ...string) Collection {
    panic("not implement")
}

// ToStruct turn the collection to the specified struct using mapstructure.
// https://github.com/mitchellh/mapstructure
func (c BaseCollection) ToStruct(dist interface{}) {
    panic("not implement")
}

// All returns the underlying array represented by the collection.
func (c BaseCollection) All() []interface{} {
    panic("not implement")
}

// Avg returns the average value of a given key.
func (c BaseCollection) Avg(key ...string) decimal.Decimal {
    return c.Sum(key...).Div(decimal.New(int64(c.length), 0))
}

// Sum returns the sum of all items in the collection.
func (c BaseCollection) Sum(key ...string) decimal.Decimal {
    panic("not implement")
}

// Min returns the minimum value of a given key.
func (c BaseCollection) Min(key ...string) decimal.Decimal {
    panic("not implement")
}

// Max returns the maximum value of a given key.
func (c BaseCollection) Max(key ...string) decimal.Decimal {
    panic("not implement")
}

// Join joins the collection's values with a string.
func (c BaseCollection) Join(delimiter string) string {
    panic("not implement")
}

// Combine combines the values of the collection, as keys, with the values of another array or collection.
func (c BaseCollection) Combine(value []interface{}) Collection {
    panic("not implement")
}

// Pluck retrieves all of the values for a given key.
func (c BaseCollection) Pluck(key string) Collection {
    panic("not implement")
}

// ToIntArray converts the collection into a plain golang slice which contains int.
func (c BaseCollection) ToIntArray() []int {
    panic("not implement")
}

// ToInt64Array converts the collection into a plain golang slice which contains int64.
func (c BaseCollection) ToInt64Array() []int64 {
    panic("not implement")
}

// Mode returns the mode value of a given key.
func (c BaseCollection) Mode(key ...string) []interface{} {
    panic("not implement")
}

// Only returns the items in the collection with the specified keys.
func (c BaseCollection) Only(keys []string) Collection {
    panic("not implement")
}

// Prepend adds an item to the beginning of the collection.
func (c BaseCollection) Prepend(values ...interface{}) Collection {
    panic("not implement")
}

// Pull removes and returns an item from the collection by its key.
func (c BaseCollection) Pull(key interface{}) Collection {
    panic("not implement")
}

// Put sets the given key and value in the collection:.
func (c BaseCollection) Put(key string, value interface{}) Collection {
    panic("not implement")
}

// SortBy sorts the collection by the given key.
func (c BaseCollection) SortBy(key string) Collection {
    panic("not implement")
}

// Take returns a new collection with the specified number of items.
func (c BaseCollection) Take(num int) Collection {
    panic("not implement")
}

// Chunk breaks the collection into multiple, smaller collections of a given size.
func (c BaseCollection) Chunk(num int) MultiDimensionalArrayCollection {
    panic("not implement")
}

// Collapse collapses a collection of arrays into a single, flat collection.
func (c BaseCollection) Collapse() Collection {
    panic("not implement")
}

// Concat appends the given array or collection values onto the end of the collection.
func (c BaseCollection) Concat(value interface{}) Collection {
    panic("not implement")
}

// Contains determines whether the collection contains a given item.
func (c BaseCollection) Contains(value ...interface{}) bool {
    panic("not implement")
}

// CountBy counts the occurrences of values in the collection. By default, the method counts the occurrences of every element.
func (c BaseCollection) CountBy(callback ...interface{}) map[interface{}]int {
    panic("not implement")
}

// CrossJoin cross joins the collection's values among the given arrays or collections, returning a Cartesian product with all possible permutations.
func (c BaseCollection) CrossJoin(array ...[]interface{}) MultiDimensionalArrayCollection {
    panic("not implement")
}

// Dd dumps the collection's items and ends execution of the script.
func (c BaseCollection) Dd() {
    panic("not implement")
}

// Diff compares the collection against another collection or a plain PHP array based on its values.
// This method will return the values in the original collection that are not present in the given collection.
func (c BaseCollection) Diff(interface{}) Collection {
    panic("not implement")
}

// DiffAssoc compares the collection against another collection or a plain PHP  array based on its keys and values.
// This method will return the key / value pairs in the original collection that are not present in the given collection.
func (c BaseCollection) DiffAssoc(map[string]interface{}) Collection {
    panic("not implement")
}

// DiffKeys compares the collection against another collection or a plain PHP array based on its keys.
// This method will return the key / value pairs in the original collection that are not present in the given collection.
func (c BaseCollection) DiffKeys(map[string]interface{}) Collection {
    panic("not implement")
}

// Dump dumps the collection's items.
func (c BaseCollection) Dump() {
    panic("not implement")
}

// Each iterates over the items in the collection and passes each item to a callback.
func (c BaseCollection) Each(func(item, value interface{}) (interface{}, bool)) Collection {
    panic("not implement")
}

// Every may be used to verify that all elements of a collection pass a given truth test.
func (c BaseCollection) Every(CB) bool {
    panic("not implement")
}

// Except returns all items in the collection except for those with the specified keys.
func (c BaseCollection) Except([]string) Collection {
    panic("not implement")
}

// Filter filters the collection using the given callback, keeping only those items that pass a given truth test.
func (c BaseCollection) Filter(CB) Collection {
    panic("not implement")
}

// First returns the first element in the collection that passes a given truth test.
func (c BaseCollection) First(...CB) interface{} {
    panic("not implement")
}

// FirstWhere returns the first element in the collection with the given key / value pair.
func (c BaseCollection) FirstWhere(key string, values ...interface{}) map[string]interface{} {
    panic("not implement")
}

// FlatMap iterates through the collection and passes each value to the given callback.
func (c BaseCollection) FlatMap(func(value interface{}) interface{}) Collection {
    panic("not implement")
}

// Flip swaps the collection's keys with their corresponding values.
func (c BaseCollection) Flip() Collection {
    panic("not implement")
}

// Forget removes an item from the collection by its key.
func (c BaseCollection) Forget(string) Collection {
    panic("not implement")
}

// ForPage returns a new collection containing the items that would be present on a given page number.
func (c BaseCollection) ForPage(int, int) Collection {
    panic("not implement")
}

// Get returns the item at a given key. If the key does not exist, null is returned.
func (c BaseCollection) Get(string, ...interface{}) interface{} {
    panic("not implement")
}

// GroupBy groups the collection's items by a given key.
func (c BaseCollection) GroupBy(string) Collection {
    panic("not implement")
}

// Has determines if a given key exists in the collection.
func (c BaseCollection) Has(...string) bool {
    panic("not implement")
}

// Implode joins the items in a collection. Its arguments depend on the type of items in the collection.
func (c BaseCollection) Implode(string, string) string {
    panic("not implement")
}

// Intersect removes any values from the original collection that are not present in the given array or collection.
func (c BaseCollection) Intersect([]string) Collection {
    panic("not implement")
}

// IntersectByKeys removes any keys from the original collection that are not present in the given array or collection.
func (c BaseCollection) IntersectByKeys(map[string]interface{}) Collection {
    panic("not implement")
}

// IsEmpty returns true if the collection is empty; otherwise, false is returned.
func (c BaseCollection) IsEmpty() bool {
    panic("not implement")
}

// IsNotEmpty returns true if the collection is not empty; otherwise, false is returned.
func (c BaseCollection) IsNotEmpty() bool {
    panic("not implement")
}

// KeyBy keys the collection by the given key. If multiple items have the same key, only the last one will
// appear in the new collection.
func (c BaseCollection) KeyBy(interface{}) Collection {
    panic("not implement")
}

// Keys returns all of the collection's keys.
func (c BaseCollection) Keys() Collection {
    panic("not implement")
}

// Last returns the last element in the collection that passes a given truth test.
func (c BaseCollection) Last(...CB) interface{} {
    panic("not implement")
}

// MapToGroups groups the collection's items by the given callback.
func (c BaseCollection) MapToGroups(MapCB) Collection {
    panic("not implement")
}

// MapWithKeys iterates through the collection and passes each value to the given callback.
func (c BaseCollection) MapWithKeys(MapCB) Collection {
    panic("not implement")
}

// Median returns the median value of a given key.
func (c BaseCollection) Median(key ...string) decimal.Decimal {
    panic("not implement")
}

// Merge merges the given array or collection with the original collection. If a string key in the given items
// matches a string key in the original collection, the given items's value will overwrite the value in the
// original collection.
func (c BaseCollection) Merge(interface{}) Collection {
    panic("not implement")
}

func (c BaseCollection) Nth(...int) Collection {
    panic("not implement")
}

// Pad will fill the array with the given value until the array reaches the specified size.
func (c BaseCollection) Pad(int, interface{}) Collection {
    panic("not implement")
}

// Partition separate elements that pass a given truth test from those that do not.
func (c BaseCollection) Partition(PartCB) (Collection, Collection) {
    panic("not implement")
}

// Pop removes and returns the last item from the collection.
func (c BaseCollection) Pop() interface{} {
    panic("not implement")
}

// Push appends an item to the end of the collection.
func (c BaseCollection) Push(interface{}) Collection {
    panic("not implement")
}

// Random returns a random item from the collection.
func (c BaseCollection) Random(...int) Collection {
    panic("not implement")
}

// Reduce reduces the collection to a single value, passing the result of each iteration into the subsequent iteration.
func (c BaseCollection) Reduce(ReduceCB) interface{} {
    panic("not implement")
}

// Reject filters the collection using the given callback.
func (c BaseCollection) Reject(CB) Collection {
    panic("not implement")
}

// Reverse reverses the order of the collection's items, preserving the original keys.
func (c BaseCollection) Reverse() Collection {
    panic("not implement")
}

// Search searches the collection for the given value and returns its key if found. If the item is not found,
// -1 is returned.
func (c BaseCollection) Search(interface{}) int {
    panic("not implement")
}

// Shift removes and returns the first item from the collection.
func (c BaseCollection) Shift() Collection {
    panic("not implement")
}

// Shuffle randomly shuffles the items in the collection.
func (c BaseCollection) Shuffle() Collection {
    panic("not implement")
}

// Slice returns a slice of the collection starting at the given index.
func (c BaseCollection) Slice(...int) Collection {
    panic("not implement")
}

// Sort sorts the collection.
func (c BaseCollection) Sort() Collection {
    panic("not implement")
}

// SortByDesc has the same signature as the sortBy method, but will sort the collection in the opposite order.
func (c BaseCollection) SortByDesc() Collection {
    panic("not implement")
}

// Splice removes and returns a slice of items starting at the specified index.
func (c BaseCollection) Split(int) Collection {
    panic("not implement")
}

// Split breaks a collection into the given number of groups.
func (c BaseCollection) Splice(index ...int) Collection {
    panic("not implement")
}

// Unique returns all of the unique items in the collection.
func (c BaseCollection) Unique() Collection {
    panic("not implement")
}

// WhereIn filters the collection by a given key / value contained within the given array.
func (c BaseCollection) WhereIn(string, []interface{}) Collection {
    panic("not implement")
}

// WhereNotIn filters the collection by a given key / value not contained within the given array.
func (c BaseCollection) WhereNotIn(string, []interface{}) Collection {
    panic("not implement")
}

// ToJson converts the collection into a json string.
func (c BaseCollection) ToJson() string {
    s, err := json.Marshal(c.value)
    if err != nil {
        panic(err)
    }
    return string(s)
}

// ToNumberArray converts the collection into a plain golang slice which contains decimal.Decimal.
func (c BaseCollection) ToNumberArray() []decimal.Decimal {
    panic("not implement")
}

// ToStringArray converts the collection into a plain golang slice which contains string.
func (c BaseCollection) ToMultiDimensionalArray() [][]interface{} {
    panic("not implement")
}

// ToStringArray converts the collection into a plain golang slice which contains string.
func (c BaseCollection) ToStringArray() []string {
    panic("not implement")
}

// ToMap converts the collection into a plain golang map.
func (c BaseCollection) ToMap() map[string]interface{} {
    panic("not implement")
}

// ToMapArray converts the collection into a plain golang slice which contains map.
func (c BaseCollection) ToMapArray() []map[string]interface{} {
    panic("not implement")
}

// Where filters the collection by a given key / value pair.
func (c BaseCollection) Where(key string, values ...interface{}) Collection {
    panic("not implement")
}

// Count returns the total number of items in the collection.
func (c BaseCollection) Count() int {
    return c.length
}
