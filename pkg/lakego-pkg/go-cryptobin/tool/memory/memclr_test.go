package memory

import "testing"

func TestMemclrI(t *testing.T) {
	t.Run("slice", func(t *testing.T) {
		s := []int{1, 2, 3, 4, 5}
		MemclrI(s)
		for _, v := range s {
			if v != 0 {
				t.Fail()
			}
		}
	})

	t.Run("array", func(t *testing.T) {
		s := [3]int{1, 2, 3}
		MemclrI(&s)
		for _, v := range s {
			if v != 0 {
				t.Fail()
			}
		}
	})

	t.Run("struct", func(t *testing.T) {
		type data struct {
			PointerA    *data
			pointerA    *data
			IntValue    int
			intValue    int
			StringValue string
			stringValue string
			sliceValue  []byte
			SliceValue  []byte
			ArrayValue  [3]byte
			arrayValue  [3]byte
			MapValue    map[string]string
			mapValue    map[string]string
		}
		arr := []byte{1, 2, 3}
		m := map[string]string{"a": "b"}

		d := &data{
			IntValue:    1,
			intValue:    2,
			StringValue: "aaa",
			stringValue: "bbb",
			SliceValue:  arr,
			sliceValue:  []byte{1, 2, 3},
			ArrayValue:  [3]byte{7, 8, 9},
			arrayValue:  [3]byte{10, 11, 12},
			MapValue:    m,
			mapValue:    map[string]string{"c": "d"},
		}
		d2 := &data{
			PointerA: d,
		}
		d.PointerA = d2

		MemclrI(d)

		if d.pointerA != nil ||
			d.IntValue != 0 ||
			d.intValue != 0 ||
			d.StringValue != "" ||
			d.stringValue != "" ||
			d.sliceValue != nil ||
			d.SliceValue != nil ||
			d.ArrayValue != [3]byte{} ||
			d.arrayValue != [3]byte{} ||
			d.MapValue != nil ||
			d.mapValue != nil {
			t.Fail()
		}
	})
}
