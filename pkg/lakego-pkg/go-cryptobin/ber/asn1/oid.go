package asn1

import (
    "bytes"
    "fmt"
    "reflect"
    "strconv"
)

type ObjectIdentifier []int

// Equal reports whether oi and other represent the same identifier.
func (oi ObjectIdentifier) Equal(other ObjectIdentifier) bool {
    if len(oi) != len(other) {
        return false
    }

    for i := 0; i < len(oi); i++ {
        if oi[i] != other[i] {
            return false
        }
    }

    return true
}

func (oi ObjectIdentifier) String() string {
    var s string

    for i, v := range oi {
        if i > 0 {
            s += "."
        }
        s += strconv.Itoa(v)
    }

    return s
}

func isValidRootNode(root int) bool {
    switch root {
        case 0, 1, 2:
            return true
        default:
            return false
    }
}

func NewObjectIdentifier(root int, node []int) (ObjectIdentifier, error) {
    if !isValidRootNode(root) {
        return nil, fmt.Errorf("error creating object identifier: invalid root node %d", root)
    }
    if len(node) == 0 {
        return nil, fmt.Errorf("error creating object identifier: empty node")
    }

    switch root {
        case 0, 1:
            if node[0] >= 40 {
                return nil, fmt.Errorf("invalid node")
            }
    }

    oid := []int{root}
    oid = append(oid, node...)

    return ObjectIdentifier(oid), nil
}

var objectIdentifierType = reflect.TypeOf(ObjectIdentifier{})

type objectIdentifierEncoder ObjectIdentifier

func (e objectIdentifierEncoder) encode() ([]byte, error) {
    b := new(bytes.Buffer)

    b.Write(encodeBase128((e[0]*40 + e[1])))

    for i := 2; i < len(e); i++ {
        b.Write(encodeBase128(e[i]))
    }

    return b.Bytes(), nil
}
