package bign

import (
    "bytes"
    "testing"
)

func Test_MakeAdata(t *testing.T) {
    oid := []byte("123")
    typ := []byte("33")

    adata := MakeAdata(oid, typ)

    oid2, err := GetOidFromAdata(adata)
    if err != nil {
        t.Fatal(err)
    }

    typ2, err := GetTFromAdata(adata)
    if err != nil {
        t.Fatal(err)
    }

    if !bytes.Equal(oid2, oid) {
        t.Errorf("get oid fail, got: %x, want: %x", oid2, oid)
    }
    if !bytes.Equal(typ2, typ) {
        t.Errorf("get type fail, got: %x, want: %x", typ2, typ)
    }

}
