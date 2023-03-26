package rsa

import (
    "testing"
    "reflect"
)

func assertT(t *testing.T) func(any, any, string) {
    return func(actual any, expected any, msg string) {
        if !reflect.DeepEqual(actual, expected) {
            t.Errorf("Failed %s: actual: %v, expected: %v", msg, actual, expected)
        }
    }
}

func assertErrorT(t *testing.T) func(error, string) {
    return func(err error, msg string) {
        if err != nil {
            t.Errorf("Failed %s: error: %+v", msg, err)
        }
    }
}

func assertEmptyT(t *testing.T) func(string, string) {
    return func(data string, msg string) {
        if data == "" {
            t.Errorf("Failed %s: error: data empty", msg)
        }
    }
}

// Test_PrimeKeyGeneration
func Test_PrimeKeyGeneration(t *testing.T) {
    assertEmpty := assertEmptyT(t)
    assertError := assertErrorT(t)

    size := 768
    if testing.Short() {
        size = 256
    }

    obj := NewRsa().GenerateMultiPrimeKey(3, size)

    objPriKey := obj.CreatePKCS1PrivateKey()

    assertError(objPriKey.Error(), "objPriKey")
    assertEmpty(objPriKey.ToKeyString(), "objPriKey")

    objPubKey := obj.CreatePKCS1PublicKey()

    assertError(objPubKey.Error(), "objPubKey")
    assertEmpty(objPubKey.ToKeyString(), "objPubKey")
}
