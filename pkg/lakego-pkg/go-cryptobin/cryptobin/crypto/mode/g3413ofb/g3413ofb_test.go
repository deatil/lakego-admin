package g3413ofb

import (
    "testing"

    "github.com/deatil/go-cryptobin/tool/test"
    "github.com/deatil/go-cryptobin/cryptobin/crypto"
)

func Test_Name(t *testing.T) {
    eq := test.AssertEqualT(t)

    eq(G3413OFB.String(), "G3413OFB", "Test_Name")
}

func Test_KuznyechikG3413OFBPKCS7Padding(t *testing.T) {
    assert := test.AssertEqualT(t)
    assertNoError := test.AssertNoErrorT(t)

    data := "test-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-pass"
    cypt := crypto.FromString(data).
        SetKey("dfertf12dfertf12dfertf12dfertf12").
        SetIv("dfertf12dfer1232dfertf12dfer1232").
        Kuznyechik().
        ModeBy(G3413OFB).
        PKCS7Padding().
        Encrypt()
    cyptStr := cypt.ToBase64String()

    assertNoError(cypt.Error(), "Test_KuznyechikG3413OFBPKCS7Padding-Encode")

    cyptde := crypto.FromBase64String(cyptStr).
        SetKey("dfertf12dfertf12dfertf12dfertf12").
        SetIv("dfertf12dfer1232dfertf12dfer1232").
        Kuznyechik().
        ModeBy(G3413OFB).
        PKCS7Padding().
        Decrypt()
    cyptdeStr := cyptde.ToString()

    assertNoError(cyptde.Error(), "Test_KuznyechikG3413OFBPKCS7Padding-Decode")

    assert(data, cyptdeStr, "Test_KuznyechikG3413OFBPKCS7Padding-res")
}

func Test_KuznyechikG3413OFBPKCS7Padding_Bad(t *testing.T) {
    empty := test.AssertEmptyT(t)
    assertError := test.AssertErrorT(t)

    data := "test-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-pass"
    cypt := crypto.FromString(data).
        SetKey("dfertf112dfertf12dfertf12dfertf12").
        SetIv("dfertf112dfer1232dfertf12dfer1232").
        Kuznyechik().
        ModeBy(G3413OFB).
        PKCS7Padding().
        Encrypt()
    cyptStr := cypt.ToBase64String()

    assertError(cypt.Error(), "Test_KuznyechikG3413OFBPKCS7Padding_Bad-Encode")
    empty(cyptStr, "Test_KuznyechikG3413OFBPKCS7Padding_Bad-Encode")

    cyptedStr := "4ynA5GUBeN99ly1mXV7ZXGgjY+Y2Gy2ocgjcQkr6fYFIJsBjbF/DtI/y8hxto/MWVYGhU04K0cv7JQAdknoTXX7PdO28Mf5HTh22NDhG6ks6M8csANC66ynjQz5ttF+mOnTqsMfOJ7Ze9r2IhFpX5nA7LfmnRAJ981P92kb/PdGuDEHY/Wg9UIDH/vCSmM5HihASKm0e5bZypq628rXE7W9L5EW2lYrFWq7EuWfjmqUB7uWUTHOkswOSsoMy+dKxudIBx1vQ4lZ6FBzDQxqA62cXSpkTi+zNAo6IbDo2G7zvoEpvsQsSWHtKIQN+q9ANBqYgD0MfGgGnASVc2Qo6MQ=="
    cyptde := crypto.FromBase64String(cyptedStr).
        SetKey("dfertf1212dfertf12dfertf12dfertf12").
        SetIv("dfertf1122dfer1232dfertf12dfer1232").
        Kuznyechik().
        ModeBy(G3413OFB).
        PKCS7Padding().
        Decrypt()
    cyptdeStr := cyptde.ToString()

    assertError(cyptde.Error(), "Test_KuznyechikG3413OFBPKCS7Padding_Bad-Decode")
    empty(cyptdeStr, "Test_KuznyechikG3413OFBPKCS7Padding_Bad-Encode")
}
