package filesystem_test

import (
    "reflect"
    "testing"

    "github.com/deatil/lakego-filesystem/filesystem"
)

func assertErrorT(t *testing.T) func(error, string) {
    return func(err error, msg string) {
        if err != nil {
            t.Errorf("Failed %s: error: %+v", msg, err)
        }
    }
}

func assertEqualT(t *testing.T) func(any, any, string) {
    return func(actual any, expected any, msg string) {
        if !reflect.DeepEqual(actual, expected) {
            t.Errorf("Failed %s: actual: %v, expected: %v", msg, actual, expected)
        }
    }
}

func Test_Exists(t *testing.T) {
    assertEqual := assertEqualT(t)

    fs := filesystem.New()

    res := fs.Exists("./testdata/test.txt")
    assertEqual(res, true, "Test_Exists")

    res2 := fs.Exists("./testdata/test2.txt")
    assertEqual(res2, false, "Test_Exists 2")
}

func Test_Get(t *testing.T) {
    assertEqual := assertEqualT(t)

    fs := filesystem.New()

    res, err := fs.Get("./testdata/test.txt")
    if err != nil {
        t.Fatal(err.Error())
    }

    assertEqual(string(res), "testdata", "Test_Get")
}

func Test_MimeType(t *testing.T) {
    assertEqual := assertEqualT(t)

    fs := filesystem.New()

    res := fs.MimeType("./testdata/test.txt")
    assertEqual(res, "application/octet-stream", "Test_MimeType")
}

func Test_LastModified(t *testing.T) {
    fs := filesystem.New()

    res := fs.LastModified("./testdata/test.txt")

    ts := int64(1733803713)
    if res < ts {
        t.Errorf("got %d, want %d", res, ts)
    }
}

func Test_Size(t *testing.T) {
    assertEqual := assertEqualT(t)

    fs := filesystem.New()

    res := fs.Size("./testdata/test.txt")
    assertEqual(res, int64(8), "Test_GetSize")
}

func Test_Put(t *testing.T) {
    assertEqual := assertEqualT(t)

    fs := filesystem.New()

    // 使用
    err := fs.Put("./testdata/testcopy.txt", []byte("testtestdata1111111"))
    if err != nil {
        t.Fatal(err.Error())
    }

    res2, err := fs.Get("./testdata/testcopy.txt")
    if err != nil {
        t.Fatal(err.Error())
    }

    assertEqual(string(res2), "testtestdata1111111", "Test_Write")

    // 使用
    err = fs.Put("./testdata/testcopy.txt", []byte("testdata"))
    if err != nil {
        t.Fatal(err.Error())
    }
}

func Test_Prepend(t *testing.T) {
    assertEqual := assertEqualT(t)

    fs := filesystem.New()

    // 使用
    err := fs.Prepend("./testdata/testcopy.txt", []byte("222222222"))
    if err != nil {
        t.Fatal(err.Error())
    }

    res2, err := fs.Get("./testdata/testcopy.txt")
    if err != nil {
        t.Fatal(err.Error())
    }

    assertEqual(string(res2), "222222222testdata", "Test_Prepend")

    // 使用
    err = fs.Put("./testdata/testcopy.txt", []byte("testdata"))
    if err != nil {
        t.Fatal(err.Error())
    }
}

func Test_Append(t *testing.T) {
    assertEqual := assertEqualT(t)

    fs := filesystem.New()

    // 使用
    err := fs.Append("./testdata/testcopy.txt", []byte("222222222"))
    if err != nil {
        t.Fatal(err.Error())
    }

    res2, err := fs.Get("./testdata/testcopy.txt")
    if err != nil {
        t.Fatal(err.Error())
    }

    assertEqual(string(res2), "testdata222222222", "Test_Append")

    // 使用
    err = fs.Put("./testdata/testcopy.txt", []byte("testdata"))
    if err != nil {
        t.Fatal(err.Error())
    }
}

func Test_Rename(t *testing.T) {
    assertEqual := assertEqualT(t)

    fs := filesystem.New()

    // 使用
    err := fs.Rename("./testdata/testcopy.txt", "./testdata/testcopy222.txt")
    if err != nil {
        t.Fatal(err.Error())
    }

    res2 := fs.Exists("./testdata/testcopy222.txt")
    assertEqual(res2, true, "Test_Rename")

    // 使用
    err = fs.Rename("./testdata/testcopy222.txt", "./testdata/testcopy.txt")
    if err != nil {
        t.Fatal(err.Error())
    }

    res3 := fs.Exists("./testdata/testcopy222.txt")
    assertEqual(res3, false, "Test_Rename Rename 1")

    res33 := fs.Exists("./testdata/testcopy.txt")
    assertEqual(res33, true, "Test_Rename Rename 2")

}

func Test_Copy(t *testing.T) {
    assertEqual := assertEqualT(t)

    fs := filesystem.New()

    err := fs.Copy("./testdata/testcopy.txt", "./testdata/newtestcopy.txt")
    if err != nil {
        t.Fatal(err.Error())
    }

    res2 := fs.Exists("./testdata/newtestcopy.txt")
    assertEqual(res2, true, "Test_Copy Exists")

    res3 := fs.Delete("./testdata/newtestcopy.txt")
    if res3 != nil {
        t.Fatal(res3.Error())
    }

    res33 := fs.Exists("./testdata/newtestcopy.txt")
    assertEqual(res33, false, "Test_Copy Delete after Exists")
}

func Test_MakeDirectory(t *testing.T) {
    assertEqual := assertEqualT(t)

    fs := filesystem.New()

    err := fs.MakeDirectory("./testdata/testdir", 755)
    if err != nil {
        t.Fatal(err.Error())
    }

    res2 := fs.Exists("./testdata/testdir")
    assertEqual(res2, true, "Test_CreateDir Has")

    res3 := fs.DeleteDirectory("./testdata/testdir")
    if res3 != nil {
        t.Fatal(res3.Error())
    }

    res33 := fs.Exists("./testdata/testdir")
    assertEqual(res33, false, "Test_CreateDir Delete after Has")
}

func Test_IsFile(t *testing.T) {
    assertEqual := assertEqualT(t)

    fs := filesystem.New()

    res2 := fs.IsFile("./testdata/test.txt")
    assertEqual(res2, true, "Test_IsFile 1")

    res33 := fs.IsFile("./testdata/testdir")
    assertEqual(res33, false, "Test_IsFile 2")
}

func Test_IsDirectory(t *testing.T) {
    assertEqual := assertEqualT(t)

    fs := filesystem.New()

    res2 := fs.IsDirectory("./testdata/test.txt")
    assertEqual(res2, false, "Test_IsDirectory 1")

    res33 := fs.IsDirectory("./testdata")
    assertEqual(res33, true, "Test_IsDirectory 2")
}

func Test_Directories(t *testing.T) {
    assertEqual := assertEqualT(t)

    fs := filesystem.New()

    res, err := fs.Directories("./testdata")
    if err != nil {
        t.Fatal(err.Error())
    }

    assertEqual(res, []string{
        "testdir222",
    }, "Test_Directories")
}
