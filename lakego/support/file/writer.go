package file

import (
	"fmt"
	"os"
	"path"
)

func WriteBytes(filePath string, b []byte) (n int, err error) {
	if err := os.MkdirAll(path.Dir(filePath), os.ModePerm); err != nil {
		return 0, fmt.Errorf("mkdir error: %s", err)
	}

	fw, err := os.Create(filePath)
	if err != nil {
		return 0, err
	}

	defer func() {
		cerr := fw.Close()
		if err == nil {
			err = cerr
		}
	}()

	n, err = fw.Write(b)
	return
}

func WriteString(filePath string, s string) (int, error) {
	return WriteBytes(filePath, []byte(s))
}
