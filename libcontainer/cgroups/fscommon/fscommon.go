// +build linux

package fscommon

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

// WriteFile writes data to a cgroup file in dir.
// It is supposed to be used for cgroup files only.
func WriteFile(dir, file, data string) error {
	fd, err := OpenFile(dir, file, unix.O_WRONLY)
	if err != nil {
		return err
	}
	defer fd.Close()
	if err := retryingWriteFile(fd, data); err != nil {
		return errors.Wrapf(err, "failed to write %q", data)
	}
	return nil
}

// ReadFile reads data from a cgroup file in dir.
// It is supposed to be used for cgroup files only.
func ReadFile(dir, file string) (string, error) {
	fd, err := OpenFile(dir, file, unix.O_RDONLY)
	if err != nil {
		return "", err
	}
	defer fd.Close()
	var buf bytes.Buffer

	_, err = buf.ReadFrom(fd)
	return buf.String(), err
}

func CopyFile(source, dest string) error {
	var (
		srcF *os.File
		dstF *os.File
		data []byte
		err  error
	)

	srcF, err = os.Open(source)
	if err != nil {
		return fmt.Errorf("failed to open %s: %s", source, err)
	}
	defer srcF.Close()

	dstF, err = os.Open(dest)
	if err != nil {
		dstF.Close()
		return fmt.Errorf("failed to open %s: %s", dest, err)
	}
	defer dstF.Close()

	data, err = ioutil.ReadFile(source)
	if err != nil {
		return fmt.Errorf("failed to read %s: %s", source, err)
	}

	err = ioutil.WriteFile(dest, data, 0)
	if err != nil {
		return fmt.Errorf("failed to read %s: %s", dest, err)
	}

	return nil
}

func retryingWriteFile(fd *os.File, data string) error {
	for {
		_, err := fd.Write([]byte(data))
		if errors.Is(err, unix.EINTR) {
			logrus.Infof("interrupted while writing %s to %s", data, fd.Name())
			continue
		}
		return err
	}
}
