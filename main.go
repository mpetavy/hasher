package main

import (
	"crypto/md5"
	"crypto/sha256"
	"flag"
	"fmt"
	"github.com/mpetavy/common"
	"hash"
	"io"
	"os"
)

var (
	filename *string
	hashAlg  *string
)

func init() {
	common.Init(false, "1.0.0", "2017", "simple http tool", "mpetavy", fmt.Sprintf("https://github.com/mpetavy/%s", common.Title()), common.APACHE, nil, nil, run, 0)

	filename = flag.String("f", "", "filename to hash, '.' for STDIN")
	hashAlg = flag.String("h", "md5", "hash algorithmn (md5,sha224,sha256)")
}

func run() error {
	b, err := common.FileExists(*filename)
	if common.Error(err) {
		return err
	}

	if !b {
		return &common.ErrFileNotFound{FileName: *filename}
	}

	var hasher hash.Hash

	switch *hashAlg {
	case "":
	case "md5":
		hasher = md5.New()
	case "sha224":
		hasher = sha256.New224()
	case "sha256":
		hasher = sha256.New()
	default:
		common.Error(fmt.Errorf("unknown hash algorithm: %s", *hashAlg))
	}

	var file *os.File

	if *filename == "." {
		file = os.Stdin
	} else {
		file, err = os.Open(*filename)
		if common.Error(err) {
			return err
		}

		defer func() {
			common.Error(file.Close())
		}()
	}

	_, err = io.Copy(hasher, file)
	if common.Error(err) {
		return err
	}

	fmt.Printf("%v", hasher.Sum(nil))

	return nil
}

func main() {
	defer common.Done()

	common.Run([]string{"f"})
}
