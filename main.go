package main

import (
	"bytes"
	"crypto"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"github.com/mpetavy/common"
	"hash"
	"io"
	"os"
	"strings"
)

var (
	inputFile       = flag.String("i", "", "input file")
	outputFile      = flag.String("o", "", "output file")
	inputAlgorithm  = flag.String("ia", "", "hash algorithmn (md5,sha224,sha256,sha512,base64)")
	outputAlgorithm = flag.String("oa", "", "hash algorithmn (md5,sha224,sha256,sha512,base64)")
	text            = flag.String("t", "", "text input")

	notImplemented = fmt.Errorf("not implemented")
)

//go:embed go.mod
var resources embed.FS

func init() {
	common.Init("", "", "", "", "simple hashing tool", "", "", "", &resources, nil, nil, run, 0)
}

type Base64Encoder struct {
}

func (this Base64Encoder) Write(p []byte) (n int, err error) {
	common.Panic(notImplemented)

	return 0, nil
}

func (this Base64Encoder) Reset() {
	common.Panic(notImplemented)
}

func (this Base64Encoder) Size() int {
	common.Panic(notImplemented)

	return 0
}

func (this Base64Encoder) BlockSize() int {
	common.Panic(notImplemented)

	return 0
}

func (this Base64Encoder) Sum(b []byte) []byte {
	r := make([]byte, base64.StdEncoding.EncodedLen(len(b)))

	base64.StdEncoding.Encode(r, b)

	return r
}

type Base64Decoder struct {
}

func (this Base64Decoder) Write(p []byte) (n int, err error) {
	common.Panic(notImplemented)

	return 0, nil
}

func (this Base64Decoder) Reset() {
	common.Panic(notImplemented)
}

func (this Base64Decoder) Size() int {
	common.Panic(notImplemented)

	return 0
}

func (this Base64Decoder) BlockSize() int {
	common.Panic(notImplemented)

	return 0
}

func (this Base64Decoder) Sum(b []byte) []byte {
	r := make([]byte, base64.StdEncoding.DecodedLen(len(b)))

	_, err := base64.StdEncoding.Decode(r, b)
	common.Panic(err)

	return r
}

type NOPHash struct {
	bytes.Buffer
}

func (nopHash *NOPHash) Sum(b []byte) []byte {
	if b != nil {
		nopHash.Write(b)
	}

	return nopHash.Buffer.Bytes()
}

func (nopHash *NOPHash) Size() int {
	return nopHash.Len()
}

func (nopHash *NOPHash) BlockSize() int {
	return nopHash.BlockSize()
}

func findHash(alg string, isInput bool) (hash.Hash, error) {
	switch strings.ToUpper(alg) {
	case "":
		return &NOPHash{}, nil
	case crypto.MD5.String():
		return crypto.MD5.New(), nil
	case crypto.SHA224.String():
		return crypto.SHA224.New(), nil
	case crypto.SHA256.String():
		return crypto.SHA256.New(), nil
	case crypto.SHA512.String():
		return crypto.SHA512.New(), nil
	case "BASE64":
		if isInput {
			return &Base64Decoder{}, nil
		} else {
			return &Base64Encoder{}, nil
		}
	default:
		return nil, fmt.Errorf("unknown hash algorithm: %s", *inputAlgorithm)
	}
}

func run() error {
	if *inputFile != "" && !common.FileExists(*inputFile) {
		return &common.ErrFileNotFound{FileName: *inputFile}
	}

	inputHash, err := findHash(*inputAlgorithm, true)
	if common.Error(err) {
		return err
	}

	outputHash, err := findHash(*outputAlgorithm, false)
	if common.Error(err) {
		return err
	}

	var file io.Reader

	switch {
	case *text != "":
		file = strings.NewReader(*text)
	case *inputFile == "":
		file = os.Stdin
	case *inputFile != "":
		file, err = os.Open(*inputFile)
		if common.Error(err) {
			return err
		}

		defer func() {
			common.Error(file.(*os.File).Close())
		}()
	}

	ba, err := io.ReadAll(file)
	if common.Error(err) {
		return err
	}

	ba = inputHash.Sum(ba)

	ba = outputHash.Sum(ba)

	if *outputFile != "" {
		err := os.WriteFile(*outputFile, ba, common.DefaultFileMode)
		if common.Error(err) {
			return err
		}
	} else {
		if *outputAlgorithm != "" && *outputAlgorithm != "base64" {
			fmt.Printf("%s\n", hex.EncodeToString(ba))
		} else {
			fmt.Printf("%s\n", ba)
		}
	}

	return nil
}

func main() {
	common.Run([]string{"i|t"})
}
