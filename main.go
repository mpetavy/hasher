package main

import (
	"bytes"
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"github.com/mpetavy/common"
	"io"
	"os"
	"strings"
)

var (
	input   *string
	output  *string
	hashAlg *string
)

type hasher interface {
	io.Writer
	Sum(b []byte) []byte
}

type base64dEncoder struct {
	buf *bytes.Buffer
}

func NewBase64Encoder() *base64dEncoder {
	return &base64dEncoder{
		buf: &bytes.Buffer{},
	}
}

func (this base64dEncoder) Sum(b []byte) []byte {
	_, err := this.Write(b)
	if common.Error(err) {
		return nil
	}

	if b != nil {
		return nil
	}

	r := make([]byte, base64.StdEncoding.EncodedLen(this.buf.Len()))

	base64.StdEncoding.Encode(r, this.buf.Bytes())

	return r
}

func (this *base64dEncoder) Write(b []byte) (int, error) {
	return this.buf.Write(b)
}

type base64dDecoder struct {
	buf *bytes.Buffer
}

func NewBase64Decoder() *base64dDecoder {
	return &base64dDecoder{
		buf: &bytes.Buffer{},
	}
}

func (this base64dDecoder) Sum(b []byte) []byte {
	_, err := this.Write(b)
	if common.Error(err) {
		return nil
	}

	if b != nil {
		return nil
	}

	r := make([]byte, base64.StdEncoding.DecodedLen(this.buf.Len()))

	_, err = base64.StdEncoding.Decode(r, this.buf.Bytes())
	if common.Error(err) {
		return nil
	}

	return r
}

func (this *base64dDecoder) Write(b []byte) (int, error) {
	return this.buf.Write(b)
}

func init() {
	common.Init(false, "1.0.0", "", "", "2017", "simple hashing tool", "mpetavy", fmt.Sprintf("https://github.com/mpetavy/%s", common.Title()), common.APACHE, nil, nil, nil, run, 0)

	input = flag.String("i", "", "input file")
	output = flag.String("o", "", "output file")
	hashAlg = flag.String("h", "md5", "hash algorithmn (md5,sha224,sha256)")
}

func run() error {
	if *input != "" && !common.FileExists(*input) {
		return &common.ErrFileNotFound{FileName: *input}
	}

	var hasher hasher

	switch *hashAlg {
	case "md5":
		hasher = md5.New()
	case "sha224":
		hasher = sha256.New224()
	case "sha256":
		hasher = sha256.New()
	case "base64encoder":
		hasher = NewBase64Encoder()
	case "base64decoder":
		hasher = NewBase64Decoder()
	default:
		return fmt.Errorf("unknown hash algorithm: %s", *hashAlg)
	}

	var file io.Reader
	var err error

	if *input == "" {
		file = os.Stdin
	} else {
		file, err = os.Open(*input)
		if common.Error(err) {
			return err
		}

		defer func() {
			common.Error(file.(*os.File).Close())
		}()
	}

	_, err = io.Copy(hasher, file)
	if common.Error(err) {
		return err
	}

	if *output != "" {
		err := os.WriteFile(*output, hasher.Sum(nil), common.DefaultFileMode)
		if common.Error(err) {
			return err
		}
	} else {
		var txt string

		if strings.Index(*hashAlg, "base64") == 0 {
			txt = string(hasher.Sum(nil))
		} else {
			txt = hex.EncodeToString(hasher.Sum(nil))
		}

		fmt.Printf("%s\n", txt)
	}

	return nil
}

func main() {
	defer common.Done()

	common.Run(nil)
}
