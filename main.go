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
	input   *string
	output  *string
	hashAlg *string
	text    *string
)

type base64dEncoder struct {
	hash.Hash

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
	hash.Hash

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

//go:embed go.mod
var resources embed.FS

func init() {
	common.Init("", "", "", "", "simple hashing tool", "", "", "", &resources, nil, nil, run, 0)

	input = flag.String("i", "", "input file")
	output = flag.String("o", "", "output file")
	hashAlg = flag.String("a", "MD5", "hash algorithmn (MD5,SHA224,SHA256,SHA512,BASE64ENC,BASE64DEC)")
	text = flag.String("t", "", "text input")
}

func run() error {
	if *input != "" && !common.FileExists(*input) {
		return &common.ErrFileNotFound{FileName: *input}
	}

	var algorithm hash.Hash

	switch strings.ToUpper(*hashAlg) {
	case crypto.MD5.String():
		algorithm = crypto.MD5.New()
	case crypto.SHA224.String():
		algorithm = crypto.SHA224.New()
	case crypto.SHA256.String():
		algorithm = crypto.SHA256.New()
	case crypto.SHA512.String():
		algorithm = crypto.SHA512.New()
	case "BASE64ENC":
		algorithm = NewBase64Encoder()
	case "BASE64DEC":
		algorithm = NewBase64Decoder()
	default:
		return fmt.Errorf("unknown hash algorithm: %s", *hashAlg)
	}

	var file io.Reader
	var err error

	switch {
	case *text != "":
		file = strings.NewReader(*text)
	case *input == "":
		file = os.Stdin
	case *input != "":
		file, err = os.Open(*input)
		if common.Error(err) {
			return err
		}

		defer func() {
			common.Error(file.(*os.File).Close())
		}()
	}

	_, err = io.Copy(algorithm, file)
	if common.Error(err) {
		return err
	}

	if *output != "" {
		err := os.WriteFile(*output, algorithm.Sum(nil), common.DefaultFileMode)
		if common.Error(err) {
			return err
		}
	} else {
		var txt string

		if strings.Index(*hashAlg, "base64") == 0 {
			txt = string(algorithm.Sum(nil))
		} else {
			txt = hex.EncodeToString(algorithm.Sum(nil))
		}

		fmt.Printf("%s\n", txt)
	}

	return nil
}

func main() {
	common.Run(nil)
}
