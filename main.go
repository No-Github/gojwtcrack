package main

import (
	"bufio"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"gojwtcrack/mod"
	"log"
	"os"
	"strings"
	"sync"
)

type Header struct {
	Typ string `json:"typ"`
	Alg string `json:"alg"`
}

type Token struct {
	header    string
	payload   string
	signature []byte
}

func main() {

	flag.Parse()
	if mod.TokenFile == "" {
		log.Fatal("Must specify -t")
	}

	var inputStream *bufio.Scanner
	if mod.DictFile == "" {
		inputStream = bufio.NewScanner(os.Stdin)
	} else {
		file, err := os.Open(mod.DictFile)
		defer file.Close()

		if err != nil {
			log.Fatal(err)
		}

		inputStream = bufio.NewScanner(file)
	}

	file, err := os.Open(mod.TokenFile)
	if err != nil {
		log.Fatal(err)
	}

	s := bufio.NewScanner(file)
	s.Scan()
	t := s.Text()
	crackJWT(t, mod.WorkerCount, inputStream)
}

func crackJWT(token string, workerCount int, scanner *bufio.Scanner) bool {
	var wg sync.WaitGroup
	queue := make(chan string)

	t := parseToken(token)
	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func() {
			for secret := range queue {
				headerPayload := t.header + "." + t.payload
				isMatch := checkSignature(secret, []byte(headerPayload), t.signature)
				if isMatch == true {
					fmt.Println(secret + "\t" + token)
					os.Exit(0)
				}
			}
			wg.Done()
		}()
	}

	for scanner.Scan() {
		queue <- scanner.Text()
	}
	close(queue)
	wg.Wait()
	return true
}

func checkSignature(secret string, headerPayload []byte, validSignature []byte) bool {
	var h = hmac.New(sha256.New, []byte(secret))
	h.Write(headerPayload)
	if hmac.Equal(h.Sum(nil), validSignature) {
		return true
	}
	return false
}

func parseToken(token string) Token {
	var t = strings.Split(token, ".")
	if len(t) != 3 {
		fmt.Println("Invalid token")
		os.Exit(1)

	}

	header := t[0]
	str, err := base64.RawURLEncoding.DecodeString(header)
	//fmt.Printf("%q\n", str)
	if err != nil {
		log.Fatal(err)
	}

	var h Header
	err = json.Unmarshal([]byte(str), &h)
	if err != nil {
		log.Fatal(err)
	}

	if h.Typ != "JWT" {
		log.Fatal("Invalid token")
	}

	if h.Alg != "HS256" {
		log.Fatal("Currently only HS256 is supported")
	}

	base64Sig := t[2]
	s, err := base64.RawURLEncoding.DecodeString(base64Sig)
	if err != nil {
		log.Fatal(err)
	}
	ts := Token{header: t[0], payload: t[1], signature: s}
	return ts

}
