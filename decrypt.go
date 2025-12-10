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
	"log"
	"os"
	"path/filepath"
	"strings"
)

func openfile(path string) []byte {
	text, err := os.ReadFile(path)
	if err != nil {
		log.Fatal("err reading file", path)
	}
	return []byte(text)
}

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

func decrypt_files(files []string, key []byte) {
	c, err := aes.NewCipher(key)
	if err != nil {
		log.Fatal(err)
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		log.Fatal(err)
	}

	noncesize := gcm.NonceSize() // should be 12 for GCM

	for _, v := range files {
		enc_bytes := openfile(v)

		if len(enc_bytes) < noncesize+gcm.Overhead() {
			log.Fatalf("ciphertext too short in file %s", v)
		}

		nonce := enc_bytes[:noncesize]
		ciphertext := enc_bytes[noncesize:]

		plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
		if err != nil {
			log.Fatalf("GCM decrypt error in file %s: %v", v, err)
		}

		err = os.Remove(v)
		if err != nil {
			fmt.Print("couldn't remove file")
		}
		name := strings.TrimRight(v, ".wasted")
		err = os.WriteFile(name, plaintext, 0644)
		if err != nil {
			log.Print(err)
		}
	}
}

func load_priv_key_to_mem(path string) (*rsa.PrivateKey, error) {
	private_key_data, err := os.ReadFile(path)
	if err != nil {
		log.Fatal(err, "error in load key")
	}
	block, _ := pem.Decode(private_key_data)
	if block == nil {
		return nil, fmt.Errorf("couldn't resolve the blocker")
	}
	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("couldnt parse the key block", err)
	}
	return priv, nil
}

func decrypt_key(content []byte, priv *rsa.PrivateKey) error {
	decryptedBytes, err := rsa.DecryptOAEP(
		sha256.New(),
		rand.Reader,
		priv,
		content,
		nil)
	if err != nil {
		return fmt.Errorf("error here decoding", err)
	}

	log.Println("Decrypted key length:", len(decryptedBytes))
	return os.WriteFile("key.txt", decryptedBytes, 0600)
}

func main() {
	priv_key, err := load_priv_key_to_mem("/keys/private.rsa")
	if err != nil {
		log.Fatal(err)
	}
	data := openfile("/keys/key.txt")

	if err := decrypt_key(data, priv_key); err != nil {
		log.Fatal(err)
	}

	AES_key := openfile("key.txt")
	_, files := scandirs("path/to/your/folder")
	decrypt_files(files, AES_key)
}
