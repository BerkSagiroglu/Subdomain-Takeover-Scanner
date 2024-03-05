package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
)

// Fingerprints struct to hold fingerprint data
type Fingerprints struct {
	Fingerprint string   `json:"Fingerprint"`
	Service     string   `json:"Service"`
	Cname       []string `json:"Cname"`
}

func main() {
	// Okunacak dosya adı
	filename := "fingerprints.json"

	// Fingerprints JSON dosyasını oku
	fingerprints, err := readFingerprints(filename)
	if err != nil {
		fmt.Println("Fingerprint file can't read.:", err)
		return
	}

	// Okunacak dosya adı
	subdomainFilename := "subdomains.txt"

	// Dosyayı aç
	file, err := os.Open(subdomainFilename)
	if err != nil {
		fmt.Println("Subdomain file can't opened.:", err)
		return
	}
	defer file.Close()

	var wg sync.WaitGroup
	scanner := bufio.NewScanner(file)

	// Satırları oku
	for scanner.Scan() {
		subdomain := scanner.Text()
		wg.Add(1)
		go func(subdomain string) {
			defer wg.Done()
			checkSubdomain(subdomain, fingerprints)
		}(subdomain)
	}

	wg.Wait()
}

func readFingerprints(filename string) (map[string]Fingerprints, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var fingerprints map[string]Fingerprints
	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&fingerprints); err != nil {
		return nil, err
	}

	return fingerprints, nil
}

func checkSubdomain(subdomain string, fingerprints map[string]Fingerprints) {
	// HTTP GET isteği yap
	resp, err := http.Get("http://" + subdomain)
	if err != nil {
		fmt.Printf("%s: Connection error.\n", subdomain)
		return
	}
	defer resp.Body.Close()

	// Eğer hedef subdomain'in response kodu 404 ise subdomain takeover zafiyeti olabilir
	if resp.StatusCode == http.StatusNotFound {
		bodyText := make([]byte, 512)
		_, err := resp.Body.Read(bodyText)
		if err != nil {
			fmt.Printf("%s: 404 - Could be subdomain takeover.\n", subdomain)
		} else {
			bodyStr := string(bodyText)
			for _, fp := range fingerprints {
				if strings.Contains(bodyStr, fp.Fingerprint) {
					fmt.Printf("%s: 404 - Could be subdomain takeover. (%s)\n", subdomain, fp.Service)
					return
				}
			}
			fmt.Printf("%s: 404 - It can be False-Positive.\n", subdomain)
		}
	} else {
		fmt.Printf("%s: HTTP status code %d\n", subdomain, resp.StatusCode)
	}
}
