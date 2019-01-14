package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

type dnserr struct {
	Err string
}

type cliSettings struct {
	Domain       string
	WordlistFile string
	Threads      int
}

type semaphore chan bool

var sem semaphore
var settings cliSettings
var dnsnames chan string

func main() {
	printme()
	parseFlags()

	sem = make(semaphore, 1)
	dnsnames = make(chan string, settings.Threads)
	sem <- true
	solved := make(map[string]bool)

	var wg sync.WaitGroup

	wg.Add(1)
	go findByDnsDumpster(&wg, solved)

	wg.Add(1)
	go findByWordList(&wg, solved)

	wg.Wait()
}

func printme() {
	fmt.Println()
	fmt.Println("Developed by © SanSYS (https://github.com/SanSYS)")
	fmt.Println()
}

func findByDnsDumpster(wg *sync.WaitGroup, solved map[string]bool) {
	defer wg.Done()

	resp, httpErr := http.Get("https://dnsdumpster.com")

	if httpErr != nil {
		fmt.Println("Fail in usage dnsdumpster.com")
		return
	}

	strResp, httpErr := ioutil.ReadAll(resp.Body)

	r := regexp.MustCompile("csrfmiddlewaretoken.+value='(.+)'")
	match := r.FindAllString(string(strResp), 1)
	csrf := match[0][29:60]

	vals := make(url.Values)
	vals.Set("csrfmiddlewaretoken", csrf)
	vals.Set("targetip", settings.Domain)

	body := strings.NewReader(vals.Encode())

	httpClient := &http.Client{Timeout: time.Second * 60}
	req, _ := http.NewRequest("POST", "https://dnsdumpster.com/", body)
	req.Header.Add("Origin", "https://dnsdumpster.com/")
	req.Header.Add("Referer", "https://dnsdumpster.com/")
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Cookie", "csrftoken="+csrf)

	resp, httpErr = httpClient.Do(req)

	if httpErr != nil {
		fmt.Println("Fail in usage dnsdumpster.com")
		return
	}

	if httpErr == nil {
		r = regexp.MustCompile("col-md-4\">(.+)." + settings.Domain + "<br>")
		strResp, _ := ioutil.ReadAll(resp.Body)
		match = r.FindAllString(string(strResp), -1)

		for i := 0; i < len(match); i++ {
			domain := match[i][10 : len(match[i])-4]
			dnsnames <- domain
		}
	}
}

func findByWordList(wg *sync.WaitGroup, solved map[string]bool) {
	defer wg.Done()

	file, err := os.Open(settings.WordlistFile)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	for i := 0; i < settings.Threads; i++ {
		wg.Add(1)
		go tryDns(wg, solved)
	}

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		subdomain := scanner.Text() + "." + settings.Domain
		dnsnames <- subdomain
	}

	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}

	for i := 0; i < settings.Threads; i++ {
		dnsnames <- ""
	}
}

func parseFlags() {
	flag.StringVar(&settings.Domain, "d", "", "Set domain scan like '-d ya.ru'")
	flag.StringVar(&settings.WordlistFile, "w", "wordlist.txt", "Set subdomains dictionary file like '-w wordlist.txt'")
	flag.IntVar(&settings.Threads, "t", 10, "Set parallelism like '-t 50'")

	flag.Parse()

	if settings.Domain == "" || settings.Domain == "site.ru" {
		flag.Usage()
		os.Exit(-1)
	}

	if settings.Threads <= 0 {
		fmt.Println("-t can not be less than 1")
		flag.Usage()
		os.Exit(-1)
	}

	fmt.Printf("Find subdomains for site:\t%s\r\n", settings.Domain)
	fmt.Printf("Subdomains dictionary file:\t%s\r\n", settings.WordlistFile)
	fmt.Printf("Threads:\t%d\r\n", settings.Threads)
	fmt.Println()
}

var cnt int = 0

func tryDns(wg *sync.WaitGroup, solved map[string]bool) {
	defer wg.Done()
	for {
		select {
		case dnsname := <-dnsnames:
			if dnsname == "" {
				return
			}

			cname, err := net.LookupCNAME(dnsname)

			<-sem
			if _, ok := solved[dnsname]; ok {
				sem <- true
				continue
			} else {
				solved[dnsname] = true
			}
			sem <- true

			if err != nil {
				jerr, _ := json.Marshal(err)
				var derr dnserr
				json.Unmarshal(jerr, &derr)

				// if jerr != nil && derr.Err == "dnsquery: DNS name does not exist." {
				// 	return
				// } else if jerr != nil && derr.Err == "dnsquery: This operation returned because the timeout period expired." {
				// 	return
				// } else {
				// 	fmt.Printf("%s\t%s", cname, err)
				continue
				//}
			}

			cname = cname[0 : len(cname)-1]

			iprecords, err := net.LookupIP(dnsname)

			for i, ip := range iprecords {
				httpClient := &http.Client{Timeout: time.Second * 3}
				url := fmt.Sprintf("http://%s", dnsname)
				req, herr := http.NewRequest("GET", url, nil)
				if herr != nil {
					fmt.Println(herr)
					continue
				}

				resp, httpErr := httpClient.Do(req)

				var respCode string

				if httpErr != nil {
					if resp != nil {
						respCode = strconv.Itoa(resp.StatusCode)
					} else {
						respCode = "?"
					}
				} else {
					respCode = strconv.Itoa(resp.StatusCode)
				}

				if dnsname == cname {
					cname = ""
				}

				linkType := "CNAME"

				if cname == "" {
					linkType = "HOST"
				}

				if i == 0 {
					fmt.Printf("%s\t%s\t%s\t%s\t\t%s\r\n", ip, respCode, linkType, dnsname, cname)
				}

				if cname != "" {
					go func() {
						dnsnames <- cname
					}()
				}
			}
		}
	}
}