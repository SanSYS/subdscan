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
}

type semaphore chan bool

var sem semaphore
var settings cliSettings

func main() {
	printme()
	parseFlags()

	sem = make(semaphore, 1)
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
		r = regexp.MustCompile("<td class=\"col-md-4\">([\\w\\d]+)." + settings.Domain + "<br>")
		strResp, _ := ioutil.ReadAll(resp.Body)
		match = r.FindAllString(string(strResp), 1000)

		for i := 0; i < len(match); i++ {
			domain := match[i][21 : len(match[i])-4]
			wg.Add(1)
			go tryDns(domain, wg, solved)
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

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		subdomain := scanner.Text() + "." + settings.Domain
		wg.Add(1)
		go tryDns(subdomain, wg, solved)
	}

	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}
}

func parseFlags() {
	flag.StringVar(&settings.Domain, "d", "", "Set domain scan like '-d ya.ru'")
	flag.StringVar(&settings.WordlistFile, "w", "wordlist.txt", "Set subdomains dictionary file like '-w wordlist.txt'")

	flag.Parse()

	if settings.Domain == "" || settings.Domain == "site.ru" {
		flag.Usage()
		os.Exit(0)
	}

	fmt.Printf("Find subdomains for site:\t%s\r\n", settings.Domain)
	fmt.Printf("Subdomains dictionary file:\t%s\r\n", settings.WordlistFile)
	fmt.Println()
}

func tryDns(dnsname string, wg *sync.WaitGroup, solved map[string]bool) {
	defer wg.Done()

	cname, err := net.LookupCNAME(dnsname)

	<-sem
	if _, ok := solved[dnsname+cname]; ok {
		sem <- true
		return
	} else {
		solved[dnsname+cname] = true
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
		return
		//}
	}

	cname = cname[0 : len(cname)-1]

	iprecords, err := net.LookupIP(dnsname)

	for _, ip := range iprecords {
		httpClient := &http.Client{Timeout: time.Second * 3}
		url := fmt.Sprintf("http://%s", dnsname)
		req, herr := http.NewRequest("GET", url, nil)
		if herr != nil {
			fmt.Println(herr)
			return
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

		fmt.Printf("%s\t%s\t%s\t%s\t\t%s\r\n", ip, respCode, linkType, dnsname, cname)

		if cname != "" {
			wg.Add(1)
			go tryDns(cname, wg, solved)
		}
	}
}
