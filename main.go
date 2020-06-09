package main

import (
	"bufio"
	"crypto/rand"
	"encoding/json"
	"errors"
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

	"github.com/gorilla/websocket"
)

type dnserr struct {
	Err string
}

type cliSettings struct {
	Domain       string
	WordlistFile string
	Threads      int
	WebPort      int
	SyncId       string
}

type coutResult struct {
	SyncId string
	Type   string
	Result interface{}
}

type semaphore chan bool

var sem semaphore
var dnsnames chan string
var cout chan coutResult

func main() {
	// get hostname for run from ENV
	serverHost := GetENV("SERVER_HOST", "127.0.0.1")

	cout = make(chan coutResult)

	var settings cliSettings
	parseFlags(&settings)

	printme()
	fmt.Println("")
	if settings.Domain != "" {
		fmt.Printf("Find subdomains for site:\t%s\r\n", settings.Domain)
	}
	fmt.Printf("Subdomains dictionary file:\t%s\r\n", settings.WordlistFile)
	fmt.Printf("Threads:\t%d\r\n", settings.Threads)
	fmt.Println("")

	if settings.WebPort > 0 {

		http.Handle(
			"/",
			http.StripPrefix(
				"/",
				http.FileServer(http.Dir("static")),
			),
		)

		http.HandleFunc("/echo", func(w http.ResponseWriter, r *http.Request) {
			echo(w, r, cout)
		})

		http.HandleFunc("/scan", func(res http.ResponseWriter, req *http.Request) {
			scanSetting := cliSettings{}
			scanSetting.Domain = req.FormValue("domain")
			scanSetting.Threads, _ = strconv.Atoi(req.FormValue("threads"))
			scanSetting.WordlistFile = settings.WordlistFile
			scanSetting.SyncId = uuid()

			go runScan(&scanSetting)
		})

		addr := flag.String("addr", serverHost+":"+strconv.Itoa(settings.WebPort), "http service address")
		fmt.Println("Runned Web UI on http://" + *addr)
		log.Fatal(http.ListenAndServe(*addr, nil))
	} else {
		go func() {
			for {
				out := <-cout

				if out.Result == "done" {
					return
				}

				fmt.Println(out)
			}
		}()

		runScan(&settings)
	}
}

// GetENV get environment variable
func GetENV(name string, defaultValue string) string {
	val := os.Getenv(name)
	if val == "" {
		val = defaultValue
	}

	return val
}

func uuid() string {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		log.Fatal(err)
	}
	return fmt.Sprintf("%x-%x-%x-%x-%x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}

func runScan(settings *cliSettings) {
	sem = make(semaphore, 1)
	dnsnames = make(chan string, settings.Threads)
	sem <- true
	solved := make(map[string]bool)

	var wg sync.WaitGroup

	wg.Add(1)
	go findByDnsDumpster(&wg, solved, settings)

	wg.Add(1)
	go findByWordList(&wg, solved, settings)

	wg.Wait()

	cout <- coutResult{Type: "console", Result: "done", SyncId: settings.SyncId}
}

func printme() {
	fmt.Println("")
	fmt.Println("Developed by © SanSYS (https://github.com/SanSYS)")
	fmt.Println("")
}

func findByDnsDumpster(wg *sync.WaitGroup, solved map[string]bool, settings *cliSettings) {
	defer wg.Done()

	resp, httpErr := http.Get("https://dnsdumpster.com")

	if httpErr != nil {
		cout <- coutResult{Type: "error", Result: fmt.Sprintf("Fail in usage dnsdumpster.com"), SyncId: settings.SyncId}
		return
	}

	strResp, httpErr := ioutil.ReadAll(resp.Body)

	if httpErr != nil {
		cout <- coutResult{Type: "error", Result: fmt.Sprintf("Fail in usage dnsdumpster.com"), SyncId: settings.SyncId}
		return
	}

	r := regexp.MustCompile("csrfmiddlewaretoken.+value=['\"](.+)['\"]")
	match := r.FindAllString(string(strResp), 1)
	if len(match) == 0 {
		cout <- coutResult{Type: "error", Result: fmt.Sprintf("Fail in usage dnsdumpster.com"), SyncId: settings.SyncId}
		return
	}

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
		cout <- coutResult{Type: "error", Result: fmt.Sprintf("Fail in usage dnsdumpster.com"), SyncId: settings.SyncId}
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

func findByWordList(wg *sync.WaitGroup, solved map[string]bool, settings *cliSettings) {
	defer wg.Done()

	file, err := os.Open(settings.WordlistFile)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	for i := 0; i < settings.Threads; i++ {
		wg.Add(1)
		go tryDns(wg, solved, settings)
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

func parseFlags(settings *cliSettings) {
	flag.StringVar(&settings.Domain, "d", "", "Set domain scan like '-d ya.ru'")
	flag.StringVar(&settings.WordlistFile, "w", "wordlist.txt", "Set subdomains dictionary file like '-w wordlist.txt'")
	flag.IntVar(&settings.Threads, "t", 10, "Set parallelism like '-t 50'")
	flag.IntVar(&settings.WebPort, "ui", 0, "Enable user interface on port '-ui 8080'")

	flag.Parse()

	if settings.WebPort == 0 {
		if settings.Domain == "" || settings.Domain == "site.ru" {
			flag.Usage()
			os.Exit(-1)
		}
	}

	if settings.Threads <= 0 {
		fmt.Println("-t can not be less than 1")
		flag.Usage()
		os.Exit(-1)
	}
}

var cnt int = 0

func tryDns(wg *sync.WaitGroup, solved map[string]bool, settings *cliSettings) {
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

				continue
			}

			cname = cname[0 : len(cname)-1]

			iprecords, err := net.LookupIP(dnsname)

			for i, ip := range iprecords {
				_, respCode, herr := getWebResponse(fmt.Sprintf("http://%s", dnsname), settings)

				if herr != nil {
					if herr.Error() != "exit" {
						_, respCode, herr = getWebResponse(fmt.Sprintf("https://%s", dnsname), settings)
					}

					if herr != nil && herr.Error() == "exit" {
						cout <- coutResult{Type: "error", Result: fmt.Sprint(herr), SyncId: settings.SyncId}
						continue
					}
				}

				if dnsname == cname {
					cname = ""
				}

				linkType := "CNAME"

				if cname == "" {
					linkType = "HOST"
				}

				if i == 0 {
					res := struct {
						Ip       string
						RespCode string
						LinkType string
						Dnsname  string
						Cname    string
					}{Ip: ip.String(), RespCode: respCode, LinkType: linkType, Dnsname: dnsname, Cname: cname}

					cout <- coutResult{Type: "domain", Result: res, SyncId: settings.SyncId}
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

func getWebResponse(url string, settings *cliSettings) (string, string, error) {
	httpClient := &http.Client{Timeout: time.Second * 3}

	req, herr := http.NewRequest("GET", url, nil)
	if herr != nil {
		cout <- coutResult{Type: "error", Result: fmt.Sprint(herr), SyncId: settings.SyncId}

		return "", "?", errors.New("exit")
	}

	resp, httpErr := httpClient.Do(req)

	var respCode string

	if httpErr != nil {
		if resp != nil {
			respCode = strconv.Itoa(resp.StatusCode)
			return "", respCode, httpErr
		}

		return "", "?", httpErr
	}

	respCode = strconv.Itoa(resp.StatusCode)

	return "", respCode, nil
}

var upgrader = websocket.Upgrader{} // use default options

func echo(w http.ResponseWriter, r *http.Request, zc <-chan coutResult) {
	c, err := upgrader.Upgrade(w, r, nil)

	if err != nil {
		log.Print("upgrade:", err)
		return
	}

	defer c.Close()

	for {
		res := <-zc
		msg, _ := json.Marshal(res)

		c.WriteMessage(1, msg)
	}
}
