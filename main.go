package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

func main() {

	var domains []string

	var dates bool
	flag.BoolVar(&dates, "dates", false, "show date of fetch in the first column")

	var noSubs bool
	flag.BoolVar(&noSubs, "no-subs", false, "don't include subdomains of the target domain")

	flag.Parse()

	if flag.NArg() > 0 {
		domains = []string{flag.Arg(0)}
	} else {
		sc := bufio.NewScanner(os.Stdin)
		for sc.Scan() {
			domains = append(domains, sc.Text())
		}
		if err := sc.Err(); err != nil {
			fmt.Fprintf(os.Stderr, "failed to read input: %s\n", err)
		}
	}

	fetchFns := []fetchFn{
		getWaybackParams,
		getCommonCrawlParams,
		getVirusTotalParams,
	}

	for _, domain := range domains {

		var wg sync.WaitGroup
		paramsChan := make(chan paramData)

		for _, fn := range fetchFns {
			wg.Add(1)
			fetch := fn
			go func() {
				defer wg.Done()
				resp, err := fetch(domain, noSubs)
				if err != nil {
					return
				}
				for _, r := range resp {
					if noSubs && isSubdomain(r.url, domain) {
						continue
					}
					paramsChan <- r
				}
			}()
		}

		go func() {
			wg.Wait()
			close(paramsChan)
		}()

		seen := make(map[string]bool)
		for p := range paramsChan {
			key := p.param
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = true

		
			cleanDomain := strings.TrimPrefix(strings.TrimPrefix(domain, "https://"), "http://")

			if dates && p.date != "" {
				d, err := time.Parse("20060102150405", p.date)
				if err != nil {
					fmt.Fprintf(os.Stderr, "failed to parse date [%s] for param [%s]\n", p.date, key)
					fmt.Printf("https://%s/?%s=\n", cleanDomain, key)
					continue
				}
				fmt.Printf("%s https://%s/?%s=\n", d.Format(time.RFC3339), cleanDomain, key)
			} else {
				fmt.Printf("https://%s/?%s=\n", cleanDomain, key)
			}
		}
	}
}

type paramData struct {
	date  string
	url   string
	param string
}

type fetchFn func(string, bool) ([]paramData, error)

func getWaybackParams(domain string, noSubs bool) ([]paramData, error) {
	subsWildcard := "*."
	if noSubs {
		subsWildcard = ""
	}

	res, err := http.Get(
		fmt.Sprintf("http://web.archive.org/cdx/search/cdx?url=%s%s/*&output=json&collapse=urlkey", subsWildcard, domain),
	)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	raw, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	var wrapper [][]string
	err = json.Unmarshal(raw, &wrapper)
	if err != nil {
		return nil, err
	}

	out := make([]paramData, 0)
	skip := true
	for _, urls := range wrapper {
		if skip {
			skip = false
			continue
		}
		u := urls[2]
		parsed, err := url.Parse(u)
		if err != nil {
			continue
		}
		for k := range parsed.Query() {
			out = append(out, paramData{
				date:  urls[1],
				url:   u,
				param: k,
			})
		}
	}

	return out, nil
}

func getCommonCrawlParams(domain string, noSubs bool) ([]paramData, error) {
	subsWildcard := "*."
	if noSubs {
		subsWildcard = ""
	}

	res, err := http.Get(
		fmt.Sprintf("http://index.commoncrawl.org/CC-MAIN-2018-22-index?url=%s%s/*&output=json", subsWildcard, domain),
	)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	sc := bufio.NewScanner(res.Body)
	out := make([]paramData, 0)

	for sc.Scan() {
		wrapper := struct {
			URL       string `json:"url"`
			Timestamp string `json:"timestamp"`
		}{}
		err = json.Unmarshal([]byte(sc.Text()), &wrapper)
		if err != nil {
			continue
		}
		parsed, err := url.Parse(wrapper.URL)
		if err != nil {
			continue
		}
		for k := range parsed.Query() {
			out = append(out, paramData{
				date:  wrapper.Timestamp,
				url:   wrapper.URL,
				param: k,
			})
		}
	}

	return out, nil
}

func getVirusTotalParams(domain string, noSubs bool) ([]paramData, error) {
	out := make([]paramData, 0)

	apiKey := os.Getenv("VT_API_KEY")
	if apiKey == "" {
		return out, nil
	}

	fetchURL := fmt.Sprintf(
		"https://www.virustotal.com/vtapi/v2/domain/report?apikey=%s&domain=%s",
		apiKey,
		domain,
	)

	resp, err := http.Get(fetchURL)
	if err != nil {
		return out, err
	}
	defer resp.Body.Close()

	wrapper := struct {
		URLs []struct {
			URL string `json:"url"`
		} `json:"detected_urls"`
	}{}

	dec := json.NewDecoder(resp.Body)
	err = dec.Decode(&wrapper)
	if err != nil {
		return out, err
	}

	for _, u := range wrapper.URLs {
		parsed, err := url.Parse(u.URL)
		if err != nil {
			continue
		}
		for k := range parsed.Query() {
			out = append(out, paramData{
				url:   u.URL,
				param: k,
			})
		}
	}

	return out, nil
}

func isSubdomain(rawUrl, domain string) bool {
	u, err := url.Parse(rawUrl)
	if err != nil {
		return false
	}
	return strings.ToLower(u.Hostname()) != strings.ToLower(domain)
}
