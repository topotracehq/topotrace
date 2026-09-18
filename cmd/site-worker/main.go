// site-worker polls for explicitly approved discovery and deployment jobs.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"muster/internal/siteops"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

func main() {
	path := flag.String("config", "site-worker.json", "local worker configuration")
	once := flag.Bool("once", false, "poll once and exit")
	flag.Parse()
	b, e := os.ReadFile(*path)
	if e != nil {
		log.Fatal(e)
	}
	var c siteops.Config
	if e = json.Unmarshal(b, &c); e != nil {
		log.Fatal(e)
	}
	u, e := url.Parse(c.Server)
	if e != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || (u.Scheme != "https" && !(u.Scheme == "http" && c.AllowHTTP)) {
		log.Fatal("server must be HTTPS; protected LAN HTTP needs allow_http=true")
	}
	token := os.Getenv(c.TokenEnv)
	if token == "" || len(c.AllowedCIDRs) == 0 {
		log.Fatal("worker token environment and local allowed_cidrs required")
	}
	client := &http.Client{Timeout: 45 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	request := func(path string, body any) ([]byte, int, error) {
		b, _ := json.Marshal(body)
		r, e := http.NewRequest("POST", strings.TrimRight(c.Server, "/")+path, bytes.NewReader(b))
		if e != nil {
			return nil, 0, e
		}
		r.Header.Set("Authorization", "Bearer "+token)
		r.Header.Set("Content-Type", "application/json")
		resp, e := client.Do(r)
		if e != nil {
			return nil, 0, e
		}
		defer resp.Body.Close()
		b, e = io.ReadAll(io.LimitReader(resp.Body, 2<<20))
		if resp.StatusCode >= 300 {
			return nil, resp.StatusCode, fmt.Errorf("server returned %d", resp.StatusCode)
		}
		return b, resp.StatusCode, e
	}
	for {
		b, status, e := request("/api/worker/poll", nil)
		if e != nil {
			log.Printf("Poll failed: %v", e)
		} else if status == 200 {
			var t siteops.Task
			if e = json.Unmarshal(b, &t); e != nil {
				log.Fatal("invalid task response")
			}
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
			result, runErr := siteops.Run(ctx, c, t)
			cancel()
			if runErr != nil {
				log.Printf("Job %s: %v", t.Job.ID, runErr)
				result.Detail = runErr.Error()
			}
			result.OK = runErr == nil
			// Retry submitting the outcome, never re-execute a leased task.
			for attempt := 0; attempt < 3; attempt++ {
				_, _, e = request("/api/worker/results/"+t.Job.ID, result)
				if e == nil {
					break
				}
				log.Printf("Result submission failed: %v", e)
				time.Sleep(5 * time.Second)
			}
		}
		if *once {
			return
		}
		time.Sleep(15 * time.Second)
	}
}
