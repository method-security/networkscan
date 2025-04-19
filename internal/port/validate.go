package port

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	portFern "github.com/Method-Security/networkscan/generated/go/port"
)

func RunPortScanValidate(ctx context.Context, config *portFern.PortScanValidateConfig) (*portFern.PortScanValidateReport, error) {

	resources := portFern.PortScanValidateReport{
		Config: config,
	}
	errors := []string{}

	portscanResult, err := RunPortScan(ctx, config.Target, *config.Ports, *config.Topports, config.Threads, strings.ToLower(string(config.Scantype)))
	if err != nil {
		errors = append(errors, err.Error())
	}

	hostDetails := []*portFern.HostValidateDetails{}
	var mu sync.Mutex // For safely appending to slices
	var wg sync.WaitGroup
	sem := make(chan struct{}, config.Threads) // Semaphore to limit concurrency

	hostChan := make(chan *portFern.HostValidateDetails)
	errorChan := make(chan string)

	// Worker goroutines to process hosts
	for _, host := range portscanResult.Hosts {
		host := host // Capture variable for goroutine
		wg.Add(1)
		go func() {
			defer wg.Done()

			// Acquire semaphore
			sem <- struct{}{}
			defer func() { <-sem }() // Release semaphore

			hostDetail := &portFern.HostValidateDetails{
				Host: host.Host,
				Ip:   host.Ip,
			}
			ports := []*portFern.PortValidateDetails{}
			var portWG sync.WaitGroup

			for _, p := range host.Ports {
				p := p // Capture variable for goroutine
				portWG.Add(1)
				go func() {
					defer portWG.Done()
					log.Println("Sending requests to", host.Host, "on port", p.Port)

					portDetails := &portFern.PortValidateDetails{Port: p.Port}

					// IP request
					ipRequest := sendHTTPRequest(host.Ip, p.Port, config.Timeout, config.SkipTlsVerify)
					portDetails.IpRequest = ipRequest

					// Host request
					hostRequest := sendHTTPRequest(host.Host, p.Port, config.Timeout, config.SkipTlsVerify)
					portDetails.HostRequest = hostRequest

					// Append port details safely
					mu.Lock()
					ports = append(ports, portDetails)
					mu.Unlock()
				}()
			}
			portWG.Wait()
			hostDetail.PortDetails = ports

			// Send the completed host details to the channel
			hostChan <- hostDetail
		}()
	}

	// Goroutine to collect results from hostChan
	go func() {
		wg.Wait()
		close(hostChan)
		close(errorChan)
	}()

	// Collect results from channels
	for hostDetail := range hostChan {
		hostDetails = append(hostDetails, hostDetail)
	}
	for errMsg := range errorChan {
		errors = append(errors, errMsg)
	}

	resources.Hosts = hostDetails
	resources.Errors = errors

	return &resources, nil
}

func sendHTTPRequest(target string, targetPort int, timeout int, skipTLSVerify bool) *portFern.HttpRequest {
	address := fmt.Sprintf("%s:%d", target, targetPort)

	// Create a custom HTTP client
	client := &http.Client{
		Timeout: time.Duration(timeout) * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: skipTLSVerify},
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return net.DialTimeout(network, address, time.Duration(timeout)*time.Second)
			},
		},
	}

	url := fmt.Sprintf("https://%s", address)
	request := &portFern.HttpRequest{
		Url:    url,
		Method: "GET",
	}

	resp, err := client.Get(url)
	if err != nil {
		errString := err.Error()

		// Retry with HTTP if specific error occurs
		if strings.Contains(errString, "http: server gave HTTP response to HTTPS client") {
			url = fmt.Sprintf("http://%s", address)
			resp, err = client.Get(url)
			if err != nil {
				request.Error = &errString
				return request
			}
		} else {
			request.Error = &errString
			return request
		}
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		errString := err.Error()
		request.Error = &errString
		return request
	}

	err = resp.Body.Close()
	if err != nil {
		errString := err.Error()
		request.Error = &errString
		return request
	}

	bodyString := string(body)
	request.Url = url
	request.ResponseBody = &bodyString
	request.ResponseCode = &resp.StatusCode

	return request
}
