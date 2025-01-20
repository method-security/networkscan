package port

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
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
	for _, host := range portscanResult.Hosts {
		hostDetail := &portFern.HostValidateDetails{
			Host: host.Host,
			Ip:   host.Ip,
		}
		ports := []*portFern.PortValidateDetails{}
		for _, p := range host.Ports {
			// Create portHttpDetail
			portDetails := &portFern.PortValidateDetails{Port: p.Port}

			// IP request
			ipRequest := sendHTTPRequest(host.Ip, p.Port, config.Timeout, config.SkipTlsVerify)
			portDetails.IpRequest = ipRequest

			// Host request
			hostRequest := sendHTTPRequest(host.Host, p.Port, config.Timeout, config.SkipTlsVerify)
			portDetails.HostRequest = hostRequest

			// Add to portHttpDetails
			ports = append(ports, portDetails)
		}
		hostDetail.PortDetails = ports
		hostDetails = append(hostDetails, hostDetail)
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

	// Attempt HTTPS first if httpsRequest is true, fallback to HTTP on specific error
	url := fmt.Sprintf("https://%s", address)

	// Initialize request structure
	request := &portFern.HttpRequest{
		Url:    url,
		Method: "GET",
	}

	resp, err := client.Get(url)
	if err != nil {
		errString := err.Error()

		// Check for specific HTTPS error and retry with HTTP
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

	// Read the response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		errString := err.Error()
		request.Error = &errString
		return request
	}

	// Close the response body
	err = resp.Body.Close()
	if err != nil {
		errString := err.Error()
		request.Error = &errString
		return request
	}

	// Populate request with response details
	bodyString := string(body)
	request.Url = url
	request.ResponseBody = &bodyString
	request.ResponseCode = &resp.StatusCode

	return request
}
