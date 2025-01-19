package port

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"time"

	"github.com/Method-Security/networkscan/generated/go/port"
)

func RunPortHTTP(ctx context.Context, target string, ports string, topport string, threads int, scantype string, timeout int, httpsRequest bool, tlsVerify bool) (*port.PortHttpReport, error) {
	resources := port.PortHttpReport{}
	errors := []string{}

	portscanResult, err := RunPortScan(ctx, target, ports, topport, threads, scantype)
	if err != nil {
		errors = append(errors, err.Error())
	}
	hostDetails := []*port.HostHttpDetails{}
	for _, host := range portscanResult.Hosts {
		hostDetail := &port.HostHttpDetails{
			Host: host.Host,
			Ip:   host.Ip,
		}
		ports := []*port.PortHttpDetails{}
		for _, p := range host.Ports {
			// Create portHttpDetail
			portDetails := &port.PortHttpDetails{Port: p.Port}

			// IP request
			ipRequest := sendHTTPRequest(host.Ip, p.Port, timeout, httpsRequest, tlsVerify)
			portDetails.IpRequest = ipRequest

			// Host request
			hostRequest := sendHTTPRequest(host.Host, p.Port, timeout, httpsRequest, tlsVerify)
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

func sendHTTPRequest(host string, targetPort int, timeout int, httpsRequest bool, tlsVerify bool) *port.HttpRequest {
	address := fmt.Sprintf("%s:%d", host, targetPort)

	// Create a custom HTTP client
	client := &http.Client{
		Timeout: time.Duration(timeout) * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: !tlsVerify},
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return net.DialTimeout(network, address, time.Duration(timeout)*time.Second)
			},
		},
	}

	// Send an HTTP or HTTPS GET request
	var url string
	if httpsRequest {
		url = fmt.Sprintf("https://%s", address)
	} else {
		url = fmt.Sprintf("http://%s", address)
	}

	// Initialize request
	request := &port.HttpRequest{
		Url:    url,
		Method: "GET",
	}

	resp, err := client.Get(url)
	if err != nil {
		log.Printf("Error connecting to %s: %v\n", address, err)
		errString := err.Error()
		request.Error = &errString
		return request
	}

	// Read and display the response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		errString := err.Error()
		request.Error = &errString
		return request
	}
	bodyString := string(body)

	// Close the response body
	err = resp.Body.Close()
	if err != nil {
		log.Printf("Error closing response body: %v\n", err)
		errString := err.Error()
		request.Error = &errString
		return request
	}

	request.ResponseBody = &bodyString
	request.ResponseCode = &resp.StatusCode
	return request
}
