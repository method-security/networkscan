package host

import (
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/Method-Security/networkscan/generated/go/address/bruteforce"
)

type TelnetLibrary struct{}

func (TelnetLib *TelnetLibrary) StandardPorts() []int {
	return []int{23, 2323}
}

func (TelnetLib *TelnetLibrary) BruteForce(host string, port int, credPair *bruteforce.CredentialPair, config *bruteforce.BruteForceRunConfig) (*bruteforce.AttemptInfo, []string) {
	attempt := bruteforce.AttemptInfo{Timestamp: time.Now()}
	errors := []string{}

	var message string

	targetAddr := fmt.Sprintf("%s:%d", host, port)
	timeout := time.Duration(config.Timeout) * time.Second

	username, password := "", ""
	if credPair != nil {
		username, password = credPair.Username, credPair.Password
	}

	request := bruteforce.GeneralRequestInfo{
		Username: &username,
		Password: &password,
		Host:     host,
		Port:     port,
	}

	conn, err := net.DialTimeout("tcp", targetAddr, timeout)
	if err != nil {
		response := bruteforce.GeneralResponseInfo{
			Message: fmt.Sprintf("Failed to connect: %v", err),
		}
		attempt.Request = bruteforce.NewRequestUnionFromGeneralRequest(&request)
		attempt.Response = bruteforce.NewResponseUnionFromGeneralResponse(&response)
		attempt.Result = TelnetLib.AnalyzeResponse(attempt.Response)
		return &attempt, append(errors, err.Error())
	}

	if credPair != nil {
		err = readUntilPromptWithTimeout(conn, "login: ", timeout)
		if err != nil {
			errors = append(errors, fmt.Sprintf("Failed to read login prompt: %v", err))
		}
		_, err = conn.Write([]byte(username + "\r\n"))
		if err != nil {
			errors = append(errors, fmt.Sprintf("Failed to send username: %v", err))
		}
		time.Sleep(1 * time.Second)

		// Read password prompt with timeout
		err = readUntilPromptWithTimeout(conn, "Password: ", timeout)
		if err != nil {
			errors = append(errors, fmt.Sprintf("Failed to read password prompt: %v", err))
		}
		_, err = conn.Write([]byte(password + "\r\n"))
		if err != nil {
			errors = append(errors, fmt.Sprintf("Failed to send password: %v", err))
		}
		time.Sleep(1 * time.Second)
	}

	_, err = conn.Write([]byte("echo \"success\"\r\n"))
	if err != nil {
		errors = append(errors, fmt.Sprintf("Failed to send echo command: %v", err))
	}
	time.Sleep(2 * time.Second)

	// Read the full response
	var fullResponse []byte
	buf := make([]byte, 1024)
	err = readFullResponseWithTimeout(conn, buf, &fullResponse, timeout)
	if err != nil {
		errors = append(errors, fmt.Sprintf("Failed to read response: %v", err))
	}
	if len(fullResponse) > 0 {
		message = filterPrintable(fullResponse)
	}
	response := bruteforce.GeneralResponseInfo{
		Message: message,
	}
	attempt.Request = bruteforce.NewRequestUnionFromGeneralRequest(&request)
	attempt.Response = bruteforce.NewResponseUnionFromGeneralResponse(&response)
	attempt.Result = TelnetLib.AnalyzeResponse(attempt.Response)

	err = conn.Close()
	if err != nil {
		errors = append(errors, err.Error())
	}

	return &attempt, errors
}

func (TelnetLib *TelnetLibrary) AnalyzeResponse(response *bruteforce.ResponseUnion) *bruteforce.ResultInfo {
	result := bruteforce.ResultInfo{Login: false, Ratelimit: false}
	responseMessage := strings.ToLower(response.GeneralResponse.Message)
	successIndicators := []string{"#", "$", "welcome"}
	for _, indicator := range successIndicators {
		if strings.Contains(responseMessage, indicator) {
			result.Login = true
			break
		}
	}
	// TODO: result.Ratelimit = true
	return &result
}

func readUntilPromptWithTimeout(conn net.Conn, prompt string, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	done := make(chan error, 1)
	buffer := make([]byte, 1024)

	go func() {
		defer close(done)
		var received []byte
		for {
			n, err := conn.Read(buffer)
			if err != nil {
				if err == io.EOF {
					done <- fmt.Errorf("EOF reached without finding prompt")
					return
				}
				done <- err
				return
			}
			received = append(received, buffer[:n]...)
			if strings.Contains(strings.ToLower(string(received)), strings.ToLower(prompt)) {
				done <- nil
				return
			}
		}
	}()

	select {
	case <-ctx.Done():
		return fmt.Errorf("timeout: Did not find prompt '%s' within %v", prompt, timeout)
	case err := <-done:
		return err
	}
}

func readFullResponseWithTimeout(conn net.Conn, buf []byte, fullResponse *[]byte, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	done := make(chan error, 1)

	go func() {
		for {
			n, err := conn.Read(buf)
			if err != nil {
				if err == io.EOF {
					done <- nil
					return
				}
				done <- err
				return
			}
			if n > 0 {
				*fullResponse = append(*fullResponse, buf[:n]...)
			}
			if strings.Contains(string(buf[:n]), "\r\n") {
				done <- nil
				return
			}
		}
	}()

	select {
	case <-ctx.Done():
		return fmt.Errorf("timeout: Reading full response took longer than %v", timeout)
	case err := <-done:
		return err
	}
}

func filterPrintable(input []byte) string {
	printable := make([]byte, 0, len(input))
	for _, b := range input {
		if b >= 32 && b <= 126 {
			printable = append(printable, b)
		}
		if b == '\r' || b == '\n' {
			printable = append(printable, b)
		}
	}
	return string(printable)
}
