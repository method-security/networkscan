package host

import (
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	"github.com/Method-Security/networkscan/generated/go/address/bruteforce"
)

const bufferSize = 2048

func grabBanner(conn net.Conn) (string, error) {
	var bannerStr string
	response := make([]byte, bufferSize)
	for {
		n, err := conn.Read(response)
		if err != nil {
			return "", fmt.Errorf("error reading initial banner: %v", err)
		}
		// Safely append raw bytes without assuming ASCII encoding
		bannerStr += string(response[:n])

		log.Printf("[INFO] Reading banner, current content (partial): %x", response[:n])

		if strings.Contains(bannerStr, "220") {
			break
		}
	}
	log.Printf("[INFO] Final banner: %s", strings.TrimSpace(bannerStr))
	return bannerStr, nil
}

type FTPLibrary struct{}

func (FTPLib *FTPLibrary) StandardPorts() []int {
	return []int{21}
}

func (FTPLib *FTPLibrary) BruteForce(host string, port int, credPair *bruteforce.CredentialPair, config *bruteforce.BruteForceRunConfig) (*bruteforce.AttemptInfo, []string) {
	attempt := bruteforce.AttemptInfo{Timestamp: time.Now()}
	errors := []string{}

	username, password := "", ""
	if credPair != nil {
		username, password = credPair.Username, credPair.Password
	}

	address := fmt.Sprintf("%s:%d", host, port)
	fmt.Println(address)
	fmt.Printf("Attempting to connect to FTP server at %s...\n", address)
	conn, err := net.DialTimeout("tcp", address, time.Duration(config.Timeout)*time.Millisecond)
	if err != nil {
		fmt.Printf("[ERROR] Error connecting to FTP server: %v\n", err)
		errors = append(errors, err.Error())
		request := bruteforce.GeneralRequestInfo{
			Host: host,
			Port: port,
		}

		attempt.Request = bruteforce.NewRequestUnionFromGeneralRequest(&request)
		return &attempt, errors
	}
	fmt.Println("[INFO] Connection established.")

	fmt.Println(host, port)

	// Sleep
	time.Sleep(2 * time.Second)

	// Read the initial banner using grabBanner function
	banner, err := grabBanner(conn)
	if err != nil {
		fmt.Printf("[ERROR] Error reading banner: %v\n", err)
		errors = append(errors, err.Error())
		return &attempt, errors
	}
	fmt.Printf("[INFO] Banner read successfully: %s\n", banner)

	// Sleep
	time.Sleep(1 * time.Second)

	// Send USER command using conn.Write
	fmt.Printf("[INFO] Sending USER command with username: %s...\n", username)
	_, err = conn.Write([]byte(fmt.Sprintf("USER %s\r\n", username)))
	if err != nil {
		fmt.Printf("[ERROR] Error sending USER command: %v\n", err)
		errors = append(errors, err.Error())
		return &attempt, errors
	}
	fmt.Println("[INFO] USER command sent.")

	// Sleep
	time.Sleep(1 * time.Second)

	// Read response for USER command
	response := make([]byte, bufferSize)
	n, err := conn.Read(response)
	if err != nil {
		fmt.Printf("[ERROR] Error reading USER response: %v\n", err)
		errors = append(errors, err.Error())
		return &attempt, errors
	}
	userResponse := string(response[:n])
	fmt.Printf("[INFO] USER response: %s\n", userResponse)

	// Send PASS command if USER was accepted
	var passResponse *string
	if strings.Contains(userResponse, "331") { // 331 indicates "Username OK, Password required"
		fmt.Printf("[INFO] USER accepted. Sending PASS command with password: %s...\n", password)
		_, err = conn.Write([]byte(fmt.Sprintf("PASS %s\r\n", password)))
		if err != nil {
			fmt.Printf("[ERROR] Error sending PASS command: %v\n", err)
			errors = append(errors, err.Error())
			return &attempt, errors
		}
		fmt.Println("[INFO] PASS command sent.")

		// Read response for PASS command
		n, err = conn.Read(response)
		if err != nil {
			fmt.Printf("[ERROR] Error reading PASS response: %v\n", err)
			errors = append(errors, err.Error())
			return &attempt, errors
		}
		temp := string(response[:n])
		passResponse = &temp
		fmt.Printf("[INFO] PASS response: %s\n", *passResponse)
	}

	err = conn.Close()
	if err != nil {
		fmt.Printf("[ERROR] Error closing connection: %v\n", err)
		errors = append(errors, err.Error())
	}

	var message string
	if passResponse != nil {
		message = "PASS response: " + *passResponse
	} else {
		message = "USER response: " + userResponse
	}

	request := bruteforce.GeneralRequestInfo{
		Username: &username,
		Password: &password,
		Host:     host,
		Port:     port,
	}
	responseInfo := bruteforce.GeneralResponseInfo{
		Message: message,
	}
	attempt.Request = bruteforce.NewRequestUnionFromGeneralRequest(&request)
	attempt.Response = bruteforce.NewResponseUnionFromGeneralResponse(&responseInfo)
	attempt.Result = FTPLib.AnalyzeResponse(attempt.Response)

	fmt.Printf("[INFO] Attempt result: Login: %v, Ratelimit: %v\n", attempt.Result.Login, attempt.Result.Ratelimit)

	return &attempt, errors
}

func (FTPLib *FTPLibrary) AnalyzeResponse(response *bruteforce.ResponseUnion) *bruteforce.ResultInfo {
	result := bruteforce.ResultInfo{Login: false, Ratelimit: false}

	// 230 indicates login was successful
	if strings.Contains(response.GeneralResponse.Message, "230") {
		result.Login = true
	}
	return &result
}
