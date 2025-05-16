package ftp

import (
	"context"
	"fmt"
	"log"

	enumerateFern "github.com/Method-Security/networkscan/generated/go/enumerate"
	ftp "github.com/Method-Security/networkscan/generated/go/enumerate/ftp"
)

var bufferSize = 2048

// RunFTPEnumerate Overview:
//  1. Connect to the target
//     a. Exit if connection isnt established
//  2. Grab the FTP banner
//     a. Exit if no banner is returned (assume FTP is not implemented)
//     b. Else set successful connection to true
//  3. Check if TLS is implemented
//     a. Send a 'FEAT' command
//     b. Check if the response contains TLS, SSL or RFC 2228 or 4217
//  4. Check if TLS is forced
//     a. Send a 'AUTH TLS' command
//     b. Check if the response contains 234 which indicates TLS forced
//  5. Check if anonymous login is supported with retry on broken pipe errors
//     (This happens when the connection has been open for too long or too many invalid commands have been sent
//     The connection is closed by the server)
//     a. Send a 'USER anonymous' command
//     b. Check if the response contains 331 which indicates anonymous login supported
//     c. Send a 'PASS anonymous' command
//     d. Check if the response contains 230 which indicates anonymous login successful
//  6. Return the details
//     a. Banner
//     b. Successful Connection
//     c. TLS Implemented
//     d. TLS Forced
//     e. Allows Anonymous Login

// LibraryEnumerateFTP implements NetworkApplicationLibrary for FTP enumeration.
type LibraryEnumerateFTP struct{}

// EnumerateTarget connects to the target and extracts FTP details.
func (f *LibraryEnumerateFTP) EnumerateTarget(ctx context.Context, target string) (*enumerateFern.NetworkApplicationEnumerateDetails, []string) {
	var details ftp.EnumerateFtpDetails
	details.Target = target
	errors := []string{}
	log.Printf("[INFO] Enumerating target: %s", target)

	// Attempt to connect to the target
	conn, err := attemptConnection(ctx, target)
	if err != nil {
		log.Printf("[ERROR] Failed to connect to %s: %v", target, err)
		errors = append(errors, fmt.Sprintf("Failed to connect to %s: %v", target, err))
		return enumerateFern.NewNetworkApplicationEnumerateDetailsFromEnumerateFtpDetails(&details), errors
	}

	// Grab the FTP banner
	bannerStr, err := grabBanner(conn)
	if err != nil {
		errors = append(errors, fmt.Sprintf("error reading banner from %s: %v", target, err))
		return enumerateFern.NewNetworkApplicationEnumerateDetailsFromEnumerateFtpDetails(&details), errors
	}
	details.Banner = &bannerStr
	successFulConnection := true
	details.SuccessfulConnection = &successFulConnection

	// Check TLS implemented
	if err := checkTLSImplemented(conn, &details); err != nil {
		errors = append(errors, fmt.Sprintf("error checking if TLS is implemented for %s: %v", target, err))
	}
	if details.TlsImplemented != nil && !*details.TlsImplemented {
		tlsForced := false
		details.TlsForced = &tlsForced
	}

	// Check TLS forced (Only check if TLS is implemented)
	if details.TlsForced == nil {
		errs := checkTLSForced(conn, &details)
		if len(errs) > 0 {
			errors = append(errors, errs...)
		}
	}

	// Check if anonymous login is supported
	errs := checkAnonymousLoginWithRetry(ctx, target, conn, &details)
	if len(errs) > 0 {
		errors = append(errors, errs...)
	}

	err = conn.Close()
	if err != nil {
		errors = append(errors, fmt.Sprintf("failed to close connection: %v", err))
	}

	return enumerateFern.NewNetworkApplicationEnumerateDetailsFromEnumerateFtpDetails(&details), errors
}
