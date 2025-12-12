package smb

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/oiweiwei/go-smb2.fork"
	"github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

var (
	DefaultOutputPollInterval = 500 * time.Millisecond
	DefaultOutputPollTimeout  = 60 * time.Second
	pathPrefix                = regexp.MustCompile(`^([a-zA-Z]:)?[\\\\/]*`)
)

// OutputFileFetcher handles retrieval of command output via SMB file access
type OutputFileFetcher struct {
	// SMB Connection Configuration
	Host     string // SMB server hostname or IP address
	Username string // Username for authentication
	Password string // Password for authentication
	NTLMHash string // NTLM hash for pass-the-hash authentication (hex string)
	Domain   string // Domain for authentication (optional)

	// SMB Share Configuration
	Share     string // SMB share name (e.g., "ADMIN$", "C$")
	SharePath string // Base path within the share (e.g., `C:\Windows`)
	File      string // Full path to the output file to retrieve

	// Behavior Configuration
	DeleteOutputFile bool // Whether to delete the output file after retrieval
	ForceReconnect   bool // Whether to force reconnection for each operation

	// Internal state
	relativePath string // computed relative path for SMB access
}

// GetOutput implements OutputProvider interface
func (o *OutputFileFetcher) GetOutput(ctx context.Context, writer io.Writer) error {
	log := svc1log.FromContext(ctx)
	timeout := DefaultOutputPollTimeout
	pollInterval := DefaultOutputPollInterval

	// Handle context timeout configuration
	if v := ctx.Value(ContextOptionOutputTimeout); v != nil {
		if t, ok := v.(time.Duration); ok {
			timeout = t
		}
	}
	if v := ctx.Value(ContextOptionOutputPollInterval); v != nil {
		if p, ok := v.(time.Duration); ok {
			pollInterval = p
		}
	}

	// Calculate relative path for SMB share access
	shp := pathPrefix.ReplaceAllString(strings.ToLower(strings.ReplaceAll(o.SharePath, `\`, "/")), "")
	fp := pathPrefix.ReplaceAllString(strings.ToLower(strings.ReplaceAll(o.File, `\`, "/")), "")

	var err error
	if o.relativePath, err = filepath.Rel(shp, fp); err != nil {
		return fmt.Errorf("calculate relative path: %w", err)
	}

	log.Info("Fetching output file", svc1log.SafeParam("path", o.relativePath))

	// Create TCP connection to SMB server
	// Use net.JoinHostPort to properly handle IPv6 addresses with brackets
	address := net.JoinHostPort(o.Host, "445")
	conn, err := net.Dial("tcp", address)
	if err != nil {
		return fmt.Errorf("connect to SMB server: %w", err)
	}
	defer func() { _ = conn.Close() }()

	// Create NTLM initiator with hash or password authentication
	initiator := &smb2.NTLMInitiator{
		User:   o.Username,
		Domain: o.Domain,
	}

	// Use NTLM hash if provided, otherwise use password
	if o.NTLMHash != "" {
		hashBytes, err := hex.DecodeString(o.NTLMHash)
		if err != nil {
			return fmt.Errorf("decode NTLM hash: %w", err)
		}
		initiator.Hash = hashBytes
		log.Info("Using NTLM hash authentication for SMB output fetch")
	} else {
		initiator.Password = o.Password
	}

	// Create SMB dialer and session
	dialer := &smb2.Dialer{
		Initiator: initiator,
	}

	session, err := dialer.DialContext(ctx, conn)
	if err != nil {
		return fmt.Errorf("create SMB session: %w", err)
	}
	defer func() { _ = session.Logoff() }()

	// Mount share
	share, err := session.Mount(o.Share)
	if err != nil {
		return fmt.Errorf("mount share %s: %w", o.Share, err)
	}
	defer func() { _ = share.Umount() }()

	// Poll for file availability with timeout
	reader, err := func() (io.ReadCloser, error) {
		timer := time.NewTimer(timeout)
		defer timer.Stop()
		poll := time.NewTicker(pollInterval)
		defer poll.Stop()

		for {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-timer.C:
				return nil, errors.New("execution output timeout")
			case <-poll.C:
				// Open the remote file with read/write access to ensure process completion
				reader, err := share.OpenFile(o.relativePath, os.O_RDWR, 0)
				if err == nil {
					return reader, nil
				}
				log.Debug("File not yet available, continuing to poll", svc1log.SafeParam("error", err.Error()))
			}
		}
	}()
	if err != nil {
		return err
	}
	defer func() { _ = reader.Close() }()
	if _, err := io.Copy(writer, reader); err != nil {
		return fmt.Errorf("copy file contents: %w", err)
	}
	// Delete temporary file if requested
	if o.DeleteOutputFile {
		if removeErr := share.Remove(o.relativePath); removeErr != nil {
			log.Debug("Failed to delete output file", svc1log.SafeParam("error", removeErr.Error()))
		}
	}

	return nil
}

// Clean implements OutputProvider interface
func (o *OutputFileFetcher) Clean(ctx context.Context) error {
	// Cleanup is handled in GetOutput method
	return nil
}
