// Package redis provides Redis service enumeration functionality.
package redis

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	enumeratefern "github.com/Method-Security/networkscan/generated/go/enumerate"
	redisFern "github.com/Method-Security/networkscan/generated/go/enumerate/redis"
	"github.com/Method-Security/networkscan/utils"
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
	redisclient "github.com/redis/go-redis/v9"
)

const defaultRedisPort = 6379

// LibraryEnumerateRedis implements NetworkApplicationLibrary for Redis enumeration.
// It probes Redis targets for connectivity, server info, and security configuration.
type LibraryEnumerateRedis struct{}

// EnumerateTarget connects to a Redis instance, probes server info,
// tests authentication configuration, checks ACL users, and identifies dangerous exposed commands.
func (r *LibraryEnumerateRedis) EnumerateTarget(ctx context.Context, target string) (*enumeratefern.EnumerateServiceDetails, []string) {
	log := svc1log.FromContext(ctx)
	log.Info("Starting Redis enumeration", svc1log.SafeParam("target", target))

	details := redisFern.EnumerateRedisDetails{Target: target}
	var errors []string

	host, port := utils.ParseHostPort(target, defaultRedisPort)
	if host == "" {
		errors = append(errors, fmt.Sprintf("invalid target %q: could not parse host:port", target))
		return &enumeratefern.EnumerateServiceDetails{EnumerateRedisDetails: &details}, errors
	}

	addr := utils.FormatHostPort(host, port)
	details.Target = addr

	// Create Redis client (unauthenticated)
	client := redisclient.NewClient(&redisclient.Options{
		Addr: addr,
	})
	defer func() { _ = client.Close() }()

	// Send PING to test connectivity
	pingErr := client.Ping(ctx).Err()
	if pingErr != nil {
		// Check if we get NOAUTH - this means the server is up but requires auth
		if isNoAuthError(pingErr) {
			canConnect := true
			details.CanConnect = &canConnect
			requirepassSet := true
			details.RequirepassSet = &requirepassSet
			log.Info("Redis requires authentication", svc1log.SafeParam("target", addr))
			return &enumeratefern.EnumerateServiceDetails{EnumerateRedisDetails: &details}, errors
		}
		// Connection failed entirely
		errMsg := fmt.Sprintf("connection failed: %v", pingErr)
		errors = append(errors, errMsg)
		canConnect := false
		details.CanConnect = &canConnect
		return &enumeratefern.EnumerateServiceDetails{EnumerateRedisDetails: &details}, errors
	}

	canConnect := true
	details.CanConnect = &canConnect
	log.Info("Redis connection successful", svc1log.SafeParam("target", addr))

	// Run INFO all to gather server details
	infoResult, infoErr := client.Info(ctx, "all").Result()
	if infoErr != nil {
		errors = append(errors, fmt.Sprintf("INFO command failed: %v", infoErr))
	} else {
		parseInfoFields(infoResult, &details)
	}

	// Check if requirepass is set via CONFIG GET requirepass
	configResult, configErr := client.ConfigGet(ctx, "requirepass").Result()
	if configErr != nil {
		if isNoAuthError(configErr) {
			requirepassSet := true
			details.RequirepassSet = &requirepassSet
		}
		// If we get any other error (including NOPERM), we can't determine this
	} else {
		// configResult is a map[string]string in go-redis v9
		if val, ok := configResult["requirepass"]; ok {
			requirepassSet := val != ""
			details.RequirepassSet = &requirepassSet
		} else {
			requirepassSet := false
			details.RequirepassSet = &requirepassSet
		}
	}

	// Try ACL LIST to enumerate configured users
	aclResult, aclErr := client.ACLList(ctx).Result()
	if aclErr == nil {
		var users []string
		for _, entry := range aclResult {
			// Extract username from ACL entry (format: "user <username> ...")
			parts := strings.Fields(entry)
			if len(parts) >= 2 && parts[0] == "user" {
				users = append(users, parts[1])
			}
		}
		if len(users) > 0 {
			details.AclUsersConfigured = users
		}
	}
	// If ACL LIST errors, it may not be supported on older Redis versions; skip silently

	// Probe dangerous commands
	dangerousCommands := probeDangerousCommands(ctx, client)
	if len(dangerousCommands) > 0 {
		details.DangerousCommandsExposed = dangerousCommands
	}

	return &enumeratefern.EnumerateServiceDetails{EnumerateRedisDetails: &details}, errors
}

// parseInfoFields parses key fields from the Redis INFO all output.
func parseInfoFields(info string, details *redisFern.EnumerateRedisDetails) {
	for _, line := range strings.Split(info, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		switch key {
		case "redis_version":
			details.ServerVersion = &value
		case "redis_mode":
			details.Mode = &value
		case "role":
			details.Role = &value
		case "connected_clients":
			if n, err := strconv.Atoi(value); err == nil {
				details.ConnectedClients = &n
			}
		}
	}
}

// probeDangerousCommands attempts safe probes for a set of dangerous Redis commands.
// A command is considered "exposed" if the error is NOT a permission denial (NOPERM/NOAUTH/ERR unknown command).
func probeDangerousCommands(ctx context.Context, client *redisclient.Client) []string {
	type probe struct {
		name string
		args []interface{}
	}

	probes := []probe{
		{name: "CONFIG", args: []interface{}{"CONFIG", "GET", "maxmemory"}},
		{name: "DEBUG", args: []interface{}{"DEBUG", "SLEEP", "0"}},
		{name: "FLUSHALL", args: []interface{}{"COMMAND", "INFO", "flushall"}},
		{name: "MODULE", args: []interface{}{"COMMAND", "INFO", "module"}},
	}

	var exposed []string
	for _, p := range probes {
		err := client.Do(ctx, p.args...).Err()
		if err == nil {
			// Command succeeded — exposed
			exposed = append(exposed, p.name)
		} else if !isDeniedError(err) && !isUnknownCommandError(err) {
			// Got a non-permission error (e.g., wrong args) — command is still accessible
			exposed = append(exposed, p.name)
		}
	}
	return exposed
}

// isNoAuthError returns true if the error is a Redis NOAUTH error.
func isNoAuthError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToUpper(err.Error())
	return strings.Contains(msg, "NOAUTH")
}

// isDeniedError returns true if the error indicates a permission denial.
func isDeniedError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToUpper(err.Error())
	return strings.Contains(msg, "NOPERM") || strings.Contains(msg, "NOAUTH") || strings.Contains(msg, "DENIED")
}

// isUnknownCommandError returns true if the error indicates the command is not known to the server.
func isUnknownCommandError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToUpper(err.Error())
	return strings.Contains(msg, "ERR UNKNOWN") || strings.Contains(msg, "UNKNOWN COMMAND")
}
