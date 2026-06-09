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
		// Check if we get NOAUTH - the server is up but requires authentication.
		// We deliberately leave RequirepassSet nil here: NOAUTH can come from either
		// the requirepass directive or from ACL-only auth (Redis 6.0+). We cannot
		// determine which without authenticating, so reporting requirepassSet=true
		// would be inaccurate when ACL-only auth is in use.
		if isNoAuthError(pingErr) {
			canConnect := true
			details.CanConnect = &canConnect
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

	// Check if requirepass is set via CONFIG GET requirepass.
	// A NOAUTH error here means the ACL restricts CONFIG for this user; we leave
	// RequirepassSet nil because NOAUTH does not distinguish requirepass from ACL-only auth.
	configResult, configErr := client.ConfigGet(ctx, "requirepass").Result()
	if configErr != nil {
		// If we get NOAUTH or any other error (including NOPERM), we cannot determine
		// whether requirepass is configured — leave RequirepassSet unset (nil).
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
	var exposed []string

	// Direct probes: actually invoke each command with a safe read-only argument so that
	// ACL-denied responses (NOPERM/NOAUTH) are correctly treated as NOT exposed.
	directProbes := []struct {
		name string
		args []interface{}
	}{
		{name: "CONFIG", args: []interface{}{"CONFIG", "GET", "maxmemory"}},
		{name: "DEBUG", args: []interface{}{"DEBUG", "SLEEP", "0"}},
		// MODULE LIST is a safe read-only invocation; NOPERM means the command is ACL-restricted.
		{name: "MODULE", args: []interface{}{"MODULE", "LIST"}},
	}

	for _, p := range directProbes {
		err := client.Do(ctx, p.args...).Err()
		if err == nil || (!isDeniedError(err) && !isUnknownCommandError(err)) {
			exposed = append(exposed, p.name)
		}
	}

	// FLUSHALL cannot be invoked safely (it is always destructive). Use ACL DRYRUN
	// (Redis 7.0+) for a non-destructive, ACL-accurate check. Falls back to
	// COMMAND INFO with explicit payload parsing on older Redis to avoid treating
	// an unknown/unregistered command as exposed.
	if probeFlushAll(ctx, client) {
		exposed = append(exposed, "FLUSHALL")
	}

	return exposed
}

// probeFlushAll returns true if FLUSHALL appears to be accessible to the connected user.
// It prefers ACL DRYRUN (Redis 7.0+) over COMMAND INFO to avoid false positives from
// ACL-restricted commands and from nil payloads returned for unknown command names.
func probeFlushAll(ctx context.Context, client *redisclient.Client) bool {
	// ACL DRYRUN checks permissions without side effects (Redis 7.0+).
	dryrunErr := client.Do(ctx, "ACL", "DRYRUN", "default", "FLUSHALL").Err()
	if dryrunErr == nil {
		return true
	}
	if isDeniedError(dryrunErr) {
		// A NOPERM response can mean either:
		//   (a) FLUSHALL is denied for this user → return false (correct)
		//   (b) ACL DRYRUN itself is restricted → fall through to COMMAND INFO
		// Distinguish by checking whether the error message names "flushall".
		// When FLUSHALL is the denied command, Redis includes "flushall" in the message.
		// When ACL DRYRUN is itself restricted, it names "acl|dryrun" instead.
		if strings.Contains(strings.ToLower(dryrunErr.Error()), "flushall") {
			return false
		}
		// ACL DRYRUN is restricted for this user — fall through to COMMAND INFO.
	}
	// ACL DRYRUN not supported (Redis < 7.0) or restricted for this user: fall back to COMMAND INFO.
	// Parse the response payload to distinguish "command unknown" (nil element)
	// from "command registered" (non-nil element).
	val, err := client.Do(ctx, "COMMAND", "INFO", "flushall").Result()
	if err != nil {
		return false
	}
	arr, ok := val.([]interface{})
	if !ok || len(arr) == 0 || arr[0] == nil {
		// Nil element means FLUSHALL is not registered on this server.
		return false
	}
	// Command is registered. On Redis < 6.0 (no ACL), registered implies callable.
	// On Redis 6.x with ACL configured to deny FLUSHALL, this may be a false positive;
	// ACL DRYRUN (Redis 7.0+) is required for ACL-accurate results on those versions.
	return true
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
