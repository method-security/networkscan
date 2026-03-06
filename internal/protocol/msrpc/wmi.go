package msrpc

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Method-Security/networkscan/internal/protocol/smb"
	"github.com/Method-Security/networkscan/utils"
	"github.com/google/uuid"
	"github.com/oiweiwei/go-msrpc/dcerpc"
	"github.com/oiweiwei/go-msrpc/msrpc/dcom"
	"github.com/oiweiwei/go-msrpc/msrpc/dcom/iactivation/v0"
	"github.com/oiweiwei/go-msrpc/msrpc/dcom/wmi"
	"github.com/oiweiwei/go-msrpc/msrpc/dcom/wmi/iwbemlevel1login/v0"
	"github.com/oiweiwei/go-msrpc/msrpc/dcom/wmi/iwbemservices/v0"
	"github.com/oiweiwei/go-msrpc/msrpc/dcom/wmio/query"
	"github.com/oiweiwei/go-msrpc/ssp"
	"github.com/oiweiwei/go-msrpc/ssp/credential"
	"github.com/oiweiwei/go-msrpc/ssp/gssapi"
	"github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

// WMI protocol constants for DCOM communication
const (
	ProtocolSequenceRPC uint16 = 7
	ProtocolSequenceNP  uint16 = 15
)

var (
	ComVersion = &dcom.COMVersion{
		MajorVersion: 5,
		MinorVersion: 7,
	}
	ORPCThis = &dcom.ORPCThis{Version: ComVersion}
)

// WMIExecutor provides WMI command execution functionality
type WMIExecutor struct {
	conn           dcerpc.Conn
	servicesClient iwbemservices.ServicesClient
	resource       string
	host           string
	username       string
	password       string
	ntlmHash       string
	domain         string
}

// NewWMIExecutor creates a new WMI executor with proper authentication
// Supports both password and NTLM hash authentication
func NewWMIExecutor(ctx context.Context, host, username, password, domain string) (*WMIExecutor, error) {
	return NewWMIExecutorWithHash(ctx, host, username, password, "", domain)
}

// NewWMIExecutorWithHash creates a new WMI executor with NTLM hash authentication support
func NewWMIExecutorWithHash(ctx context.Context, host, username, password, ntlmHash, domain string) (*WMIExecutor, error) {
	log := svc1log.FromContext(ctx)

	// Set up DCE/RPC authentication options
	var credStr string
	if domain != "" {
		credStr = domain + "\\" + username
	} else {
		credStr = username
	}

	// Use NTLM hash authentication if provided, otherwise use password
	var cred any
	if ntlmHash != "" {
		log.Info("Using NTLM hash authentication for WMI")
		cred = credential.NewFromNTHash(credStr, ntlmHash)
	} else {
		cred = credential.NewFromPassword(credStr, password)
	}

	// Create GSSAPI credential with proper formatting
	gssapiCred := gssapi.NewCredential("", nil, gssapi.InitiateAndAccept, cred)

	// Create DCOM/WMI connection with DCE/RPC authentication
	conn, err := dcerpc.Dial(ctx, utils.FormatRPCBinding(host, "135"),
		dcerpc.WithSeal(),
		dcerpc.WithSign(),
		dcerpc.WithSecurityLevel(dcerpc.AuthLevelPktPrivacy),
		dcerpc.WithCredentials(gssapiCred),
		dcerpc.WithMechanism(ssp.NTLM),
		dcerpc.WithAbstractSyntax(iactivation.ActivationSyntaxV0_0))
	if err != nil {
		log.Debug("Failed to connect to RPC endpoint mapper",
			svc1log.SafeParam("error", err.Error()))
		return nil, fmt.Errorf("failed to connect to RPC endpoint: %w", err)
	}

	executor := &WMIExecutor{
		conn:     conn,
		resource: "//./root/cimv2",
		host:     host,
		username: username,
		password: password,
		ntlmHash: ntlmHash,
		domain:   domain,
	}

	// Initialize WMI connection
	if err := executor.initialize(ctx); err != nil {
		_ = conn.Close(ctx)
		return nil, fmt.Errorf("failed to initialize WMI: %w", err)
	}

	return executor, nil
}

// initialize performs the WMI initialization sequence
func (w *WMIExecutor) initialize(ctx context.Context) error {
	log := svc1log.FromContext(ctx)

	// Step 1: Remote Activation
	actClient, err := iactivation.NewActivationClient(ctx, w.conn)
	if err != nil {
		log.Error("Failed to initialize IActivation client", svc1log.SafeParam("error", err.Error()))
		return fmt.Errorf("create IActivation client: %w", err)
	}

	actResponse, err := actClient.RemoteActivation(ctx, &iactivation.RemoteActivationRequest{
		ORPCThis:                   ORPCThis,
		ClassID:                    wmi.Level1LoginClassID.GUID(),
		IIDs:                       []*dcom.IID{iwbemlevel1login.Level1LoginIID},
		RequestedProtocolSequences: []uint16{ProtocolSequenceRPC},
	})
	if err != nil {
		log.Error("Failed to activate remote object", svc1log.SafeParam("error", err.Error()))
		return fmt.Errorf("request remote activation: %w", err)
	}
	if actResponse.HResult != 0 {
		return fmt.Errorf("remote activation failed with code %d", actResponse.HResult)
	}

	log.Info("Remote activation succeeded")

	// Step 2: Parse OXID bindings and reconnect
	var newOpts []dcerpc.Option
	for _, bind := range actResponse.OXIDBindings.GetStringBindings() {
		stringBinding, err := dcerpc.ParseStringBinding(bind.String())
		if err != nil {
			log.Debug("Failed to parse string binding", svc1log.SafeParam("error", err.Error()))
			continue
		}
		// Only consider ncacn_ip_tcp endpoints
		if stringBinding.ProtocolSequence == dcerpc.ProtocolSequenceIPTCP {
			// Use the stored host address for reconnection
			stringBinding.NetworkAddress = w.host
			newOpts = append(newOpts, dcerpc.WithEndpoint(stringBinding.String()))
		}
	}

	// Perform reconnection with discovered endpoints
	if len(newOpts) > 0 {
		log.Info("Reconnecting to WMI interface with new endpoints")
		// Close the old connection first
		_ = w.conn.Close(ctx)

		// Create new connection with discovered endpoints
		var credStr string
		if w.domain != "" {
			credStr = w.domain + "\\" + w.username
		} else {
			credStr = w.username
		}

		// Use NTLM hash authentication if provided, otherwise use password
		var cred any
		if w.ntlmHash != "" {
			cred = credential.NewFromNTHash(credStr, w.ntlmHash)
		} else {
			cred = credential.NewFromPassword(credStr, w.password)
		}
		gssapiCred := gssapi.NewCredential("", nil, gssapi.InitiateAndAccept, cred)

		// Configure connection options with endpoints and authentication
		reconnectOpts := append(newOpts,
			dcerpc.WithSeal(),
			dcerpc.WithSign(),
			dcerpc.WithSecurityLevel(dcerpc.AuthLevelPktPrivacy),
			dcerpc.WithCredentials(gssapiCred),
			dcerpc.WithMechanism(ssp.NTLM),
			dcerpc.WithAbstractSyntax(iwbemlevel1login.Level1LoginSyntaxV0_0))

		conn, err := dcerpc.Dial(ctx, utils.FormatRPCBinding(w.host, "135"), reconnectOpts...)
		if err != nil {
			log.Error("Failed to reconnect to WMI interface", svc1log.SafeParam("error", err.Error()))
			return fmt.Errorf("reconnect to WMI interface: %w", err)
		}
		w.conn = conn
		log.Info("Successfully reconnected to WMI interface")
	} else {
		log.Info("Using original connection - no new endpoints found")
	}

	log.Info("Connected to remote instance")

	// Step 3: Create Level1Login client
	ipid := actResponse.InterfaceData[0].GetStandardObjectReference().Std.IPID
	loginClient, err := iwbemlevel1login.NewLevel1LoginClient(ctx, w.conn, dcom.WithIPID(ipid))
	if err != nil {
		log.Error("Failed to create IWbemLevel1Login client", svc1log.SafeParam("error", err.Error()))
		return fmt.Errorf("create IWbemLevel1Login client: %w", err)
	}

	// Step 4: NTLM Login to WMI namespace
	login, err := loginClient.NTLMLogin(ctx, &iwbemlevel1login.NTLMLoginRequest{
		This:            ORPCThis,
		NetworkResource: w.resource,
	})
	if err != nil {
		log.Error("Failed to login on remote instance", svc1log.SafeParam("error", err.Error()))
		return fmt.Errorf("login: IWbemLevel1Login::NTLMLogin: %w", err)
	}

	log.Info("Completed NTLMLogin operation")

	// Step 5: Create services client
	ipid = login.Namespace.InterfacePointer().IPID()
	w.servicesClient, err = iwbemservices.NewServicesClient(ctx, w.conn, dcom.WithIPID(ipid))
	if err != nil {
		log.Error("Failed to create services client", svc1log.SafeParam("error", err.Error()))
		return fmt.Errorf("create IWbemServices client: %w", err)
	}

	log.Info("Initialized services client")

	return nil
}

// ExecuteCommand executes a command using WMI Win32_Process.Create
func (w *WMIExecutor) ExecuteCommand(ctx context.Context, command string) (map[string]any, error) {
	log := svc1log.FromContext(ctx)

	if w.servicesClient == nil {
		return nil, errors.New("WMI executor has not been initialized")
	}

	// Generate unique temporary output file
	outputFile := `C:\Windows\Temp\` + uuid.New().String()

	// Create ExecutionIO for command execution with output capture
	execIO := &smb.ExecutionIO{
		Input: &smb.ExecutionInput{
			Command: command,
		},
		Output: &smb.ExecutionOutput{
			RemotePath: outputFile,
			Timeout:    60 * time.Second,
			Provider: &smb.OutputFileFetcher{
				Host:             w.host,
				Username:         w.username,
				Password:         w.password,
				NTLMHash:         w.ntlmHash,
				Domain:           w.domain,
				Share:            "ADMIN$",
				SharePath:        `C:\Windows`,
				File:             outputFile,
				DeleteOutputFile: true,
				ForceReconnect:   false,
			},
		},
	}

	// Generate command line with output redirection
	redirectedCommand := execIO.String()

	log.Info("Executing command via WMI",
		svc1log.SafeParam("command", command),
		svc1log.SafeParam("outputFile", outputFile),
		svc1log.SafeParam("redirectedCommand", redirectedCommand))

	// Execute the WMI query
	out, err := query.NewBuilder(ctx, w.servicesClient, ComVersion).
		Spawn("Win32_Process").
		Method("Create").
		Values(map[string]any{
			"CommandLine": redirectedCommand,
			"WorkingDir":  "C:\\",
		}).
		Exec().
		Object()

	if err != nil {
		log.Error("WMI query failed", svc1log.SafeParam("error", err.Error()))
		return nil, fmt.Errorf("spawn WMI query: %w", err)
	}

	result := out.Values()

	// Process WMI execution results
	var pid uint32
	if pidVal, ok := result["ProcessId"].(uint32); pidVal != 0 && ok {
		pid = pidVal
		log.Info("Process created", svc1log.SafeParam("pid", pid))
	} else {
		log.Error("Process creation failed - no ProcessId returned")
		return result, errors.New("process creation failed")
	}

	if ret, ok := result["ReturnValue"].(uint32); ret != 0 && ok {
		log.Error("Process returned non-zero exit code", svc1log.SafeParam("return", ret))
	}

	// Collect command output via SMB exfiltration
	var outputBuilder strings.Builder
	execIO.Output.Writer = &smb.WriteCloserWrapper{Writer: &outputBuilder}

	if err := execIO.GetOutput(ctx); err != nil {
		log.Error("Failed to collect output via SMB", svc1log.SafeParam("error", err.Error()))
		result["Output"] = fmt.Sprintf("Process created successfully. ProcessId: %d", pid)
	} else {
		result["Output"] = strings.TrimSpace(outputBuilder.String())
	}

	// Clean up temporary files
	if cleanErr := execIO.Clean(ctx); cleanErr != nil {
		log.Debug("Failed to clean up ExecutionIO", svc1log.SafeParam("error", cleanErr.Error()))
	}

	return result, nil
}

// Close closes the WMI executor connection
func (w *WMIExecutor) Close(ctx context.Context) error {
	if w.conn != nil {
		return w.conn.Close(ctx)
	}
	return nil
}
