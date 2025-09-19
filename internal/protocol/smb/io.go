package smb

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"
)

// ContextKey represents context option keys for timeout handling
type ContextKey string

const (
	ContextOptionOutputTimeout      ContextKey = "output_timeout"
	ContextOptionOutputPollInterval ContextKey = "output_poll_interval"
)

// OutputProvider interface for command output retrieval
type OutputProvider interface {
	GetOutput(ctx context.Context, writer io.Writer) error
	Clean(ctx context.Context) error
}

// ExecutionIO handles command execution and output collection
type ExecutionIO struct {
	Input  *ExecutionInput
	Output *ExecutionOutput
}

type ExecutionInput struct {
	Executable     string
	ExecutablePath string
	Arguments      string
	Command        string
}

type ExecutionOutput struct {
	NoDelete   bool
	RemotePath string
	Timeout    time.Duration
	Provider   OutputProvider
	Writer     io.WriteCloser
}

// GetOutput calls the output provider to collect output
func (execIO *ExecutionIO) GetOutput(ctx context.Context) error {
	if execIO.Output.Provider != nil {
		ctx = context.WithValue(ctx, ContextOptionOutputTimeout, execIO.Output.Timeout)
		return execIO.Output.Provider.GetOutput(ctx, execIO.Output.Writer)
	}
	return nil
}

// Clean cleans up the output provider
func (execIO *ExecutionIO) Clean(ctx context.Context) error {
	if execIO.Output.Provider != nil {
		return execIO.Output.Provider.Clean(ctx)
	}
	return nil
}

// CommandLine generates the command line for execution
func (execIO *ExecutionIO) CommandLine() []string {
	if execIO.Output.Provider != nil && execIO.Output.RemotePath != "" {
		return []string{
			`C:\Windows\System32\cmd.exe`,
			fmt.Sprintf(`/C %s > %s 2>&1`, execIO.Input.String(), execIO.Output.RemotePath),
		}
	}
	return execIO.Input.CommandLine()
}

// String returns the full command line as string
func (execIO *ExecutionIO) String() string {
	cmd := execIO.CommandLine()
	// Ensure that executable paths are quoted
	if strings.Contains(cmd[0], " ") {
		return fmt.Sprintf(`%q %s`, cmd[0], strings.Join(cmd[1:], " "))
	}
	return strings.Join(cmd, " ")
}

// CommandLine returns command line array
func (i *ExecutionInput) CommandLine() []string {
	cmd := make([]string, 2)
	cmd[1] = i.Arguments

	switch {
	case i.Command != "":
		copy(cmd, strings.SplitN(i.Command, " ", 2))
	case i.ExecutablePath != "":
		cmd[0] = i.ExecutablePath
	case i.Executable != "":
		cmd[0] = i.Executable
	}

	return cmd
}

// String returns the input command as string
func (i *ExecutionInput) String() string {
	return strings.Join(i.CommandLine(), " ")
}

// WriteCloserWrapper wraps an io.Writer to implement io.WriteCloser
type WriteCloserWrapper struct {
	io.Writer
}

func (w *WriteCloserWrapper) Close() error {
	return nil
}
