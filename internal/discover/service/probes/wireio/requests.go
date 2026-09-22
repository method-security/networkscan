package wireio

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"syscall"
	"time"

	"github.com/Method-Security/networkscan/internal/discover/service/helpers"
)

func Send(conn net.Conn, data []byte, timeout time.Duration) error {
	err := helpers.SetWriteDeadlineDuration(conn, timeout)
	if err != nil {
		return &WriteTimeoutError{WrappedError: err}
	}
	length, err := conn.Write(data)
	if err != nil {
		return &WriteError{WrappedError: err}
	}
	if length < len(data) {
		return &WriteError{
			WrappedError: fmt.Errorf(
				"Failed to write all bytes (%d bytes written, %d bytes expected)",
				length,
				len(data),
			),
		}
	}
	return nil
}

func Recv(conn net.Conn, timeout time.Duration) ([]byte, error) {
	response := make([]byte, 4096)
	err := helpers.SetReadDeadlineDuration(conn, timeout)
	if err != nil {
		return []byte{}, &ReadTimeoutError{WrappedError: err}
	}
	length, err := conn.Read(response)
	if length > 0 {
		return response[:length], nil
	}
	if err != nil {
		var netErr net.Error
		if (errors.As(err, &netErr) && netErr.Timeout()) ||
			errors.Is(err, syscall.ECONNREFUSED) { // timeout error or connection refused
			return []byte{}, nil
		}
		return response[:length], &ReadError{
			Info:         hex.EncodeToString(response[:length]),
			WrappedError: err,
		}
	}
	return response[:length], nil
}

func SendRecv(conn net.Conn, data []byte, timeout time.Duration) ([]byte, error) {
	err := Send(conn, data, timeout)
	if err != nil {
		return []byte{}, err
	}
	return Recv(conn, timeout)
}
