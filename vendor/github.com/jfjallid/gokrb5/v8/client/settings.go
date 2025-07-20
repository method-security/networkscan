package client

import (
	"encoding/json"
	"fmt"
	"log"
	"time"

	"golang.org/x/net/proxy"
)

// Settings holds optional client settings.
type Settings struct {
	disablePAFXFast         bool
	assumePreAuthentication bool
	requestPAPac            bool
	preAuthEType            int32
	logger                  *log.Logger
	proxyDialer             proxy.Dialer
	dialTimout              time.Duration
}

// jsonSettings is used when marshaling the Settings details to JSON format.
type jsonSettings struct {
	DisablePAFXFast         bool
	AssumePreAuthentication bool
}

// NewSettings creates a new client settings struct.
func NewSettings(settings ...func(*Settings)) *Settings {
	s := new(Settings)
	s.dialTimout = time.Second * 5 // default value
	for _, set := range settings {
		set(s)
	}
	return s
}

// DisablePAFXFAST used to configure the client to not use PA_FX_FAST.
//
// s := NewSettings(DisablePAFXFAST(true))
func DisablePAFXFAST(b bool) func(*Settings) {
	return func(s *Settings) {
		s.disablePAFXFast = b
	}
}

// DisablePAFXFAST indicates is the client should disable the use of PA_FX_FAST.
func (s *Settings) DisablePAFXFAST() bool {
	return s.disablePAFXFast
}

// AssumePreAuthentication used to configure the client to assume pre-authentication is required.
//
// s := NewSettings(AssumePreAuthentication(true))
func AssumePreAuthentication(b bool) func(*Settings) {
	return func(s *Settings) {
		s.assumePreAuthentication = b
	}
}

// AssumePreAuthentication indicates if the client should proactively assume using pre-authentication.
func (s *Settings) AssumePreAuthentication() bool {
	return s.assumePreAuthentication
}

// Logger used to configure client with a logger.
//
// s := NewSettings(kt, Logger(l))
func Logger(l *log.Logger) func(*Settings) {
	return func(s *Settings) {
		s.logger = l
	}
}

// Logger returns the client logger instance.
func (s *Settings) Logger() *log.Logger {
	return s.logger
}

// Log will write to the service's logger if it is configured.
func (cl *Client) Log(format string, v ...interface{}) {
	if cl.settings.Logger() != nil {
		cl.settings.Logger().Output(2, fmt.Sprintf(format, v...))
	}
}

// JSON returns a JSON representation of the settings.
func (s *Settings) JSON() (string, error) {
	js := jsonSettings{
		DisablePAFXFast:         s.disablePAFXFast,
		AssumePreAuthentication: s.assumePreAuthentication,
	}
	b, err := json.MarshalIndent(js, "", "  ")
	if err != nil {
		return "", err
	}
	return string(b), nil

}

// SetDialTimout used to configure the client with a custom timeout for establishing network connections
//
// s := NewSettings(SetDialTimout(time.Duration))
func SetDialTimout(d time.Duration) func(*Settings) {
	return func(s *Settings) {
		s.dialTimout = d
	}
}

// GetDialTimeout returns the client dial timeout duration
func (s *Settings) GetDialTimeout() time.Duration {
	return s.dialTimout
}

// SetProxyDialer used to configure the client to use an upstream proxy for all network communication
//
// s := NewSettings(SetProxyDialer(proxy.Dialer))
func SetProxyDialer(dialer proxy.Dialer) func(*Settings) {
	return func(s *Settings) {
		s.proxyDialer = dialer
	}
}

// ProxyDialer returns the client proxyDialer instance
func (s *Settings) ProxyDialer() proxy.Dialer {
	return s.proxyDialer
}

// RequestPAPac used to configure the client to request that the KDC include a PAC
//
// s := NewSettings(RequestPAPac(true))
func RequestPAPac(b bool) func(*Settings) {
	return func(s *Settings) {
		s.requestPAPac = b
	}
}

// RequestPAPac indicates that the client should request that the KDC includes a PAC
func (s *Settings) RequestPAPac() bool {
	return s.requestPAPac
}
