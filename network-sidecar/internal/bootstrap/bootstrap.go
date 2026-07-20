// Package bootstrap decodes the one-time sidecar secret bootstrap message.
package bootstrap

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"unicode"
)

const (
	ProtocolVersion = 1
	maxMessageSize  = 64 * 1_024
)

var (
	ErrMessageTooLarge = errors.New("bootstrap message too large")
	ErrInvalidConfig   = errors.New("invalid bootstrap configuration")
)

type Config struct {
	ProtocolVersion uint8  `json:"protocol_version"`
	InstanceID      string `json:"instance_id"`
	AuthToken       []byte `json:"auth_token"`
	PrivateKey      []byte `json:"private_key"`
}

func (config *Config) Clear() {
	clear(config.AuthToken)
	clear(config.PrivateKey)
}

func (config Config) String() string {
	return fmt.Sprintf("Config{ProtocolVersion:%d InstanceID:%q AuthToken:<redacted> PrivateKey:<redacted>}", config.ProtocolVersion, config.InstanceID)
}

func DecodeLine(reader *bufio.Reader) (Config, error) {
	message, err := reader.ReadSlice('\n')
	if errors.Is(err, bufio.ErrBufferFull) || len(message) > maxMessageSize {
		clear(message)
		return Config{}, ErrMessageTooLarge
	}
	if err != nil && !errors.Is(err, io.EOF) {
		clear(message)
		return Config{}, fmt.Errorf("read bootstrap: %w", err)
	}
	message = bytes.TrimSuffix(message, []byte{'\n'})
	decoder := json.NewDecoder(bytes.NewReader(message))
	decoder.DisallowUnknownFields()
	var config Config
	if decodeErr := decoder.Decode(&config); decodeErr != nil {
		config.Clear()
		clear(message)
		return Config{}, fmt.Errorf("decode bootstrap: %w", ErrInvalidConfig)
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		config.Clear()
		clear(message)
		return Config{}, ErrInvalidConfig
	}
	clear(message)
	if config.ProtocolVersion != ProtocolVersion || !validInstanceID(config.InstanceID) || len(config.AuthToken) < 32 || len(config.AuthToken) > 64 || len(config.PrivateKey) != 32 {
		config.Clear()
		return Config{}, ErrInvalidConfig
	}
	return config, nil
}

func AuthProof(config Config) string {
	authenticator := hmac.New(sha256.New, config.AuthToken)
	_, _ = authenticator.Write([]byte("kyclash-sidecar-bootstrap-v1\x00"))
	_, _ = authenticator.Write([]byte(config.InstanceID))
	return hex.EncodeToString(authenticator.Sum(nil))
}

func validInstanceID(value string) bool {
	if len(value) < 8 || len(value) > 64 {
		return false
	}
	for _, character := range value {
		if !(unicode.IsLetter(character) || unicode.IsDigit(character) || character == '-' || character == '_') || character > unicode.MaxASCII {
			return false
		}
	}
	return true
}
