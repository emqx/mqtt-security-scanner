package mqtt_scanner

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"mqtt-security-scanner/config"
)

// TLSMap Mapping between TLS versions and their string representations
var TLSMap = map[uint16]string{768: "SSL3.0", 769: "TLS1.0", 770: "TLS1.1", 771: "TLS1.2", 772: "TLS1.3"}

// InvalidMQTTProtocolScanner scans the broker to check if it supports invalid MQTT message format connections
func InvalidMQTTProtocolScanner(cfg *config.Config) (*config.ScanItem, error) {
	si := config.NewScanItem("Invalid MQTT Message")

	// Check if MQTT port accepts non-MQTT messages
	ok, err := checkDenyNonMQTTConnection(cfg.BrokerInfo.Host, cfg.BrokerInfo.MQTTPort)
	if err != nil {
		return nil, err
	}

	if !ok {
		si.Message = append(si.Message, "Invalid MQTT protocol connect successfully")
		return si, nil
	}

	si.Pass = true
	return si, nil
}

// InvalidWSProtocolScanner scans the broker to check if it supports invalid WebSocket message format connections
func InvalidWSProtocolScanner(cfg *config.Config) (*config.ScanItem, error) {
	si := config.NewScanItem("Invalid Websocket Protocol")

	// Check if MQTT over websocket port accepts non-MQTT messages
	ok, err := checkDenyNonMQTTConnection(cfg.BrokerInfo.Host, cfg.BrokerInfo.WSPort)
	if err != nil {
		return nil, err
	}

	if !ok {
		si.Message = append(si.Message, "Invalid websocket protocol connect successfully")
		return si, nil
	}

	si.Pass = true
	return si, nil
}

// TLSVersionsScanner scans the broker for supported TLS protocol versions
func TLSVersionsScanner(cfg *config.Config) (*config.ScanItem, error) {
	si := config.NewScanItem("TLS Version")

	satisfied := true
	// Check if all the supported TLS protocol versions are actually supported
	for _, version := range cfg.Limit.SupportTLSVersions {
		ok, err := checkTLSVersion(cfg.BrokerInfo.Host, cfg.BrokerInfo.MQTTSPort, version)
		if err != nil {
			return nil, err
		}

		if !ok {
			satisfied = false
			si.Message = append(si.Message, fmt.Sprintf("TLS version %s is not supported", TLSMap[version]))
		}
	}

	// Check if all the unsupported TLS protocol versions are actually unsupported
	for _, version := range cfg.Limit.UnsupportedTLSVersions {
		ok, err := checkTLSVersion(cfg.BrokerInfo.Host, cfg.BrokerInfo.MQTTSPort, version)
		if err != nil {
			return nil, err
		}

		if ok {
			satisfied = false
			si.Message = append(si.Message, fmt.Sprintf("Unsafe TLS version %s is support", TLSMap[version]))
		}
	}

	si.Pass = satisfied
	return si, nil
}

// checkDenyNonMQTTConnection checks if the specified TCP port denies non-MQTT protocol connections
// Under normal circumstances, the behavior of the EMQX broker's denial is to reply with a fin packet, corresponding to EOF
func checkDenyNonMQTTConnection(host string, port int) (bool, error) {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), 3*time.Second)
	if err != nil {
		return false, err
	}
	defer conn.Close()

	_, err = conn.Write([]byte("Non-MQTT message"))
	if err != nil {
		return false, err
	}

	response := make([]byte, 1024)
	_, err = conn.Read(response)
	if err != nil {
		if errors.Is(err, io.EOF) {
			return true, nil
		}
		return false, err
	}
	return false, nil
}

// checkTLSVersion checks the supported TLS protocol versions
// True should be returned for a given version that is supported
// False should be returned for a given version that is unsupported
// An error is returned if an unknown error occurs in the connection
func checkTLSVersion(host string, port int, tlsVersion uint16) (bool, error) {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), 3*time.Second)
	if err != nil {
		return false, err
	}
	defer conn.Close()

	c := &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tlsVersion,
		MaxVersion:         tlsVersion,
	}

	tlsClient := tls.Client(conn, c)
	defer tlsClient.Close()

	// Unsupported TLS versions may output the following two error messages
	if err := tlsClient.Handshake(); err != nil {
		if strings.Contains(err.Error(), "no supported versions satisfy MinVersion and MaxVersion") ||
			strings.Contains(err.Error(), "protocol version not supported") {
			return false, nil
		}
		return false, err
	}

	return true, nil
}
