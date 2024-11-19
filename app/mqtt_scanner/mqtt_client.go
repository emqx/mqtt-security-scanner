package mqtt_scanner

import (
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	mqtt "github.com/eclipse/paho.mqtt.golang"

	"mqtt-security-scanner/config"
)

// NewMQTTClient returns a new mqtt client with the specified connection settings
func NewMQTTClient(protocol, broker string, port int, clientID, username, password string) mqtt.Client {
	// Form a connection address string with the given protocol, broker and port
	connectAddress := fmt.Sprintf("%s://%s:%d", protocol, broker, port)

	// Initialize a new mqtt client options
	opts := mqtt.NewClientOptions()
	opts.AddBroker(connectAddress)
	opts.SetUsername(username)
	opts.SetPassword(password)
	opts.SetClientID(clientID)
	opts.SetAutoReconnect(false)

	// Create a new mqtt client
	client := mqtt.NewClient(opts)
	return client
}

// MQTTClientAuthentication scans for client connection authentication
func MQTTClientAuthentication(cfg *config.Config) (*config.ScanItem, error) {
	si := config.NewScanItem("Client Authentication")

	satisfied := true
	// Check the client connection when username and password are set
	client := NewMQTTClient("tcp", cfg.BrokerInfo.Host, cfg.BrokerInfo.MQTTPort,
		"mqtt-security-scanner-with-authentication", cfg.BrokerInfo.Username, cfg.BrokerInfo.Password)

	if ok := verifyClientConnection(client); !ok {
		satisfied = false
		si.Message = append(si.Message, "MQTT client connection with authentication failed")
	}

	// Check the client connection when no username and password are set
	client = NewMQTTClient("tcp", cfg.BrokerInfo.Host, cfg.BrokerInfo.MQTTPort,
		"mqtt-security-scanner-without-authentication", "", "")

	if ok := verifyClientConnection(client); ok {
		satisfied = false
		si.Message = append(si.Message, "MQTT client connection without authentication succeed")
	}

	// Check the client connection when wrong username and password are set
	client = NewMQTTClient("tcp", cfg.BrokerInfo.Host, cfg.BrokerInfo.MQTTPort,
		"mqtt-security-scanner-with-wrong-authentication", "wrong_user", "wrong_pass")

	if ok := verifyClientConnection(client); ok {
		satisfied = false
		si.Message = append(si.Message, "MQTT client connection with wrong authentication succeed")
	}

	si.Pass = satisfied
	return si, nil
}

// MQTTClientUsernameLength scans if a client with an excessive username length can connect
func MQTTClientUsernameLength(cfg *config.Config) (*config.ScanItem, error) {
	si := config.NewScanItem("MQTT Client Username Length")

	// Create a client with an exceeded username length
	client := NewMQTTClient("tcp", cfg.BrokerInfo.Host, cfg.BrokerInfo.MQTTPort,
		"mqtt-security-scanner-exceeded-username", RandomString(cfg.Limit.PasswordLen+10), "password")

	token := client.Connect()
	if !token.Wait() {
		si.Message = append(si.Message, "MQTT client username length limit connection timeout")
		return si, nil
	}

	if token.Error() == nil {
		si.Message = append(si.Message, "MQTT client can still connect even if username len exceed")
		return si, nil
	}

	if token.Error() != nil && !errors.Is(token.Error(), io.EOF) {
		si.Message = append(si.Message, fmt.Sprintf("MQTT client username length limit does not work, error: %v", token.Error()))
		return si, nil
	}

	si.Pass = true
	return si, nil
}

// MQTTClientPasswordLength scans if a client with an excessive password length can connect
func MQTTClientPasswordLength(cfg *config.Config) (*config.ScanItem, error) {
	si := config.NewScanItem("MQTT Client password Length")

	// Create a client with an exceeded password length
	client := NewMQTTClient("tcp", cfg.BrokerInfo.Host, cfg.BrokerInfo.MQTTPort,
		"mqtt-security-scanner-exceeded-password", "username", RandomString(cfg.Limit.PasswordLen+10))

	token := client.Connect()
	if !token.Wait() {
		si.Message = append(si.Message, "MQTT client password length limit connection timeout")
		return si, nil
	}

	if token.Error() == nil {
		si.Message = append(si.Message, "MQTT client can still connect even if password len exceed")
		return si, nil
	}

	if token.Error() != nil && !errors.Is(token.Error(), io.EOF) {
		si.Message = append(si.Message, fmt.Sprintf("MQTT client password length limit does not work, error: %v", token.Error()))
		return si, nil
	}

	si.Pass = true
	return si, nil
}

// MQTTClientIDLength scans if a client with an excessive ID length can connect
func MQTTClientIDLength(cfg *config.Config) (*config.ScanItem, error) {
	si := config.NewScanItem("MQTT Client ID Length")

	// Create a client with an exceeded ID length
	client := NewMQTTClient("tcp", cfg.BrokerInfo.Host, cfg.BrokerInfo.MQTTPort,
		RandomString(cfg.Limit.ClientIDLen+1000), cfg.BrokerInfo.Username, cfg.BrokerInfo.Password)

	token := client.Connect()
	if !token.WaitTimeout(3 * time.Second) {
		return nil, errors.New("MQTT client ID length limit connection timeout")
	}
	if token.Error() == nil {
		si.Message = append(si.Message, "MQTT client can still connect even if ID len exceed")
		return si, nil
	}
	if token.Error() != nil {
		// For id len exceed, the error message is "identifier rejected"
		if !strings.Contains(token.Error().Error(), "identifier rejected") {
			si.Message = append(si.Message, "MQTT client ID length limit does not work")
			return si, nil
		}
	}

	si.Pass = true
	return si, nil
}

// MQTTClientFlapping is used to check if a MQTT client is being added to a blacklist after flapping.
func MQTTClientFlapping(cfg *config.Config) (*config.ScanItem, error) {
	si := config.NewScanItem("MQTT Client Flapping")

	// Initialize a MQTT client
	client := NewMQTTClient("tcp", cfg.BrokerInfo.Host, cfg.BrokerInfo.MQTTPort,
		"mqtt-security-scanner-flapping", cfg.BrokerInfo.Username, cfg.BrokerInfo.Password)

	// Repeatedly connect and disconnect limit+10 times
	for i := 0; i < cfg.Limit.Flapping+10; i++ {
		time.Sleep(10 * time.Millisecond)
		if token := client.Connect(); token.WaitTimeout(3*time.Second) && token.Error() == nil {
			client.Disconnect(0)
		} else {
			break
		}
	}

	// Check if next connection attempt is blocked due to flapping
	token := client.Connect()
	if !token.WaitTimeout(3*time.Second) || token.Error() == nil {
		si.Message = append(si.Message, "MQTT client connection flapping does not work")
		return si, nil
	}
	// For flapping, the error message is "not Authorized"
	if token.Error() != nil {
		if !strings.Contains(token.Error().Error(), "not Authorized") {
			si.Message = append(si.Message,
				fmt.Sprintf("MQTT client connection flapping does not work, with error: %v", token.Error()))
			return si, nil
		}
	}

	si.Pass = true
	return si, nil
}

// MQTTClientConnection is used to test the maximum concurrent connections a MQTT broker can handle.
func MQTTClientConnection(cfg *config.Config) (*config.ScanItem, error) {
	si := config.NewScanItem("MQTT Client Connection")

	stopCh := make(chan struct{})
	defer close(stopCh)

	// Create the specified concurrent connections
	for i := 0; i < cfg.Limit.Connection+500; i++ {
		time.Sleep(10 * time.Millisecond)
		go func() {
			client := NewMQTTClient("tcp", cfg.BrokerInfo.Host, cfg.BrokerInfo.MQTTPort,
				"mqtt-security-scanner-connection-"+RandomString(10),
				cfg.BrokerInfo.Username, cfg.BrokerInfo.Password)

			client.Connect()
			<-stopCh
		}()
	}

	time.Sleep(5 * time.Second)

	// Create one more connection to check if the connection limit is working
	client := NewMQTTClient("tcp", cfg.BrokerInfo.Host, cfg.BrokerInfo.MQTTPort,
		"mqtt-security-scanner-connection", cfg.BrokerInfo.Username, cfg.BrokerInfo.Password)

	token := client.Connect()
	if !token.WaitTimeout(3 * time.Second) {
		si.Message = append(si.Message, "MQTT client connection number scanner connect timeout")
		return si, nil
	}

	if token.Error() == nil {
		si.Message = append(si.Message, "MQTT client connection limit does not work, can still connect")
		return si, nil
	}

	if token.Error() != nil && !strings.Contains(token.Error().Error(), "server Unavailable") {
		si.Message = append(si.Message, "MQTT client connection limit does not work")
		return si, nil
	}

	si.Pass = true
	return si, nil
}

// verifyClientConnection verifies if the MQTT client can establish a connection with the MQTT broker
func verifyClientConnection(client mqtt.Client) bool {
	token := client.Connect()
	if !token.Wait() {
		return false
	}
	if token.Error() != nil {
		return false
	}
	return true
}
