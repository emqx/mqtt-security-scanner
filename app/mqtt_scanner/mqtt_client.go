package mqtt_scanner

import (
	"fmt"
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
	si := config.NewScanItem("Client Connection Authentication")

	satisfied := true
	// Check the client connection when username and password are set
	client := NewMQTTClient("tcp", cfg.BrokerInfo.Host, cfg.BrokerInfo.MQTTPort,
		"cloud-security-scanner-with-authentication", cfg.BrokerInfo.Username, cfg.BrokerInfo.Password)

	if ok := VerifyMQTTConnection(client); !ok {
		satisfied = false
		si.Message = append(si.Message, "MQTT client connection with authentication failed")
	}

	// Check the client connection when no username and password are set
	client = NewMQTTClient("tcp", cfg.BrokerInfo.Host, cfg.BrokerInfo.MQTTPort,
		"cloud-security-scanner-without-authentication", "", "")

	if ok := VerifyMQTTConnection(client); ok {
		satisfied = false
		si.Message = append(si.Message, "MQTT client connection without authentication succeed")
	}

	// Check the client connection when wrong username and password are set
	client = NewMQTTClient("tcp", cfg.BrokerInfo.Host, cfg.BrokerInfo.MQTTPort,
		"cloud-security-scanner-with-wrong-authentication", "wrong_user", "wrong_pass")

	if ok := VerifyMQTTConnection(client); ok {
		satisfied = false
		si.Message = append(si.Message, "MQTT client connection with wrong authentication succeed")
	}

	si.Pass = satisfied
	return si, nil
}

// MqttClientUsernameLength scans if a client with an excessive username length can connect
func MqttClientUsernameLength(cfg *config.Config) (*config.ScanItem, error) {
	si := config.NewScanItem("MQTT Client Username Length")

	// Create a client with an exceeded username length
	client := NewMQTTClient("tcp", cfg.BrokerInfo.Host, cfg.BrokerInfo.MQTTPort,
		"cloud-security-scanner-exceeded-username", RandomString(cfg.Limit.PasswordLen+10), "password")

	token := client.Connect()
	token.Wait()
	if token.Error() == nil {
		si.Message = append(si.Message, "MQTT client username length limit does not connect")
		return si, nil
	}

	if token.Error() != nil {
		si.Message = append(si.Message, "MQTT client username length limit does not work")
		return si, nil
	}

	si.Pass = true
	return si, nil
}

// MqttClientPasswordLength scans if a client with an excessive password length can connect
func MqttClientPasswordLength(cfg *config.Config) (*config.ScanItem, error) {
	si := config.NewScanItem("MQTT Client password Length")

	// Create a client with an exceeded password length
	client := NewMQTTClient("tcp", cfg.BrokerInfo.Host, cfg.BrokerInfo.MQTTPort,
		"cloud-security-scanner-exceeded-password", "username", RandomString(cfg.Limit.PasswordLen+10))

	token := client.Connect()
	token.Wait()
	if token.Error() == nil {
		si.Message = append(si.Message, "MQTT client password length limit does not work")
		return si, nil
	}

	if token.Error() != nil {
		si.Message = append(si.Message, "MQTT client password length limit does not work")
		return si, nil
	}

	si.Pass = true
	return si, nil
}

// MqttClientIDLength scans if a client with an excessive ID length can connect
func MqttClientIDLength(cfg *config.Config) (*config.ScanItem, error) {
	si := config.NewScanItem("MQTT Client ID Length")

	// Create a client with an exceeded ID length
	client := NewMQTTClient("tcp", cfg.BrokerInfo.Host, cfg.BrokerInfo.MQTTPort,
		RandomString(cfg.Limit.ClientIDLen+1000), cfg.BrokerInfo.Username, cfg.BrokerInfo.Password)

	token := client.Connect()
	token.Wait()
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

// MqttClientFlapping is used to check if a MQTT client is being added to a blacklist after flapping.
func MqttClientFlapping(cfg *config.Config) (*config.ScanItem, error) {
	si := config.NewScanItem("MQTT Client Flapping")

	// Initialize a MQTT client
	client := NewMQTTClient("tcp", cfg.BrokerInfo.Host, cfg.BrokerInfo.MQTTPort,
		"cloud-security-scanner-flapping", cfg.BrokerInfo.Username, cfg.BrokerInfo.Password)

	// Repeatedly connect and disconnect 70 times
	for i := 0; i < 70; i++ {
		time.Sleep(10 * time.Millisecond)
		if token := client.Connect(); token.Wait() && token.Error() == nil {
			client.Disconnect(0)
		} else {
			break
		}
	}

	// Check if the 71st connection attempt is blocked due to flapping
	token := client.Connect()
	if !token.Wait() || token.Error() == nil {
		si.Message = append(si.Message, "MQTT client connection flapping does not work")
		return si, nil
	}
	// For flapping, the error message is "not Authorized"
	if token.Error() != nil {
		if !strings.Contains(token.Error().Error(), "not Authorized") {
			return nil, token.Error()
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
	for i := 0; i < cfg.Limit.Connection; i++ {
		time.Sleep(10 * time.Millisecond)
		go func() {
			client := NewMQTTClient("tcp", cfg.BrokerInfo.Host, cfg.BrokerInfo.MQTTPort,
				"cloud-security-scanner-connection-"+RandomString(10),
				cfg.BrokerInfo.Username, cfg.BrokerInfo.Password)

			client.Connect()
			<-stopCh
		}()
	}

	time.Sleep(2 * time.Second)

	// Create one more connection to check if the connection limit is working
	client := NewMQTTClient("tcp", cfg.BrokerInfo.Host, cfg.BrokerInfo.MQTTPort,
		"cloud-security-scanner-connection", cfg.BrokerInfo.Username, cfg.BrokerInfo.Password)

	token := client.Connect()
	if !token.Wait() {
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
