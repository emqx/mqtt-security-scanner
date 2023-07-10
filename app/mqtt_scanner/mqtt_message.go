package mqtt_scanner

import (
	"errors"
	"fmt"

	mqtt "github.com/eclipse/paho.mqtt.golang"

	"mqtt-security-scanner/config"
)

// MQTTMessageDenyTopic checks if the MQTT broker denies messages to certain topics.
func MQTTMessageDenyTopic(cfg *config.Config) (*config.ScanItem, error) {
	si := config.NewScanItem("MQTT Message Deny Topic")

	client := NewMQTTClient("tcp", cfg.BrokerInfo.Host, cfg.BrokerInfo.MQTTPort,
		"cloud-security-scanner-deny-topic", cfg.BrokerInfo.Username, cfg.BrokerInfo.Password)

	if token := client.Connect(); token.Wait() && token.Error() != nil {
		si.Message = append(si.Message, "MQTT message deny topic connect failed")
		return si, nil
	}

	satisfied := true
	for _, topic := range cfg.BrokerInfo.DenyTopics {
		if err := subscribe(client, topic); err == nil {
			satisfied = false
			si.Message = append(si.Message, fmt.Sprintf("MQTT deny topic %s does not work", topic))
		}
	}

	si.Pass = satisfied
	return si, nil
}

// MQTTTopicLevel checks if the MQTT broker supports a topic with more levels than the limit.
func MQTTTopicLevel(cfg *config.Config) (*config.ScanItem, error) {
	si := config.NewScanItem("MQTT Topic Level")

	client := NewMQTTClient("tcp", cfg.BrokerInfo.Host, cfg.BrokerInfo.MQTTPort,
		"cloud-security-scanner-topic-level", cfg.BrokerInfo.Username, cfg.BrokerInfo.Password)

	if token := client.Connect(); token.Wait() && token.Error() != nil {
		si.Message = append(si.Message, "MQTT topic level connect failed")
		return si, nil
	}

	if err := publish(client, GenerateRandomTopic(cfg.Limit.TopicLevel+5), "MQTT Topic Level"); err == nil {
		si.Message = append(si.Message, "MQTT topic level limit do not work")
		return si, nil
	}

	si.Pass = true
	return si, nil
}

// MQTTTopicLength checks if the MQTT broker supports a topic length larger than the limit.
func MQTTTopicLength(cfg *config.Config) (*config.ScanItem, error) {
	si := config.NewScanItem("MQTT Topic Length")

	client := NewMQTTClient("tcp", cfg.BrokerInfo.Host, cfg.BrokerInfo.MQTTPort,
		"cloud-security-scanner-topic-length", cfg.BrokerInfo.Username, cfg.BrokerInfo.Password)

	if token := client.Connect(); token.Wait() && token.Error() != nil {
		si.Message = append(si.Message, "MQTT topic length connect failed")
		return si, nil
	}

	if err := subscribe(client, GenerateRandomTopic(cfg.Limit.TopicLen+10)); err == nil {
		si.Message = append(si.Message, "MQTT topic length limit do not work")
		return si, nil
	}

	si.Pass = true
	return si, nil
}

// MQTTMessagePayloadLength checks if the MQTT broker supports a message payload length larger than the limit.
func MQTTMessagePayloadLength(cfg *config.Config) (*config.ScanItem, error) {
	si := config.NewScanItem("MQTT Message Payload Length")

	client := NewMQTTClient("tcp", cfg.BrokerInfo.Host, cfg.BrokerInfo.MQTTPort,
		"cloud-security-scanner-message-payload-length", cfg.BrokerInfo.Username, cfg.BrokerInfo.Password)

	if token := client.Connect(); token.Wait() && token.Error() != nil {
		si.Message = append(si.Message, "MQTT message payload length connect failed")
		return si, nil
	}

	if err := publish(client, "payload-len-scanner", GenerateRandomTopic(1024*1200*cfg.Limit.PayloadLen)); err == nil {
		si.Message = append(si.Message, "MQTT message payload length limit do not work")
		return si, nil
	}

	si.Pass = true
	return si, nil
}

// subscribe tries to subscribe the MQTT client to a given topic
func subscribe(client mqtt.Client, topic string) error {
	if token := client.Subscribe(topic, byte(0), nil); token.Wait() && token.Error() != nil {
		// For topic len exceeding, error is "connection lost before Subscribe completed"
		return token.Error()
	}
	return nil
}

// publish tries to publish a message with a given payload to a given topic
func publish(client mqtt.Client, topic, payload string) error {
	token := client.Publish(topic, 1, false, payload)
	ack := token.Wait()
	if !ack {
		return errors.New("Broker close connection")
	}

	if token.Error() != nil {
		return token.Error()
	}
	return nil
}
