package webhooks

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
)

func SendMessage(userGuid string, ip string, webhookURL string) error {
	if webhookURL == "" {
		// webhookURL = os.Getenv("WEBHOOK")
	}

	payload := map[string]string{
		"event":    "access from new ip",
		"userguid": userGuid,
		"newIp":    ip,
		"email":    "37dae481-23bd-44b8-9fd1-c8f1319d1129@emailhook.site",
	}

	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	client := &http.Client{}

	req, err := http.NewRequest("POST", webhookURL, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return err
	}

	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		fmt.Println("Webhook sent successfully!")
	} else {
		fmt.Printf("Failed to send webhook. Status Code: %d\n", resp.StatusCode)
	}
	return nil
}
