package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
)

const (
	abuseIPBaseUrl string = "https://api.abuseipdb.com/api/v2"
)

type AbuseIPClient struct {
	apiKeys    []string
	reqCounter int
}

type AbuseIPResponse struct {
	Data struct {
		IPAddress            string   `json:"ipAddress"`
		AbuseConfidenceScore int      `json:"abuseConfidenceScore"`
		CountryCode          string   `json:"countryCode"`
		CountryName          string   `json:"countryName"`
		UsageType            string   `json:"usageType"`
		Domain               string   `json:"domain"`
		Hostnames            []string `json:"hostnames"`
		TotalReports         int      `json:"totalReports"`
	} `json:"data"`
}

func (client *AbuseIPClient) hasKeys() bool {
	return len(client.apiKeys) > 0
}

func (client *AbuseIPClient) CheckIP(ioc IOC) bool {
	if !client.hasKeys() {
		return false
	}

	apikey := client.apiKeys[client.reqCounter%len(client.apiKeys)]
	client.reqCounter += 1

	url := fmt.Sprintf("%s/check?ipAddress=%s", abuseIPBaseUrl, ioc)
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Key", apikey)

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Println(err)
		return false
	}
	defer res.Body.Close()

	var response AbuseIPResponse
	body, _ := io.ReadAll(res.Body)
	err = json.Unmarshal(body, &response)
	if err != nil {
		log.Println(err)
		return false
	}

	if response.Data.AbuseConfidenceScore > 40 {
		return true
	}

	return false
}
