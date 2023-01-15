package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
)

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

type AbuseIPClient struct {
	BaseURL string
	ApiKey  string
}

func (client *AbuseIPClient) CheckIOC(ioc IOC) bool {
	url := fmt.Sprintf("%s/api/v2/check?ipAddress=%s", client.BaseURL, ioc)
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Key", client.ApiKey)

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Fatalln(err)
	}
	defer res.Body.Close()

	var response AbuseIPResponse
	body, _ := io.ReadAll(res.Body)
	err = json.Unmarshal(body, &response)
	if err != nil {
		log.Fatalln(err)
	}

	if response.Data.AbuseConfidenceScore > 40 {
		return true
	}

	return false
}
