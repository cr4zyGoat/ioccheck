package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
)

const (
	AbuseIPBaseUrl string = "https://api.abuseipdb.com/api/v2"
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
	ApiKey string
}

func (client *AbuseIPClient) CheckIOC(ioc IOC) bool {
	url := fmt.Sprintf("%s/check?ipAddress=%s", AbuseIPBaseUrl, ioc)
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Key", client.ApiKey)

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
