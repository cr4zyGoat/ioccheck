package ticlients

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
	threads    chan bool
	apiKeys    []string
	reqCounter int
}

type abuseIPResponse struct {
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

func NewAbuseIPClient(keys []string, threads int) *AbuseIPClient {
	client := new(AbuseIPClient)
	client.threads = make(chan bool, threads)
	client.apiKeys = keys
	return client
}

func (client *AbuseIPClient) CheckIP(ioc string) bool {
	apikey := client.apiKeys[client.reqCounter%len(client.apiKeys)]
	client.reqCounter += 1

	url := fmt.Sprintf("%s/check?ipAddress=%s", abuseIPBaseUrl, ioc)
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Key", apikey)

	client.threads <- true
	res, err := http.DefaultClient.Do(req)
	<-client.threads

	if err != nil {
		log.Println(err)
		return false
	}
	defer res.Body.Close()

	var response abuseIPResponse
	body, _ := io.ReadAll(res.Body)
	err = json.Unmarshal(body, &response)
	if err != nil {
		log.Println(err)
		return false
	}

	if response.Data.AbuseConfidenceScore >= 30 {
		return true
	}

	return false
}
