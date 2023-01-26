package main

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"net/http"
)

const (
	threatfoxBaseUrl string = "https://threatfox-api.abuse.ch/api/v1"
)

type ThreatFoxClient struct{}

type ThreatFoxResponse struct {
	QueryStatus string      `json:"query_status"`
	Data        interface{} `json:"data"`
}

type ThreatFoxDataResponse struct {
	Id              string `json:"id"`
	IoC             string `json:"ioc"`
	IoCType         string `json:"ioc_type"`
	ThreatType      string `json:"threat_type"`
	Malware         string `json:"malware"`
	ConfidenceLevel int    `json:"confidence_level"`
}

func (client *ThreatFoxClient) CheckIoC(ioc IOC) bool {
	params := map[string]string{
		"query":       "search_ioc",
		"search_term": string(ioc),
	}

	jparams, err := json.Marshal(params)
	if err != nil {
		log.Println(err)
		return false
	}

	res, err := http.Post(threatfoxBaseUrl, "application/json", bytes.NewReader(jparams))
	if err != nil {
		log.Println(err)
		return false
	}
	defer res.Body.Close()

	var response ThreatFoxResponse
	body, _ := io.ReadAll(res.Body)
	err = json.Unmarshal(body, &response)
	if err != nil {
		log.Println(err)
		return false
	}

	data, ok := response.Data.([]interface{})
	if response.QueryStatus == "ok" && ok {
		if !ioc.IsDomain() {
			return true
		}

		for _, item := range data {
			mitem, ok := item.(map[string]interface{})
			if ok && mitem["ioc_type"] == "domain" && mitem["ioc"] == string(ioc) {
				return true
			}
		}
	}

	return false
}
