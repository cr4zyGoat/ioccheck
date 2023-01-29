package ticlients

import (
	"bytes"
	"cr4zygoat/ioccheck/util"
	"encoding/json"
	"io"
	"log"
	"net/http"
)

const (
	threatfoxBaseUrl string = "https://threatfox-api.abuse.ch/api/v1"
)

type ThreatFoxClient struct {
	threads chan bool
}

type threatFoxResponse struct {
	QueryStatus string      `json:"query_status"`
	Data        interface{} `json:"data"`
}

type threatFoxDataResponse struct {
	Id              string `json:"id"`
	IoC             string `json:"ioc"`
	IoCType         string `json:"ioc_type"`
	ThreatType      string `json:"threat_type"`
	Malware         string `json:"malware"`
	ConfidenceLevel int    `json:"confidence_level"`
}

func NewThreatFoxClient(threads int) *ThreatFoxClient {
	client := new(ThreatFoxClient)
	client.threads = make(chan bool, threads)
	return client
}

func (client *ThreatFoxClient) CheckIoC(ioc string) bool {
	params := map[string]string{
		"query":       "search_ioc",
		"search_term": ioc,
	}

	jparams, err := json.Marshal(params)
	if err != nil {
		log.Println(err)
		return false
	}

	client.threads <- true
	res, err := http.Post(threatfoxBaseUrl, "application/json", bytes.NewReader(jparams))
	<-client.threads

	if err != nil {
		log.Println(err)
		return false
	}

	defer res.Body.Close()
	var response threatFoxResponse
	body, _ := io.ReadAll(res.Body)
	err = json.Unmarshal(body, &response)
	if err != nil {
		log.Println(err)
		return false
	}

	data, ok := response.Data.([]interface{})
	if response.QueryStatus == "ok" && ok {
		if !util.IsDomain(ioc) {
			return true
		}

		for _, item := range data {
			mitem, ok := item.(map[string]interface{})
			if ok && mitem["ioc_type"] == "domain" && mitem["ioc"] == ioc {
				return true
			}
		}
	}

	return false
}
