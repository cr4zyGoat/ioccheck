package ticlients

import (
	"cr4zygoat/ioccheck/util"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
)

const (
	alienVaultBaseUrl string = "https://otx.alienvault.com/api/v1"
)

type AlienVaultClient struct {
	threads    chan bool
	apiKeys    []string
	reqCounter int
}

type alienVaultResponse struct {
	Type      string `json:"type"`
	Indicator string `json:"indicator"`
	PulseInfo struct {
		Count  int `json:"count"`
		Pulses []struct {
			Id   string `json:"id"`
			Name string `json:"name"`
		} `json:"pulses"`
	} `json:"pulse_info"`
}

func NewAlienVaultClient(keys []string, threads int) *AlienVaultClient {
	client := new(AlienVaultClient)
	client.threads = make(chan bool, threads)
	client.apiKeys = keys
	return client
}

func (client *AlienVaultClient) getIocType(ioc string) (string, error) {
	switch {
	case util.IsIPv4(ioc):
		return "IPv4", nil
	case util.IsIPv6(ioc):
		return "IPv6", nil
	case util.IsUrl(ioc):
		return "url", nil
	case util.IsDomain(ioc):
		return "domain", nil
	case util.IsHash(ioc):
		return "file", nil
	default:
		message := fmt.Sprintf("Unknown IOC type for %s", ioc)
		return "", errors.New(message)
	}
}

func (client *AlienVaultClient) CheckIOC(ioc string) bool {
	ioctype, err := client.getIocType(ioc)
	if err != nil {
		return false
	}

	apikey := client.apiKeys[client.reqCounter%len(client.apiKeys)]
	client.reqCounter += 1

	url := fmt.Sprintf("%s/indicators/%s/%s", alienVaultBaseUrl, ioctype, ioc)
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Add("X-OTX-API-KEY", apikey)

	client.threads <- true
	res, err := http.DefaultClient.Do(req)
	<-client.threads

	if err != nil {
		log.Println(err)
		return false
	}
	defer res.Body.Close()

	var data alienVaultResponse
	body, _ := io.ReadAll(res.Body)
	err = json.Unmarshal(body, &data)
	if err != nil {
		log.Println(err)
		return false
	}

	if data.PulseInfo.Count > 0 {
		return true
	}

	return false
}
