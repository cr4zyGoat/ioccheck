package main

import (
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
	ApiKey string
}

type AlienVaultResponse struct {
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

func (client *AlienVaultClient) getIocType(ioc IOC) (string, error) {
	switch {
	case ioc.IsIPv4():
		return "IPv4", nil
	case ioc.IsIPv6():
		return "IPv6", nil
	case ioc.IsURL():
		return "url", nil
	case ioc.IsDomain():
		return "domain", nil
	case ioc.IsHash():
		return "file", nil
	default:
		serror := fmt.Sprintf("Unknown IOC type for %s", ioc)
		return "", errors.New(serror)
	}
}

func (client *AlienVaultClient) CheckIOC(ioc IOC) bool {
	ioctype, err := client.getIocType(ioc)
	if err != nil {
		return false
	}

	url := fmt.Sprintf("%s/indicators/%s/%s", alienVaultBaseUrl, ioctype, ioc)
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Add("X-OTX-API-KEY", client.ApiKey)

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Println(err)
		return false
	}
	defer res.Body.Close()

	var data AlienVaultResponse
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
