package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
)

const (
	OTXBaseUrl string = "https://otx.alienvault.com/api/v1"
)

type otxResponse struct {
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

type OTXClient struct {
	ApiKey string
}

func getOTXType(ioc IOC) string {
	switch {
	case ioc.IsIPv4():
		return "IPv4"
	case ioc.IsIPv6():
		return "IPv6"
	case ioc.IsURL():
		return "url"
	case ioc.IsDomain():
		return "domain"
	case ioc.IsHash():
		return "file"
	default:
		return ""
	}
}

func (client *OTXClient) CheckIOC(ioc IOC) bool {
	var ioctype string = getOTXType(ioc)
	if ioctype == "" {
		return false
	}

	url := fmt.Sprintf("%s/indicators/%s/%s", OTXBaseUrl, ioctype, ioc)
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Add("X-OTX-API-KEY", client.ApiKey)

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Println(err)
		return false
	}
	defer res.Body.Close()

	var data otxResponse
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
