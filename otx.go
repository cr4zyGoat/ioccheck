package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
)

type otxData struct {
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
	BaseURL string
	ApiKey  string
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

	url := fmt.Sprintf("%s/api/v1/indicators/%s/%s", client.BaseURL, ioctype, ioc)
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Add("X-OTX-API-KEY", client.ApiKey)

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Fatalln(err)
	}
	defer res.Body.Close()

	var data otxData
	body, _ := io.ReadAll(res.Body)
	err = json.Unmarshal(body, &data)
	if err != nil {
		log.Fatalln(err)
	}

	cpulses := data.PulseInfo.Count
	if cpulses > 0 {
		return true
	}

	return false
}
