package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
)

const (
	URLHausBaseUrl string = "https://urlhaus-api.abuse.ch/v1"
)

type URLHausResponse struct {
	QueryStatus string   `json:"query_status"`
	Id          string   `json:"id"`
	Url         string   `json:"url"`
	Host        string   `json:"host"`
	UrlStatus   string   `json:"url_status"`
	Threat      string   `json:"threat"`
	Tags        []string `json:"tags"`
}

type URLHausClient struct{}

func (client *URLHausClient) CheckIOC(ioc IOC) bool {
	endpoint := fmt.Sprintf("%s/url/", URLHausBaseUrl)
	params := url.Values{}
	params.Add("url", string(ioc))

	res, err := http.PostForm(endpoint, params)
	if err != nil {
		log.Println(err)
		return false
	}
	defer res.Body.Close()

	var response URLHausResponse
	body, _ := io.ReadAll(res.Body)
	err = json.Unmarshal(body, &response)
	if err != nil {
		log.Println(err)
		return false
	}

	if response.QueryStatus == "ok" {
		return true
	}

	return false
}
