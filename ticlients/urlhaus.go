package ticlients

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
)

const (
	urlHausBaseUrl string = "https://urlhaus-api.abuse.ch/v1"
)

type UrlHausClient struct {
	threads chan bool
}

type urlHausResponse struct {
	QueryStatus string   `json:"query_status"`
	Id          string   `json:"id"`
	Url         string   `json:"url"`
	Host        string   `json:"host"`
	UrlStatus   string   `json:"url_status"`
	Threat      string   `json:"threat"`
	Tags        []string `json:"tags"`
}

func NewUrlHausClient(threads int) *UrlHausClient {
	client := new(UrlHausClient)
	client.threads = make(chan bool, threads)
	return client
}

func (client *UrlHausClient) CheckURL(ioc string) bool {
	endpoint := fmt.Sprintf("%s/url/", urlHausBaseUrl)
	params := url.Values{}
	params.Add("url", ioc)

	res, err := http.PostForm(endpoint, params)
	if err != nil {
		log.Println(err)
		return false
	}

	defer res.Body.Close()
	var response urlHausResponse
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
