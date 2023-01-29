package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/user"
	"path/filepath"

	"github.com/cr4zygoat/ioccheck/runtime"
	"github.com/cr4zygoat/ioccheck/ticlients"
)

type configuration struct {
	AlienVault struct {
		ApiKeys []string `json:"keys"`
	} `json:"alienvault"`
	Abuseip struct {
		ApiKeys []string `json:"keys"`
	} `json:"abuseip"`
}

func readConfiguration() (configuration, error) {
	config := configuration{}

	user, err := user.Current()
	if err != nil {
		return config, err
	}

	configfile := filepath.Join(user.HomeDir, ".config", "ioccheck.json")
	bytes, err := os.ReadFile(configfile)
	if err != nil {
		return config, err
	}

	err = json.Unmarshal(bytes, &config)
	if err != nil {
		return config, err
	}

	return config, nil
}

func main() {
	var pfilename *string = flag.String("f", "", "File with the IOCs")
	var pthreads *int = flag.Int("t", 3, "Number of threads per TI platform")
	flag.Parse()

	config, err := readConfiguration()
	if err != nil {
		log.Println(err)
	}

	var source io.Reader
	if *pfilename == "" {
		source = os.Stdin
	} else {
		source, err = os.Open(*pfilename)
		if err != nil {
			log.Fatalln(err)
		}
	}

	threads := *pthreads
	runner := runtime.NewRunner()
	runner.Clients.Threatfox = ticlients.NewThreatFoxClient(threads)
	runner.Clients.Malwarebazaar = ticlients.NewMalwareBazaarClient(threads)
	runner.Clients.Urlhaus = ticlients.NewUrlHausClient(threads)

	keys := config.AlienVault.ApiKeys
	if len(keys) > 0 {
		runner.Clients.Alienvault = ticlients.NewAlienVaultClient(keys, threads)
	}

	keys = config.Abuseip.ApiKeys
	if len(keys) > 0 {
		runner.Clients.Abuseip = ticlients.NewAbuseIPClient(keys, threads)
	}

	output := make(chan string)
	go runner.Run(source, output)

	for ioc := range output {
		fmt.Println(ioc)
	}
}
