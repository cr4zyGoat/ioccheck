package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/user"
	"path/filepath"
	"sync"
)

type configuration struct {
	AlienVault struct {
		ApiKeys []string `json:"keys"`
	} `json:"alienvault"`
	Abuseip struct {
		ApiKeys []string `json:"keys"`
	} `json:"abuseip"`
}

var (
	alienvaultclient    AlienVaultClient
	abuseipclient       AbuseIPClient
	malwarebazaarclient MalwareBazaarClient
	urlhausclient       URLHausClient
)

func readConfiguration() configuration {
	user, err := user.Current()
	if err != nil {
		log.Fatalln(err)
	}

	configfile := filepath.Join(user.HomeDir, ".config", "ioccheck.json")
	bytes, err := os.ReadFile(configfile)
	if err != nil {
		log.Fatalln(err)
	}

	var config configuration
	err = json.Unmarshal(bytes, &config)
	if err != nil {
		log.Fatalln(err)
	}

	return config
}

func checkIOC(ioc IOC) bool {
	if alienvaultclient.CheckIOC(ioc) {
		return true
	} else if ioc.IsIP() && abuseipclient.CheckIP(ioc) {
		return true
	} else if ioc.IsURL() && urlhausclient.CheckURL(ioc) {
		return true
	} else if ioc.IsHash() && malwarebazaarclient.CheckHash(ioc) {
		return true
	}

	return false
}

func main() {
	var pfilename *string = flag.String("f", "", "File with the IOCs")
	var pthreads *int = flag.Int("t", 10, "Number of threads")
	flag.Parse()

	var config configuration = readConfiguration()

	var sc *bufio.Scanner
	if *pfilename == "" {
		sc = bufio.NewScanner(os.Stdin)
	} else {
		pfile, err := os.Open(*pfilename)
		if err != nil {
			log.Fatalln(err)
		}

		sc = bufio.NewScanner(pfile)
	}

	alienvaultclient = AlienVaultClient{apiKeys: config.AlienVault.ApiKeys}
	abuseipclient = AbuseIPClient{apiKeys: config.Abuseip.ApiKeys}
	malwarebazaarclient = MalwareBazaarClient{}
	urlhausclient = URLHausClient{}

	wg := new(sync.WaitGroup)
	threads := make(chan bool, *pthreads)
	uniques := make(map[string]bool)

	for sc.Scan() {
		sioc := sc.Text()
		if uniques[sioc] {
			continue
		}

		uniques[sioc] = true
		ioc := IOC(sioc)
		wg.Add(1)

		go func(ioc IOC) {
			threads <- true

			if checkIOC(ioc) {
				fmt.Println(ioc)
			}

			<-threads
			wg.Done()
		}(ioc)
	}

	wg.Wait()
}
