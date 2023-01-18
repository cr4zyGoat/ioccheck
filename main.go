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

type Configuration struct {
	AlienVaultApiKey string
	AbuseIPDBApiKey  string
}

func ReadConfiguration() Configuration {
	user, err := user.Current()
	if err != nil {
		log.Fatalln(err)
	}

	configfile := filepath.Join(user.HomeDir, ".config", "ioccheck.json")
	pfile, err := os.Open(configfile)
	if err != nil {
		log.Fatalln(err)
	}

	defer pfile.Close()
	var config Configuration
	decoder := json.NewDecoder(pfile)
	err = decoder.Decode(&config)
	if err != nil {
		log.Fatalln(err)
	}

	return config
}

func main() {
	var pfilename *string = flag.String("f", "", "File with the IOCs")
	var pthreads *int = flag.Int("t", 5, "Number of threads")
	flag.Parse()

	var config Configuration = ReadConfiguration()

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

	otxclient := OTXClient{
		ApiKey: config.AlienVaultApiKey,
	}

	abuseipclient := AbuseIPClient{
		ApiKey: config.AbuseIPDBApiKey,
	}

	urlhausclient := URLHausClient{}

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

			if otxclient.CheckIOC(ioc) {
				fmt.Println(ioc)
			} else if ioc.IsIP() && abuseipclient.CheckIOC(ioc) {
				fmt.Println(ioc)
			} else if ioc.IsURL() && urlhausclient.CheckIOC(ioc) {
				fmt.Println(ioc)
			}

			<-threads
			wg.Done()
		}(ioc)
	}

	wg.Wait()
}
