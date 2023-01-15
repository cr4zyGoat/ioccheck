package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"os"
	"sync"
)

const (
	OTXBaseUrl     string = "https://otx.alienvault.com"
	OTXApiKey      string = "783d2b8e229641b987967614b8ebe9f7f6144db8326e2b231bf71080570fba9f"
	AbuseIPBaseUrl string = "https://api.abuseipdb.com"
	AbuseIPApiKey  string = "626a68b6b1ac24f0ca93aa7cc4116ae995238401b3084fc2baf824ab0233ff599ad11f6eaa7e11fc"
)

func main() {
	var pfilename *string = flag.String("f", "", "File with the IOCs")
	var pthreads *int = flag.Int("t", 5, "Number of threads")
	flag.Parse()

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
		BaseURL: OTXBaseUrl,
		ApiKey:  OTXApiKey,
	}

	abuseipclient := AbuseIPClient{
		BaseURL: AbuseIPBaseUrl,
		ApiKey:  AbuseIPApiKey,
	}

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
			}

			<-threads
			wg.Done()
		}(ioc)
	}

	wg.Wait()
}
