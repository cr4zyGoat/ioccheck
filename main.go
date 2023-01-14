package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"os"
	"sync"
)

const OTXBaseUrl string = "https://otx.alienvault.com"
const OTXAPIKEY string = "783d2b8e229641b987967614b8ebe9f7f6144db8326e2b231bf71080570fba9f"

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
		ApiKey:  OTXAPIKEY,
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
			}

			<-threads
			wg.Done()
		}(ioc)
	}

	wg.Wait()
}
