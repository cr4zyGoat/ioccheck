package runtime

import (
	"bufio"
	"io"
	"sync"

	"github.com/cr4zygoat/ioccheck/ticlients"
	"github.com/cr4zygoat/ioccheck/util"
)

type runner struct {
	Clients struct {
		Alienvault    *ticlients.AlienVaultClient
		Abuseip       *ticlients.AbuseIPClient
		Threatfox     *ticlients.ThreatFoxClient
		Malwarebazaar *ticlients.MalwareBazaarClient
		Urlhaus       *ticlients.UrlHausClient
	}
	uniques map[string]bool
}

func NewRunner() *runner {
	runner := new(runner)
	runner.uniques = make(map[string]bool)
	return runner
}

func (r *runner) checkIoC(ioc string) bool {
	switch {
	case util.IsIP(ioc):
		if r.Clients.Abuseip != nil && r.Clients.Abuseip.CheckIP(ioc) {
			return true
		}
	case util.IsUrl(ioc):
		if r.Clients.Urlhaus != nil && r.Clients.Urlhaus.CheckURL(ioc) {
			return true
		}
	case util.IsHash(ioc):
		if r.Clients.Malwarebazaar != nil && r.Clients.Malwarebazaar.CheckHash(ioc) {
			return true
		}
	}

	if r.Clients.Threatfox != nil && r.Clients.Threatfox.CheckIoC(ioc) {
		return true
	}
	if r.Clients.Alienvault != nil && r.Clients.Alienvault.CheckIOC(ioc) {
		return true
	}

	return false
}

func (r *runner) Run(input io.Reader, output chan string) {
	sc := bufio.NewScanner(input)
	wg := new(sync.WaitGroup)

	for sc.Scan() {
		ioc := sc.Text()
		if r.uniques[ioc] {
			continue
		}

		r.uniques[ioc] = true
		wg.Add(1)

		go func(ioc string) {
			if r.checkIoC(ioc) {
				output <- ioc
			}

			wg.Done()
		}(ioc)
	}

	wg.Wait()
	close(output)
}
