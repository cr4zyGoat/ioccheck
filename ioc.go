package main

import (
	"log"
	"regexp"
)

const (
	REGEX_IPV4   = "((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])"
	REGEX_IPV6   = "((([0-9a-fA-F]){1,4})\\:){7}([0-9a-fA-F]){1,4}"
	REGEX_URL    = "http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+"
	REGEX_DOMAIN = "([A-Za-z0-9]|(?i:[a-z0-9])(?-i:[A-Z])|(?i:[A-Z])(?-i:[a-z])-?){1,63}(\\.[A-Za-z]{2,6})"
	REGEX_MD5    = "[0-9A-Fa-f]{32}"
	REGEX_SHA1   = "[A-Fa-f0-9]{40}"
	REGEX_SHA256 = "[A-Fa-f0-9]{64}"
)

var (
	ipv4Regex   *regexp.Regexp
	ipv6Regex   *regexp.Regexp
	urlRegex    *regexp.Regexp
	domainRegex *regexp.Regexp
	md5Regex    *regexp.Regexp
	sha1Regex   *regexp.Regexp
	sha256Regex *regexp.Regexp
)

type IOC string

func getIpv4Regex() *regexp.Regexp {
	if ipv4Regex == nil {
		re, err := regexp.Compile(REGEX_IPV4)
		if err != nil {
			log.Fatalln(err)
		}
		ipv4Regex = re
	}
	return ipv4Regex
}

func getIpv6Regex() *regexp.Regexp {
	if ipv6Regex == nil {
		re, err := regexp.Compile(REGEX_IPV6)
		if err != nil {
			log.Fatalln(err)
		}
		ipv6Regex = re
	}
	return ipv6Regex
}

func getUrlRegex() *regexp.Regexp {
	if urlRegex == nil {
		re, err := regexp.Compile(REGEX_URL)
		if err != nil {
			log.Fatalln(err)
		}
		urlRegex = re
	}
	return urlRegex
}

func getDomainRegex() *regexp.Regexp {
	if domainRegex == nil {
		re, err := regexp.Compile(REGEX_DOMAIN)
		if err != nil {
			log.Fatalln(err)
		}
		domainRegex = re
	}
	return domainRegex
}

func getMD5Regex() *regexp.Regexp {
	if md5Regex == nil {
		re, err := regexp.Compile(REGEX_MD5)
		if err != nil {
			log.Fatalln(err)
		}
		md5Regex = re
	}
	return md5Regex
}

func getSHA1Regex() *regexp.Regexp {
	if sha1Regex == nil {
		re, err := regexp.Compile(REGEX_SHA1)
		if err != nil {
			log.Fatalln(err)
		}
		sha1Regex = re
	}
	return sha1Regex
}

func getSHA256Regex() *regexp.Regexp {
	if sha256Regex == nil {
		re, err := regexp.Compile(REGEX_SHA256)
		if err != nil {
			log.Fatalln(err)
		}
		sha256Regex = re
	}
	return sha256Regex
}

func (ioc IOC) IsIPv4() bool {
	checker := getIpv4Regex()
	return checker.MatchString(string(ioc))
}

func (ioc IOC) IsIPv6() bool {
	checker := getIpv6Regex()
	return checker.MatchString(string(ioc))
}

func (ioc IOC) IsIP() bool {
	return ioc.IsIPv4() || ioc.IsIPv6()
}

func (ioc IOC) IsURL() bool {
	checker := getUrlRegex()
	return checker.MatchString(string(ioc))
}

func (ioc IOC) IsDomain() bool {
	checker := getDomainRegex()
	return checker.MatchString(string(ioc))
}

func (ioc IOC) IsMD5Hash() bool {
	checker := getMD5Regex()
	return checker.MatchString(string(ioc))
}

func (ioc IOC) IsSHA1Hash() bool {
	checker := getSHA1Regex()
	return checker.MatchString(string(ioc))
}

func (ioc IOC) IsSHA256Hash() bool {
	checker := getSHA256Regex()
	return checker.MatchString(string(ioc))
}

func (ioc IOC) IsHash() bool {
	return ioc.IsMD5Hash() || ioc.IsSHA1Hash() || ioc.IsSHA256Hash()
}
