package util

import (
	"net"
	"net/url"
	"regexp"
)

const (
	regexDomain = "([A-Za-z0-9]|(?i:[a-z0-9])(?-i:[A-Z])|(?i:[A-Z])(?-i:[a-z])-?){1,63}(\\.[A-Za-z]{2,6})"
	regexMD5    = "[0-9A-Fa-f]{32}"
	regexSha1   = "[A-Fa-f0-9]{40}"
	regexSha256 = "[A-Fa-f0-9]{64}"
)

func String(ioc string) string {
	return string(ioc)
}

func IsIPv4(ioc string) bool {
	ip := net.ParseIP(ioc)
	return ip != nil && ip.To4() != nil
}

func IsIPv6(ioc string) bool {
	ip := net.ParseIP(ioc)
	return ip != nil && ip.To16() != nil
}

func IsIP(ioc string) bool {
	ip := net.ParseIP(ioc)
	return ip != nil
}

func IsUrl(ioc string) bool {
	u, _ := url.Parse(ioc)
	return u != nil && u.Scheme != "" && u.Hostname() != ""
}

func IsDomain(ioc string) bool {
	regex := regexp.MustCompile(regexDomain)
	return regex.MatchString(ioc)
}

func IsMD5Hash(ioc string) bool {
	regex := regexp.MustCompile(regexMD5)
	return regex.MatchString(ioc)
}

func IsSha1Hash(ioc string) bool {
	regex := regexp.MustCompile(regexSha1)
	return regex.MatchString(ioc)
}

func IsSha256Hash(ioc string) bool {
	regex := regexp.MustCompile(regexSha256)
	return regex.MatchString(ioc)
}

func IsHash(ioc string) bool {
	return IsMD5Hash(ioc) || IsSha1Hash(ioc) || IsSha256Hash(ioc)
}
