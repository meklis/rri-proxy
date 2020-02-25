package help

import "regexp"

func GetIpFromAddr(addr string) string {
	re, err := regexp.Compile(`^(.*):[0-9]{1,6}$`)
	if err != nil {
		return addr
	}
	ind := re.FindStringSubmatch(addr)
	if len(ind) > 1 {
		return ind[1]
	}
	return addr
}
func GetDefaultPortFromScheme(schema string) int {
	switch schema {
	case "ws":
		return 80
	case "wss":
		return 443
	case "http":
		return 80
	case "https":
		return 443
	}
	return 0
}
