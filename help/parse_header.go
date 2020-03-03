package help

import (
	"regexp"
	"strconv"
	"strings"
)

func ParseHttpResponseHeader(line string) (code int, status string) {
	start := strings.IndexByte(line, 'H')
	stop := strings.LastIndexByte(line, '\n')
	line = strings.TrimSpace(line[start:stop])
	regex, err := regexp.Compile(`^HTTP\/(.*?) ([0-9]{1,3}?) (.*)$`)
	if err != nil {
		panic(err)
	}
	matches := regex.FindStringSubmatch(line)
	if len(matches) == 3 {
		code, err = strconv.Atoi(matches[2])
		status = matches[2]
	} else if len(matches) == 4 {
		code, err = strconv.Atoi(matches[2])
		status = matches[3]
	} else {
		code = 0
		status = ""
	}
	return
}
