package proxy

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"github.com/meklis/http-snmpwalk-proxy/logger"
	"github.com/meklis/rri-proxy/config"
	"github.com/meklis/rri-proxy/help"
	rri_lib "github.com/meklis/rri-proxy/rri"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

type (
	HandlingMethod int
)

const (
	PRX_TUNNEL HandlingMethod = iota
	PRX_HTTP
	PRX_WS
)

var (
	promHttpRequestsCount = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "rri_prx_proxy_request_count",
		Help: "The total number of http/https requests",
	}, []string{"code", "host", "uri", "message", "method", "addr"})
	promHttpRequestsDurationSec = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "rri_prx_proxy_request_sec",
		Help: "The total number of http/https requests",
	}, []string{"code", "host", "uri", "message", "method", "addr"})
	promSocketEstabConns = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "rri_prx_proxy_socket_estab_connections",
		Help: "The total number of established socket connections",
	}, []string{"host", "addr", "uri", "rri_interface"})
	promSocketRequestConnections = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "rri_prx_proxy_socket_requests",
		Help: "The total number of ws connections",
	}, []string{"host", "addr", "uri", "rri_interface"})
	promSocketRequestErrors = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "rri_prx_proxy_socket_requests_error",
		Help: "The total number of ws connections",
	}, []string{"host", "addr", "error", "uri", "rri_interface"})
	PromEnabled bool
)

type IdleTimeoutConn struct {
	Conn    net.Conn
	Timeout time.Duration
	Closed  bool
	sync.Mutex
}

func (self IdleTimeoutConn) Read(buf []byte) (int, error) {
	self.Conn.SetDeadline(time.Now().Add(self.Timeout))
	return self.Conn.Read(buf)
}

func (self IdleTimeoutConn) Write(buf []byte) (int, error) {
	self.Conn.SetDeadline(time.Now().Add(self.Timeout))
	return self.Conn.Write(buf)
}

func (self IdleTimeoutConn) IsClosed() bool {
	self.Lock()
	defer self.Unlock()
	return self.Closed
}
func (self IdleTimeoutConn) Close() error {
	self.Lock()
	defer self.Unlock()
	self.Closed = true
	return self.Conn.Close()
}

type Proxy struct {
	conf *config.Configuration
	lg   *logger.Logger
	rri  *rri_lib.RRI
}

type streamResponse struct {
	Status string
	Code   int
}

func Init(conf *config.Configuration, lg *logger.Logger, rri *rri_lib.RRI) *Proxy {
	prx := new(Proxy)
	prx.conf = conf
	prx.lg = lg
	prx.rri = rri
	lg.Debugf("Proxy instance initialized")
	return prx
}

func (p *Proxy) Handle(w http.ResponseWriter, r *http.Request) {
	var err error
	var code int
	var message string
	labels := make(map[string]string)
	if PromEnabled {
		labels = map[string]string{
			"code":    "-1",
			"message": "",
			"host":    r.Host,
			"uri":     r.URL.Path,
			"method":  r.Method,
			"addr":    help.GetIpFromAddr(r.RemoteAddr),
		}
	}
	started := time.Now().Nanosecond()
	getDurationSec := func() float64 {
		d := float64(time.Now().Nanosecond()-started) / 1000000000
		if d < 0 {
			return 0
		}
		return d
	}
	sendProm := func(code, message string) {
		if !PromEnabled {
			return
		}
		labels["code"] = code
		labels["message"] = message
		promHttpRequestsCount.With(labels).Inc()
		promHttpRequestsDurationSec.With(labels).Add(getDurationSec())
	}

	var iface *rri_lib.Interface
	p.dropRequestHeaders(r)
	if r.Method == http.MethodConnect {
		iface = p.rri.GetDialByRequests().IncRequests().IncEstab()
		p.lg.DebugF("Using tunneling for proccesing request (%v -> %v%v)", r.RemoteAddr, r.URL.Host, r.URL.Path)
		err, message, code = p.HandleTunneling(w, r, iface.Ip)
		if err != nil {
			sendProm(fmt.Sprintf("%v", code), fmt.Sprintf(err.Error()))
		} else {
			sendProm(fmt.Sprintf("%v", code), message)
		}
	} else if r.URL.Scheme == "ws" || r.URL.Scheme == "wss" {
		if p.conf.System.Proxy.Socket.RriByEstabConns {
			iface = p.rri.GetDialByConnections().IncRequests().IncEstab()
		} else {
			iface = p.rri.GetDialByRequests().IncRequests().IncEstab()
		}
		p.lg.DebugF("Using WS for proccesing request (%v -> %v%v)", r.RemoteAddr, r.URL.Host, r.URL.Path)
		p.HandleWS(w, r, iface.Ip)
	} else {
		iface = p.rri.GetDialByRequests().IncRequests().IncEstab()
		p.lg.DebugF("Using HTTP for proccesing request (%v -> %v%v)", r.RemoteAddr, r.URL.Host, r.URL.Path)
		err, message, code = p.HandleHTTP(w, r, iface.Ip)
		if err != nil {
			sendProm(fmt.Sprintf("%v", code), fmt.Sprintf(err.Error()))
		} else {
			sendProm(fmt.Sprintf("%v", code), message)
		}
	}
	iface.DecEstab()
	return
}
func (p *Proxy) HandleTunneling(w http.ResponseWriter, r *http.Request, ifaceIpAddr string) (err error, message string, code int) {
	if !strings.Contains(r.Host, ":") {
		r.Host = fmt.Sprintf("%v:%v", r.Host, help.GetDefaultPortFromScheme(r.URL.Scheme))
	}
	dial := net.Dialer{
		Timeout:  p.conf.System.Proxy.HTTP.ConnTimeout,
		Deadline: time.Time{},
		LocalAddr: &net.TCPAddr{
			IP: net.ParseIP(ifaceIpAddr),
		},
		FallbackDelay: 0,
		KeepAlive:     p.conf.System.Proxy.HTTP.ConnTimeout,
	}
	dest_conn, err := dial.Dial("tcp", r.Host)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		p.lg.WarningF("Dial %v to remote host %v returned err: %v", r.RemoteAddr, r.Host, err)
		return err, "", 503

	}
	w.WriteHeader(http.StatusOK)
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		p.lg.WarningF("Dial %v to to remote host %v returned err: Hijacking not supported", r.RemoteAddr, r.Host)
		return fmt.Errorf("Hijacking not supported"), "", 503

	}
	client_conn, _, err := hijacker.Hijack()

	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		p.lg.WarningF("Dial to client host %v returned err: %v", r.RemoteAddr, err)
		return err, "", 503
	}
	client := IdleTimeoutConn{
		Conn:    client_conn,
		Timeout: p.conf.System.Proxy.Socket.ConnTimeout,
	}
	dest := IdleTimeoutConn{
		Conn:    dest_conn,
		Timeout: p.conf.System.Proxy.Socket.ConnTimeout,
	}
	errc := make(chan error, 2)
	cp := func(dst io.Writer, src io.Reader) {
		_, err := io.Copy(dst, src)
		p.lg.Debugf("copy err (%v -> %v): %v", r.RemoteAddr, r.Host, err)
		errc <- err
	}
	go cp(dest, client)
	go cp(client, dest)
	<-errc
	p.lg.NoticeF("connection (%v -> %v) closed")
	return nil, "hijacking OK", 200
}
func (p *Proxy) HandleHTTP(w http.ResponseWriter, req *http.Request, ifaceIpAddr string) (err error, message string, code int) {
	redirectLimit := 0

REDIRECTED_REQUEST:
	p.lg.Debugf("new request - %v -> %v %v %v%v", req.RemoteAddr, req.Method, req.URL.Scheme, req.Host, req.URL.Path)
	var DefaultTransport http.RoundTripper = &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:  p.conf.System.Proxy.HTTP.Timeout,
			Deadline: time.Time{},
			LocalAddr: &net.TCPAddr{
				IP: net.ParseIP(ifaceIpAddr),
			},
			FallbackDelay: 0,
			KeepAlive:     p.conf.System.Proxy.HTTP.IdleTimeout,
		}).DialContext,
		//ForceAttemptHTTP2:     true,
		MaxIdleConns:          1000,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	redirectLimit++
	//req.URL, _ = url.Parse("https://api.huobi.pro/v1/account/accounts?AccessKeyId=cdddd33a-7f81d950-bvrge3rf7j-2370f&SignatureMethod=HmacSHA256&SignatureVersion=2&Timestamp=2020-03-04T14%3A43%3A44&Signature=Hh2Br4TupJ2Z7OzDzZq5SHDvy7iSGE4clLPE69ci%2FaM%3D")
	resp, err := DefaultTransport.RoundTrip(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		p.lg.WarningF("err: http response - %v %v%v -> %v - %v", req.Method, req.Host, req.URL.Path, req.RemoteAddr, err.Error())
		return err, "", 503
	}

	//Proxy Proccess redirects
	if p.conf.System.Proxy.HTTP.ProccessRedirects && (resp.StatusCode == 302 || resp.StatusCode == 301) {
		p.proccessRedirects(req, resp)
		if redirectLimit < 5 {
			goto REDIRECTED_REQUEST
		} else {
			p.lg.Errorf("[PROXY-HTTP] to many redirects to URL %v", resp.Header.Get("Location"))
		}
	}

	p.lg.Debugf("http response (%v %v%v -> %v): - %v %v", req.Method, req.Host, req.URL.Path, req.RemoteAddr, resp.StatusCode, resp.Status)
	defer resp.Body.Close()
	p.copyHeader(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
	return nil, fmt.Sprintf("%v", resp.Status), resp.StatusCode
}
func (p *Proxy) HandleWS(w http.ResponseWriter, r *http.Request, ifaceIpAddr string) {
	if !strings.Contains(r.Host, ":") {
		r.Host = fmt.Sprintf("%v:%v", r.Host, help.GetDefaultPortFromScheme(r.URL.Scheme))
	}
	labels := make(map[string]string)
	labels = map[string]string{
		"host":          r.Host,
		"addr":          help.GetIpFromAddr(r.RemoteAddr),
		"uri":           r.URL.Path,
		"rri_interface": ifaceIpAddr,
	}
	dialer := net.Dialer{
		Timeout:  p.conf.System.Proxy.HTTP.Timeout,
		Deadline: time.Time{},
		LocalAddr: &net.TCPAddr{
			IP: net.ParseIP(ifaceIpAddr),
		},
		FallbackDelay: 0,
		KeepAlive:     p.conf.System.Proxy.HTTP.IdleTimeout,
	}
	dial := func(address string) (net.Conn, error) {
		return dialer.Dial("tcp", address)
	}
	if r.URL.Scheme == "wss" {
		var tlsConfig *tls.Config
		tlsConfig = &tls.Config{
			InsecureSkipVerify: true,
		}
		dial = func(address string) (net.Conn, error) {
			return tls.DialWithDialer(&dialer, "tcp", address, tlsConfig)
		}
	}

	p.lg.Debugf("New socket connection (%v -> %v)", r.RemoteAddr, r.Host)
	d, err := dial(r.Host)
	if err != nil {
		if PromEnabled {
			labels["error"] = err.Error()
			promSocketRequestErrors.With(labels).Inc()
		}
		p.lg.WarningF("Error forwarding request (%v -> %v): %v", r.RemoteAddr, r.Host, err)
		http.Error(w, "Error forwarding request.", 500)
		if PromEnabled {
			promSocketRequestConnections.With(labels).Inc()
			labels["error"] = "Error forwarding request"
			promSocketRequestErrors.With(labels).Inc()
		}
		return
	}

	// All request generated by the http package implement this interface.
	hj, ok := w.(http.Hijacker)
	if !ok {
		if PromEnabled {
			labels["error"] = "Not hijacker"
			promSocketRequestErrors.With(labels).Inc()
		}
		p.lg.WarningF("Not a hijacker? (%v -> %v): %v", r.RemoteAddr, r.Host, err)
		http.Error(w, "Not a hijacker?", 500)
		if PromEnabled {
			promSocketRequestConnections.With(labels).Inc()
			labels["error"] = "Not a hijacker"
			promSocketRequestErrors.With(labels).Inc()
		}
		return
	}
	nc, _, err := hj.Hijack()
	if err != nil {
		if PromEnabled {
			labels["error"] = err.Error()
			promSocketRequestErrors.With(labels).Inc()
		}
		p.lg.WarningF("trying hijack err (%v -> %v): %v", r.RemoteAddr, r.Host, err)
		if PromEnabled {
			promSocketRequestConnections.With(labels).Inc()
			labels["error"] = "Trying hijack err"
			promSocketRequestErrors.With(labels).Inc()
		}
		return
	}
	defer nc.Close() // must close the underlying net connection after hijacking
	defer d.Close()

	// write the modified incoming request to the dialed connection
	err = r.Write(d)
	if err != nil {
		if PromEnabled {
			promSocketRequestConnections.With(labels).Inc()
			labels["error"] = "Error send modify header"
			promSocketRequestErrors.With(labels).Inc()
		}
		return
	}
	errc := make(chan error, 2)
	cpS := func(dst io.Writer, src io.Reader) {
		_, err := io.Copy(dst, src)
		errc <- err
	}
	cpD := func(dst io.Writer, src io.Reader) {
		if p.conf.System.Proxy.Socket.AnalizeStreamHeader {
			if code, status := p.analizeStream(dst, src); code != 0 {
				if code >= 400 {
					p.lg.Errorf("Error proccessed socket connection, incorrect response: %v", status)
					if PromEnabled {
						labelsErr := make(map[string]string)
						for k, v := range labels {
							labelsErr[k] = v
						}
						labelsErr["error"] = fmt.Sprintf("%v %v", code, status)
						promSocketRequestErrors.With(labelsErr).Inc()
					}
				}
				if code == 444 {
					errc <- fmt.Errorf(status)
					return
				}
			}
		}
		_, err := io.Copy(dst, src)
		errc <- err
	}
	if PromEnabled {
		promSocketEstabConns.With(labels).Inc()
	}
	go cpS(d, nc)
	go cpD(nc, d)
	<-errc
	if PromEnabled {
		promSocketEstabConns.With(labels).Dec()
		promSocketRequestConnections.With(labels).Inc()
	}
}
func (p *Proxy) copyHeader(dst, src http.Header) {
	mustDrop := func(headerName string) bool {
		for _, dropHeader := range p.conf.System.Proxy.HTTP.DropResponseHeaders {
			if headerName == dropHeader {
				p.lg.Debugf("Drop header %v from request", headerName)
				return true
			}
		}
		return false
	}
	for k, vv := range src {
		for _, v := range vv {
			if mustDrop(k) {
				continue
			}
			dst.Add(k, v)
		}
	}
}

func (p *Proxy) dropRequestHeaders(req *http.Request) {
	for _, drop := range p.conf.System.Proxy.HTTP.DropRequestHeaders {
		req.Header.Del(drop)
	}
}

func (p *Proxy) proccessRedirects(req *http.Request, resp *http.Response) {
	//Adding cookie to request
	p.lg.DebugF("[PROXY-HTTP] Proccess redirects enabled, wrap headers")
	if resp.Header.Get("Set-Cookie") != "" {
		p.lg.DebugF("[PROXY-HTTP] Found cookie %v", resp.Header.Get("Set-Cookie"))
		for _, cookie := range resp.Header.Values("Set-Cookie") {
			cElems := strings.Split(cookie, ";")
			if len(cElems) > 0 {
				req.Header.Add("Cookie", cElems[0])
			} else {
				p.lg.Errorf("Error parse cookie")
			}
		}
	}
	//Change URL from Location header
	if resp.Header.Get("Location") != "" {
		p.lg.DebugF("[PROXY-HTTP] Found header Location, try parse URL for redirect request to '%v'", resp.Header.Get("Location"))
		url, err := url.Parse(resp.Header.Get("Location"))
		if err != nil {
			p.lg.WarningF("[PROXY-HTTP] Error parse URL: '%v' for redirect", resp.Header.Get("Location"))
		} else {
			req.Host = url.Host
			req.URL = url
		}
	}
}

func (p *Proxy) analizeStream(dst io.Writer, src io.Reader) (int, string) {
	readBytes := make([]byte, 1)
	bytBuff := make([]byte, 1024)
	buffer := bytes.NewBuffer(bytBuff)
	code := 0
	status := ""
	for {
		if _, e := src.Read(readBytes); e != nil {
			code = 444
			status = "Connection Closed Without Response"
		}
		buffer.Write(readBytes)
		if _, e := dst.Write(readBytes); e != nil {
			code = 444
			status = "Connection Closed Without Response"
		}
		if line := buffer.String(); strings.Contains(line, "\n") && strings.Contains(line, "HTTP") {
			if c, s := help.ParseHttpResponseHeader(line); c != 0 {
				code = c
				status = s
			}
		}
		if code != 0 {
			return code, status
		}
	}
}
