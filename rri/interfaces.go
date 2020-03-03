package rri

import (
	"github.com/meklis/http-snmpwalk-proxy/logger"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"net"
	"sort"
	"sync"
	"time"
)

type RRI struct {
	lg         *logger.Logger
	interfaces []*Interface
	sync.Mutex
	lastIpByEstab string
}

var PromEnabled bool
var PromRecalcEstabTimeout time.Duration
var PromLiveRecalc bool

type Interface struct {
	Requests         int
	EstabConnections int
	Ip               string
	sync.Mutex
}

func (i *Interface) IncEstab() *Interface {
	i.Lock()
	defer i.Unlock()
	if PromEnabled && PromLiveRecalc {
		promEstabConns.With(map[string]string{
			"addr": i.Ip,
		}).Inc()
	}
	i.EstabConnections++
	return i
}
func (i *Interface) IncRequests() *Interface {
	i.Lock()
	defer i.Unlock()
	if PromEnabled {
		promRequests.With(map[string]string{
			"addr": i.Ip,
		}).Inc()
	}
	i.Requests++
	return i
}

func (i *Interface) DecEstab() *Interface {
	i.Lock()
	defer i.Unlock()
	if PromEnabled && PromLiveRecalc {
		promEstabConns.With(map[string]string{
			"addr": i.Ip,
		}).Dec()
	}
	i.EstabConnections--
	return i
}

var (
	promRequests = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "rri_prx_interface_requests",
		Help: "The total number of http/https/ws requests on interface",
	}, []string{"addr"})
	promEstabConns = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "rri_prx_interface_estab_conns",
		Help: "The total number of established socket connections",
	}, []string{"addr"})
)

func Init(interfaceIps []string, lg *logger.Logger) *RRI {
	rri := new(RRI)
	lg = lg
	rri.interfaces = make([]*Interface, 0)
	for _, iefIp := range interfaceIps {
		if ValidateIp(iefIp) {
			iface := Interface{
				Requests:         0,
				EstabConnections: 0,
				Ip:               iefIp,
			}
			rri.interfaces = append(rri.interfaces, &iface)
			lg.NoticeF("[RRI] added ip %v to pool of round robin interfaces", iefIp)
		} else {
			lg.ErrorF("[RRI] ip %v not found in interfaces", iefIp)
		}
	}
	go rri.recalcProm(lg)
	return rri
}

func (r *RRI) recalcProm(lg *logger.Logger) {
	for {
		if PromLiveRecalc {
			return
		}
		lg.Debugf("[RRI] recalc prom estab conns")
		estabs := make(map[string]int)
		r.Lock()
		for _, f := range r.interfaces {
			estabs[f.Ip] = f.EstabConnections
		}
		r.Unlock()

		for ip, count := range estabs {
			promEstabConns.With(map[string]string{
				"addr": ip,
			}).Set(float64(count))
		}
		time.Sleep(PromRecalcEstabTimeout)
	}
}

func InitEmpty(lg *logger.Logger) *RRI {
	rri := new(RRI)
	lg = lg
	rri.interfaces = make([]*Interface, 0)
	go rri.recalcProm(lg)
	return rri
}

func (r *RRI) GetDialByRequests() *Interface {
	r.Lock()
	defer r.Unlock()
	sort.Slice(r.interfaces, func(i, j int) bool {
		return r.interfaces[i].Requests < r.interfaces[j].Requests
	})
	return r.interfaces[0]
}

func (r *RRI) GetDialByConnections() *Interface {
	r.Lock()
	defer r.Unlock()
	//Sort by requests
	sort.Slice(r.interfaces, func(i, j int) bool {
		return r.interfaces[i].Requests < r.interfaces[j].Requests
	})
	//Sort by connections
	sort.Slice(r.interfaces, func(i, j int) bool {
		return r.interfaces[i].EstabConnections < r.interfaces[j].EstabConnections
	})
	return r.interfaces[0]
}

func ValidateIp(IP string) bool {
	interfaces, _ := net.Interfaces()
	for _, ief := range interfaces {
		addrs, _ := ief.Addrs()
		for _, a := range addrs {
			if a.(*net.IPNet).IP.String() == IP {
				return true
			}
		}
	}
	return false
}
