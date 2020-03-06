package main

import (
	"crypto/tls"
	"fmt"
	"github.com/meklis/http-snmpwalk-proxy/logger"
	"github.com/meklis/rri-proxy/config"
	"github.com/meklis/rri-proxy/proxy"
	rri_lib "github.com/meklis/rri-proxy/rri"
	"net/http/pprof"
	"net/url"
	"time"

	"flag"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"log"
	"net/http"
)

var (
	Config     config.Configuration
	pathConfig string
	lg         *logger.Logger
)

func init() {
	flag.StringVar(&pathConfig, "c", "proxy.conf.yml", "Configuration file for proxy-auth module")
	flag.Parse()
}

func replaceHost(req *http.Request, replValue string) error {
	repl := req.Header.Get(Config.System.Proxy.WrapHostHeader)
	if replValue != "" {
		repl = replValue
	}
	if repl != "" {
		parsed, err := url.Parse(repl)
		if err != nil {
			return err
		}
		req.Host = parsed.Host
		req.URL = parsed
	}
	return nil
}

func main() {
	log.Println("Starting...")
	//Load configuration
	if err := config.LoadConfig(pathConfig, &Config); err != nil {
		panic(err)
	}
	//Configure logger from cronfiguration
	lg = config.ConfigureLogger(&Config)

	// Configure prometheus
	if Config.Prometheus.Enabled {
		rri_lib.PromEnabled = true
		rri_lib.PromRecalcEstabTimeout = Config.Prometheus.RecalcEstabConnsTimeout
		rri_lib.PromLiveRecalc = Config.Prometheus.LiveRecalc
		proxy.PromEnabled = true

		lg.NoticeF("Exporter for prometheus is enabled...")
		http.Handle(Config.Prometheus.Path, promhttp.Handler())
		go func() {
			err := http.ListenAndServe(fmt.Sprintf(":%v", Config.Prometheus.Port), nil)
			lg.CriticalF("Prometheus exporter critical err: %v", err)
			panic(err)
		}()
		lg.NoticeF("Prometheus exporter started on 0.0.0.0:%v%v", Config.Prometheus.Port, Config.Prometheus.Path)
	}

	//Configure pprof
	if Config.Profiler.Enabled {
		go func() {
			lg.NoticeF("Profiller is enabled, try start on port :%v", Config.Profiler.Port)
			r := http.NewServeMux()
			// Регистрация pprof-обработчиков
			r.HandleFunc(fmt.Sprintf("%v/", Config.Profiler.Path), pprof.Index)
			r.HandleFunc(fmt.Sprintf("%v/cmdline", Config.Profiler.Path), pprof.Cmdline)
			r.HandleFunc(fmt.Sprintf("%v/profile", Config.Profiler.Path), pprof.Profile)
			r.HandleFunc(fmt.Sprintf("%v/symbol", Config.Profiler.Path), pprof.Symbol)
			r.HandleFunc(fmt.Sprintf("%v/trace", Config.Profiler.Path), pprof.Trace)
			r.HandleFunc(fmt.Sprintf("%v/goru", Config.Profiler.Path), pprof.Trace)
			if err := http.ListenAndServe(fmt.Sprintf(":%v", Config.Profiler.Port), r); err != nil {
				panic(err)
			}
		}()
	}
	//Initialize RRI
	var rri *rri_lib.RRI
	if Config.System.RRI.Enabled == true {
		lg.InfoF("RRI enabled, starting...")
		rri = rri_lib.Init(Config.System.RRI.Interfaces, lg)
	} else {
		lg.InfoF("RRI disabled, added default interface = 0.0.0.0")
		rri = rri_lib.InitEmpty(lg)
	}

	// Initialize proxy server
	prx := proxy.Init(&Config, lg, rri)

	startHttpListener := func(listenPort int, replAddr string) {
		//Configure and start default listeners
		if Config.System.Listener.HTTP.Enabled {
			lg.NoticeF("HTTP listener enabled")
			server := getServer(prx, replAddr, listenPort)
			go func() {
				err := server.ListenAndServe()
				lg.CriticalF("Error start listener for HTTP on port :%v", listenPort)
				panic(err)
			}()
			time.Sleep(time.Second)
			lg.NoticeF("HTTP listener started on 0.0.0.0:%v", listenPort)
		} else {
			lg.Errorf("HTTP listener disabled, ignore listening on port :%v", listenPort)
		}
	}
	startHttpsListener := func(listenPort int, replAddr string) {
		//Configure and start HTTPS listener
		if Config.System.Listener.HTTPS.Enabled {
			lg.NoticeF("HTTPS/TLS listener enabled")
			server := getServer(prx, replAddr, listenPort)
			go func() {
				err := server.ListenAndServeTLS(Config.System.Listener.HTTPS.PemPath, Config.System.Listener.HTTPS.KeyPath)
				lg.CriticalF("Error start listener for HTTPS/TLS on port :%v", Config.System.Listener.HTTPS.Listen)
				panic(err)
			}()
			time.Sleep(time.Second)
			lg.NoticeF("HTTPS listener started on 0.0.0.0:%v", listenPort)
		} else {
			lg.Errorf("HTTPS listener disabled, ignore listening on port :%v", listenPort)
		}
	}

	//Start default listeners
	startHttpListener(Config.System.Listener.HTTP.Listen, "")
	startHttpsListener(Config.System.Listener.HTTPS.Listen, "")

	//Start extended listeners with host replacing
	for _, bind := range Config.System.Listener.Bindings {
		if bind.Schema == "http" {
			startHttpListener(bind.Port, bind.Addr)
		} else {
			startHttpsListener(bind.Port, bind.Addr)
		}
	}
	for {
		time.Sleep(time.Second)
	}
}

func getServer(prx *proxy.Proxy, replAddr string, listenPort int) *http.Server {
	return &http.Server{
		Addr: fmt.Sprintf(":%v", listenPort),
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			//Подменяем адрес, если есть заголовок
			if err := replaceHost(r, replAddr); err != nil {
				w.WriteHeader(400)
				w.Write([]byte(fmt.Sprintf("Incorrect header %v", Config.System.Listener.HTTP.Listen)))
				return
			}
			prx.Handle(w, r)
		}),
		// Disable HTTP/2.
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
		IdleTimeout:  Config.System.Listener.HTTPS.Timeout,
		WriteTimeout: Config.System.Listener.HTTPS.Timeout,
		ReadTimeout:  Config.System.Listener.HTTPS.Timeout,
	}
}
