package main

import (
	"fmt"
	"os"
	"regexp"
	"sync"

	"net/http"

	"github.com/godbus/dbus"
	"github.com/godbus/dbus/introspect"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/common/promlog"
	"github.com/prometheus/common/promlog/flag"
	"github.com/prometheus/common/version"
	"gopkg.in/alecthomas/kingpin.v2"
)

type ipState struct {
	name  string
	state string
}

var (
	vrrp_states = map[string]string{
		"0":  "init",
		"1":  "backup",
		"2":  "master",
		"3":  "fault",
		"4":  "goto_master",
		"98": "goto_fault",
	}

	keepalivedUp = prometheus.NewDesc(prometheus.BuildFQName("keepalived", "", "up"), "Was the last scrape of keepalived successful.", nil, nil)
)

type Exporter struct {
	obj_path string
	mutex    sync.RWMutex

	up           prometheus.Gauge
	totalScrapes prometheus.Counter
	instances    *prometheus.GaugeVec
	changes      *prometheus.CounterVec
	logger       log.Logger
}

// NewExporter returns an initialized Exporter.
func NewExporter(obj_path string, logger log.Logger) (*Exporter, error) {
	return &Exporter{
		obj_path: obj_path,
		up: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Namespace: "keepalived",
				Name:      "up",
				Help:      "Was the last scrape of keepalived successful.",
			}),
		totalScrapes: prometheus.NewCounter(
			prometheus.CounterOpts{
				Namespace: "keepalived",
				Name:      "exporter_total_scrapes",
				Help:      "Current total Keepalived scrapes.",
			}),
		instances: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Namespace: "keepalived",
				Name:      "vrrp_instances",
				Help:      "The total number of VRRP instances",
			},
			[]string{"state", "vrid"}),
		changes: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "keepalived",
				Name:      "vrrp_state_changes",
				Help:      "The total number of VRRP state changes",
			},
			[]string{"state", "vrid"}),
		logger: logger,
	}, nil
}

func (e *Exporter) Describe(ch chan<- *prometheus.Desc) {
	ch <- keepalivedUp
	ch <- e.totalScrapes.Desc()
}

func (e *Exporter) Collect(ch chan<- prometheus.Metric) {
	e.mutex.Lock() // To protect metrics from concurrent collects.
	defer e.mutex.Unlock()

	up := e.scrape(ch)

	ch <- prometheus.MustNewConstMetric(keepalivedUp, prometheus.GaugeValue, up)
	ch <- e.totalScrapes
}

func (e *Exporter) scrape(ch chan<- prometheus.Metric) (up float64) {
	e.totalScrapes.Inc()

	conn, err := setupPrivateSystemBusConn()
	if err != nil {
		level.Error(e.logger).Log("msg", "Can't connect to Dbus", "err", err)
		return 0
	}
	interfaces, err := Interfaces(conn, e.obj_path)
	if err != nil {
		level.Error(e.logger).Log("msg", "Can't collect keepalived interfaces", "err", err)
		return 0
	}

	value_re := regexp.MustCompile(`\[([0-9]*),`)

	e.instances.Reset()
	for int := range interfaces {
		ips, err := Addresses(conn, int, e.obj_path)
		if err != nil {
			level.Error(e.logger).Log("msg", "Can't collect keepalived addresses", "err", err)
			return 0
		}
		for id := range ips {
			states, err := State(conn, int, id, e.obj_path)
			if err != nil {
				level.Error(e.logger).Log("msg", "Can't collect keepalived states", "err", err)
				return 0
			}
			for state := range states {
				state := value_re.FindStringSubmatch(state.state)
				state_str := vrrp_states[state[1]]
				e.instances.With(prometheus.Labels{"vrid": id, "state": state_str}).Set(1)

			}
		}
	}
	return 1
}

func setupPrivateSystemBusConn() (conn *dbus.Conn, err error) {
	conn, err = dbus.SystemBusPrivate()
	if err != nil {
		return nil, err
	}
	if err = conn.Auth(nil); err != nil {
		conn.Close()
		conn = nil
		return
	}
	if err = conn.Hello(); err != nil {
		conn.Close()
		conn = nil
	}
	return conn, nil // success
}

func (e *Exporter) listenSignal(conn *dbus.Conn) error {
	call := conn.BusObject().Call("org.freedesktop.DBus.AddMatch", 0, "eavesdrop='true',type='signal',sender='org.keepalived.Vrrp1',interface='org.keepalived.Vrrp1.Instance'")
	if call.Err != nil {
		fmt.Println("Failed to add match:", call.Err)
	} else {
		vrid_re := regexp.MustCompile(`^/org/.*/([0-9]*)/IPv4$`)
		state_re := regexp.MustCompile(`^\[([0-9]*)\]$`)
		c := make(chan *dbus.Signal, 10)
		conn.Signal(c)
		for sig := range c {
			state := vrrp_states[state_re.FindStringSubmatch(fmt.Sprintf("%v", sig.Body))[1]]
			vrid := vrid_re.FindStringSubmatch(string(sig.Path))[1]
			e.changes.With(prometheus.Labels{"vrid": vrid, "state": state}).Inc()
		}
	}
	return nil
}

func KAIntrospect(conn *dbus.Conn, path string, path_prefix string) (*introspect.Node, dbus.BusObject, error) {

	var path_suffix = dbus.ObjectPath(path)

	obj := conn.Object("org.keepalived.Vrrp1", dbus.ObjectPath(path_prefix)+path_suffix)
	node, err := introspect.Call(obj)
	if err != nil {
		fmt.Println(err)
		return nil, nil, err
	}
	return node, obj, err

}

func State(conn *dbus.Conn, int string, id string, path_prefix string) (<-chan ipState, error) {

	_, obj, err := KAIntrospect(conn, "Instance/"+int+"/"+id+"/IPv4", path_prefix)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}
	chnl := make(chan ipState)
	go func() {
		name, err := obj.GetProperty("org.keepalived.Vrrp1.Instance.Name")
		if err == nil {
			state, err := obj.GetProperty("org.keepalived.Vrrp1.Instance.State")
			if err == nil {
				chnl <- ipState{name.String(), state.String()}
			}
		} else {
			fmt.Println(err)
		}
		close(chnl)
	}()

	return chnl, nil

}

func Interfaces(conn *dbus.Conn, path_prefix string) (<-chan string, error) {

	node, _, err := KAIntrospect(conn, "Instance", path_prefix)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}
	chnl := make(chan string)
	go func() {
		for _, child := range node.Children {
			chnl <- child.Name
		}
		close(chnl)
	}()

	return chnl, nil

}

func Addresses(conn *dbus.Conn, int string, path_prefix string) (<-chan string, error) {

	node, _, err := KAIntrospect(conn, "Instance/"+int, path_prefix)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}

	chnl := make(chan string)
	go func() {
		for _, child := range node.Children {
			chnl <- child.Name
		}
		close(chnl)
	}()

	return chnl, nil

}

func main() {
	var (
		listenAddress      = kingpin.Flag("web.listen-address", "Address to listen on for web interface and telemetry.").Default(":9101").String()
		metricsPath        = kingpin.Flag("web.telemetry-path", "Path under which to expose metrics.").Default("/metrics").String()
		keepalivedDbusPath = kingpin.Flag("keepalived.dbus_prefix", "Keepalived dbus prefix").Default("/org/keepalived/Vrrp1/").String()
	)

	promlogConfig := &promlog.Config{}
	flag.AddFlags(kingpin.CommandLine, promlogConfig)
	kingpin.HelpFlag.Short('h')
	kingpin.Parse()
	logger := promlog.New(promlogConfig)

	level.Info(logger).Log("msg", "Starting keepalived_exporter", "version", version.Info())
	level.Info(logger).Log("msg", "Build context", "context", version.BuildContext())
	exporter, err := NewExporter(*keepalivedDbusPath, logger)

	go func() {
		conn, err := setupPrivateSystemBusConn()
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		exporter.listenSignal(conn)
	}()

	if err != nil {
		level.Error(logger).Log("msg", "Error creating an exporter", "err", err)
		os.Exit(1)
	}

	prometheus.MustRegister(exporter)
	prometheus.MustRegister(exporter.instances)
	prometheus.MustRegister(exporter.changes)

	prometheus.MustRegister(version.NewCollector("keepalived_exporter"))

	http.Handle(*metricsPath, promhttp.Handler())
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<html>
             <head><title>Keepalived Exporter</title></head>
             <body>
             <h1>Keepalived Exporter</h1>
             <p><a href='` + *metricsPath + `'>Metrics</a></p>
             </body>
             </html>`))
	})
	if err := http.ListenAndServe(*listenAddress, nil); err != nil {
		level.Error(logger).Log("msg", "Error starting HTTP server", "err", err)
		os.Exit(1)
	}
}
