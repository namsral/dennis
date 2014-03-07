// Copyright 2014 Lars Wiegman. All rights reserved.
// Based on code from Miek Gieben.

package main

import (
	"code.google.com/p/gcfg"
	"flag"
	"fmt"
	"github.com/garyburd/redigo/redis"
	"github.com/miekg/dns"
	"github.com/satori/go.uuid"
	"log"
	"net"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"
	"crypto/sha1"
)

var (
	printf     *bool
	compress   *bool
	tsig       *string
	configFile *string
	cfg        Config
)

// Setup a connection pool for Redis
var pool = &redis.Pool{
	MaxIdle:     3,
	IdleTimeout: 240 * time.Second,
	Dial: func() (redis.Conn, error) {
		c, err := redis.Dial("tcp", cfg.Main.Redis_addr)
		if err != nil {
			return nil, err
		}
		return c, err
	},
	TestOnBorrow: func(c redis.Conn, t time.Time) error {
		_, err := c.Do("PING")
		return err
	},
}

type Config struct {
	Main struct {
		Bind_addr   string
		Redis_addr  string
		Dnsfwd_addr string
		Logfile     string
		Portal_addr string
	}
}


func Shasum(s string) string {
    h := sha1.New()
    h.Write([]byte(s))
    return fmt.Sprintf("%x", h.Sum(nil))
}


func GetRootDomain(s string) string {
	labels := dns.SplitDomainName(s)
	if len(labels) < 2 {
		return s
	}
	root := dns.Fqdn(strings.Join([]string{labels[len(labels)-2], labels[len(labels)-1]}, "."))
	return root
}

func GetUserByIP(ip net.IP) (user_id string, ok bool) {
	// Retrieve user_id by IP address
	// GET gateway:<hash ip>

	// Get a connection from the Redis pool
	conn := pool.Get()
	defer conn.Close()

	//
	// u5oid, err := uuid.NewV5(uuid.NamespaceOID, []byte(ip.String()))
	u5oid := uuid.NewV5(uuid.NamespaceOID, ip.String())

	// Talk to Redis
	key := fmt.Sprintf("gateway:%s", u5oid)
	value, err := redis.String(conn.Do("GET", key))
	if err != nil {
		return "", false
	}

	return value, true
}

func GetProxyByUserAndDomain(user_id, domain string) (ip net.IP, ok bool) {
	// Retrieve proxy_ip by user_id and domain
	// GET user:<user_id>:domain:<domain>
	//
	// Domain should be in final dot notation, example: google.com.

	// Get a connection from the Redis pool
	conn := pool.Get()
	defer conn.Close()

	// Talk to Redis
	key := fmt.Sprintf("user:%s:domain:%s", user_id, domain)
	value, err := redis.String(conn.Do("GET", key))
	if err != nil {
		return []byte{0, 0, 0, 0}, false
	}

	ip = net.ParseIP(value)
	return ip, true

}

func handleAll(w dns.ResponseWriter, r *dns.Msg) {
	var (
		// v4 bool
		rr      dns.RR
		a       net.IP
		user_id string
		proxy   net.IP
		ok      bool
		ReqID   string
	)
	// TC must be done here
	m := new(dns.Msg)
	m.SetReply(r)
	m.Compress = *compress

	// Extract IP from either TCP of UDP
	if ip, ok := w.RemoteAddr().(*net.UDPAddr); ok {
		a = ip.IP
		// v4 = a.To4() != nil
	}
	if ip, ok := w.RemoteAddr().(*net.TCPAddr); ok {
		a = ip.IP
		// v4 = a.To4() != nil
	}

	// FIXME: respond with a fail when request comes from IPv6
	// if !v4 {
	//
	// }

	qname := r.Question[0].Name

	// Set a Request ID to identify the request in the logs
	ReqID = Shasum(fmt.Sprintf("%s%d", a.String(), time.Now().UTC().UnixNano()))[:8]
	log.Printf("%s %s Incomming request for domain %s\n", ReqID, a.String(), qname)

	// Check if IP is registered
	if user_id, ok = GetUserByIP(a); !ok {

		// Respond with Hotel Redirect
		log.Printf("%s %s WARNING Not registered\n", ReqID, a.String())

		rr = new(dns.A)
		rr.(*dns.A).Hdr = dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 0}
		rr.(*dns.A).A = net.ParseIP(cfg.Main.Portal_addr)
		m.Answer = append(m.Answer, rr)

		w.WriteMsg(m)
		return
	}

	// Retreive user defined proxy for domain
	qnameRoot := GetRootDomain(qname)
	proxy, ok = GetProxyByUserAndDomain(user_id, qnameRoot)

	// Forward if proxy wasn't set or set to 0.0.0.0 (local)
	unasigned := []byte{0, 0, 0, 0}
	if !ok || proxy.Equal(unasigned) {
		// Forward request to recursive nameserver
		log.Printf("%s %s Forward request for domain \"%s\"\n", ReqID, a.String(), r.Question[0].Name)

		m := new(dns.Msg)
		m.SetReply(r)
		m.Compress = *compress
		in, err := dns.Exchange(r, cfg.Main.Dnsfwd_addr)
		if err != nil {
			m.SetRcode(r, dns.RcodeServerFailure)
		} else {
			for _, a := range in.Answer {
				m.Answer = append(m.Answer, a)
			}
		}

		w.WriteMsg(m)
		return
	}

	// Reply with an Answer
	rr = new(dns.A)
	rr.(*dns.A).Hdr = dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 0}
	rr.(*dns.A).A = proxy
	m.Answer = append(m.Answer, rr)

	if *printf {
		log.Printf("%v\n", m.String())
	}

	log.Printf("%s %s INFO A > %s\n", ReqID, a.String(), proxy)

	w.WriteMsg(m)
	return
}

func serve(net, name, secret string) {
	switch name {
	case "":
		err := dns.ListenAndServe(cfg.Main.Bind_addr, net, nil)
		if err != nil {
			log.Printf("Failed to setup the "+net+" server: %s\n", err.Error())
		}
	default:
		server := &dns.Server{Addr: cfg.Main.Bind_addr, Net: net, TsigSecret: map[string]string{name: secret}}
		err := server.ListenAndServe()
		if err != nil {
			log.Printf("Failed to setup the "+net+" server: %s\n", err.Error())
		}
	}
}

func main() {
	runtime.GOMAXPROCS(runtime.NumCPU() * 4)

	printf = flag.Bool("print", false, "print replies")
	compress = flag.Bool("compress", false, "compress replies")
	tsig = flag.String("tsig", "", "use MD5 hmac tsig: keyname:base64")
	configFile = flag.String("config", "/etc/godns/godns.conf", "alternative configuration file")

	var name, secret string
	flag.Usage = func() {
		flag.PrintDefaults()
	}
	flag.Parse()

	// Setup file logging
	if len(cfg.Main.Logfile) > 0 {
		f, err := os.OpenFile(cfg.Main.Logfile, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0640)
		if err != nil {
			log.Fatalf("Error opening file: %v", err)
		}
		defer f.Close()
		log.SetOutput(f)
	}

	// Tsig
	if *tsig != "" {
		a := strings.SplitN(*tsig, ":", 2)
		name, secret = dns.Fqdn(a[0]), a[1] // fqdn the name, which everybody forgets...
	}

	// Parse configuration file
	if err := gcfg.ReadFileInto(&cfg, *configFile); err != nil {
		log.Fatal("Failed to parse configuration file ", *configFile)
		// panic(err)
	}

	// Setup Log file
	if len(cfg.Main.Logfile) > 0 {
		f, err := os.OpenFile(cfg.Main.Logfile, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0640)
		if err != nil {
			log.Fatalf("Error opening file: %v", err)
		}
		defer f.Close()
		log.SetOutput(f)
	}

	// DNS
	dns.HandleFunc(".", handleAll)

	go serve("tcp", name, secret)
	go serve("udp", name, secret)
	log.Printf("* Running on %s\n", cfg.Main.Bind_addr)
	sig := make(chan os.Signal)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
forever:
	for {
		select {
		case s := <-sig:
			fmt.Printf("Signal (%d) received, stopping\n", s)
			break forever
		}
	}
}
