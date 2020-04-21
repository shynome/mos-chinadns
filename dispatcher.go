//     Copyright (C) 2020, IrineSistiana
//
//     This file is part of mos-chinadns.
//
//     mosdns is free software: you can redistribute it and/or modify
//     it under the terms of the GNU General Public License as published by
//     the Free Software Foundation, either version 3 of the License, or
//     (at your option) any later version.
//
//     mosdns is distributed in the hope that it will be useful,
//     but WITHOUT ANY WARRANTY; without even the implied warranty of
//     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//     GNU General Public License for more details.
//
//     You should have received a copy of the GNU General Public License
//     along with this program.  If not, see <https://www.gnu.org/licenses/>.

package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/IrineSistiana/mos-chinadns/domainlist"

	"github.com/IrineSistiana/mos-chinadns/dohclient"

	"github.com/miekg/dns"

	netlist "github.com/IrineSistiana/net-list"
	"github.com/sirupsen/logrus"
)

type upstream interface {
	Exchange(q *dns.Msg, requestLogger *logrus.Entry) (*dns.Msg, time.Duration, error)
}

type dispatcher struct {
	bindAddr                    string
	localServerBlockUnusualType bool
	remoteServerDelayStart      time.Duration

	localClient  upstream
	remoteClient upstream

	localAllowedIPList     *netlist.List
	localBlockedIPList     *netlist.List
	localAllowedDomainList *domainlist.List
	localFDLIsWhitelist    bool
	localBlockedDomainList *domainlist.List
	localECS               *dns.EDNS0_SUBNET
	remoteECS              *dns.EDNS0_SUBNET

	entry *logrus.Entry
}

const (
	queryTimeout = time.Second * 3
)

type upstreamTCPUDP struct {
	client dns.Client
	addr   string
}

func (u *upstreamTCPUDP) Exchange(q *dns.Msg, _ *logrus.Entry) (r *dns.Msg, rtt time.Duration, err error) {
	r, rtt, err = u.client.Exchange(q, u.addr)
	return
}

var (
	timerPool   = sync.Pool{}
	packBufPool = sync.Pool{}
)

func getTimer(t time.Duration) *time.Timer {
	timer, ok := timerPool.Get().(*time.Timer)
	if !ok {
		return time.NewTimer(t)
	}
	if timer.Reset(t) {
		panic("dispather.go getTimer: active timer trapped in timerPool")
	}
	return timer
}

func releaseTimer(timer *time.Timer) {
	if !timer.Stop() {
		select {
		case <-timer.C:
		default:
		}
	}
	timerPool.Put(timer)
}

func initDispather(conf *Config, entry *logrus.Entry) (*dispatcher, error) {
	d := new(dispatcher)
	d.entry = entry

	if len(conf.BindAddr) == 0 {
		return nil, errors.New("missing args: bind address")
	}
	d.bindAddr = conf.BindAddr

	if len(conf.LocalServerAddr) == 0 && len(conf.RemoteServerAddr) == 0 {
		return nil, errors.New("missing args: both local server and remote server are empty")
	}

	if len(conf.LocalServerAddr) != 0 {
		client, err := newClient(conf.LocalServerAddr, conf.LocalServerProtocol, conf.LocalServerURL, conf.LocalServerPEMCA)
		if err != nil {
			return nil, fmt.Errorf("init local server: %w", err)
		}
		d.localClient = client
		d.localServerBlockUnusualType = conf.LocalServerBlockUnusualType
	}

	if len(conf.RemoteServerAddr) != 0 {
		client, err := newClient(conf.RemoteServerAddr, conf.RemoteServerProtocol, conf.RemoteServerURL, conf.RemoteServerPEMCA)
		if err != nil {
			return nil, fmt.Errorf("init remote server: %w", err)
		}
		d.remoteClient = client
		d.remoteServerDelayStart = time.Millisecond * time.Duration(conf.RemoteServerDelayStart)
	}

	if len(conf.LocalAllowedIPList) != 0 {
		allowedIPList, err := netlist.NewListFromFile(conf.LocalAllowedIPList)
		if err != nil {
			return nil, fmt.Errorf("failed to load allowed ip file, %w", err)
		}
		d.entry.Infof("initDispather: LocalAllowedIPList length %d", allowedIPList.Len())
		d.localAllowedIPList = allowedIPList
	}

	if len(conf.LocalBlockedIPList) != 0 {
		blockIPList, err := netlist.NewListFromFile(conf.LocalBlockedIPList)
		if err != nil {
			return nil, fmt.Errorf("failed to load blocked ip file, %w", err)
		}
		d.entry.Infof("initDispather: LocalBlockedIPList length %d", blockIPList.Len())
		d.localBlockedIPList = blockIPList
	}

	if len(conf.LocalForcedDomainList) != 0 {
		dl, err := domainlist.LoadFormFile(conf.LocalForcedDomainList)
		if err != nil {
			return nil, fmt.Errorf("failed to load forced domain file, %w", err)
		}
		d.entry.Infof("initDispather: LocalForcedDomainList length %d", dl.Len())
		d.localAllowedDomainList = dl
		d.localFDLIsWhitelist = conf.LocalFDLIsWhitelist
	}

	if len(conf.LocalBlockedDomainList) != 0 {
		dl, err := domainlist.LoadFormFile(conf.LocalBlockedDomainList)
		if err != nil {
			return nil, fmt.Errorf("failed to load blocked domain file, %w", err)
		}
		d.entry.Infof("initDispather: LocalBlockedDomainList length %d", dl.Len())
		d.localBlockedDomainList = dl
	}

	if len(conf.LocalECSSubnet) != 0 {
		ecs, err := newEDNSSubnet(conf.LocalECSSubnet)
		if err != nil {
			return nil, fmt.Errorf("parsing local ECS subnet, %w", err)
		}
		d.localECS = ecs
		d.entry.Info("initDispather: local server ECS enabled")
	}

	if len(conf.RemoteECSSubnet) != 0 {
		ecs, err := newEDNSSubnet(conf.RemoteECSSubnet)
		if err != nil {
			return nil, fmt.Errorf("parsing remote ECS subnet, %w", err)
		}
		d.remoteECS = ecs
		d.entry.Info("initDispather: remote server ECS enabled")
	}

	return d, nil
}

func newEDNSSubnet(strECSSubnet string) (*dns.EDNS0_SUBNET, error) {
	strs := strings.SplitN(strECSSubnet, "/", 2)
	if len(strs) != 2 {
		return nil, fmt.Errorf("invalid ECS address [%s], not a CIDR notation", strECSSubnet)
	}

	ip := net.ParseIP(strs[0])
	if ip == nil {
		return nil, fmt.Errorf("invalid ECS address [%s], invalid ip", strECSSubnet)
	}
	sourceNetmask, err := strconv.Atoi(strs[1])
	if err != nil || sourceNetmask > 128 || sourceNetmask < 0 {
		return nil, fmt.Errorf("invalid ECS address [%s], invalid net mask", strECSSubnet)
	}

	ednsSubnet := new(dns.EDNS0_SUBNET)
	// edns family: https://www.iana.org/assignments/address-family-numbers/address-family-numbers.xhtml
	// ipv4 = 1
	// ipv6 = 2
	if ip4 := ip.To4(); ip4 != nil {
		ednsSubnet.Family = 1
		ednsSubnet.SourceNetmask = uint8(sourceNetmask)
		ip = ip4
	} else {
		if ip6 := ip.To16(); ip6 != nil {
			ednsSubnet.Family = 2
			ednsSubnet.SourceNetmask = uint8(sourceNetmask)
			ip = ip6
		} else {
			return nil, fmt.Errorf("invalid ECS address [%s], it's not an ipv4 or ipv6 address", strECSSubnet)
		}
	}

	ednsSubnet.Code = dns.EDNS0SUBNET
	ednsSubnet.Address = ip

	// SCOPE PREFIX-LENGTH, an unsigned octet representing the leftmost
	// number of significant bits of ADDRESS that the response covers.
	// In queries, it MUST be set to 0.
	// https://tools.ietf.org/html/rfc7871
	ednsSubnet.SourceScope = 0
	return ednsSubnet, nil
}

func (d *dispatcher) ListenAndServe(network string) error {
	server := &dns.Server{Addr: d.bindAddr, Net: network, Handler: d, UDPSize: 1480}
	return server.ListenAndServe()
}

// ServeDNS impliment the interface
func (d *dispatcher) ServeDNS(w dns.ResponseWriter, q *dns.Msg) {
	r := d.serveDNS(q)
	if r != nil {
		buf, _ := packBufPool.Get().([]byte)
		data, err := r.PackBuffer(buf)
		if err != nil {
			d.entry.Warnf("ServeDNS: PackBuffer: %v", err)
			return
		}

		_, err = w.Write(data)
		packBufPool.Put(data[:cap(data)])
		if err != nil {
			d.entry.Warnf("ServeDNS: Write: %v", err)
		}
	}
}

func isUnusualType(q *dns.Msg) bool {
	return q.Opcode != dns.OpcodeQuery || len(q.Question) != 1 || q.Question[0].Qclass != dns.ClassINET || (q.Question[0].Qtype != dns.TypeA && q.Question[0].Qtype != dns.TypeAAAA)
}

// check if q has a blocked QName. q and l can't be nil.
func inDomainList(q *dns.Msg, l *domainlist.List) bool {
	for i := range q.Question {
		if l.Has(q.Question[i].Name) {
			return true
		}
	}
	return false
}

func (d *dispatcher) hasRemote() bool {
	return d.remoteClient != nil
}

func (d *dispatcher) hasLocal() bool {
	return d.localClient != nil
}

// serveDNS: q can't be nil, r might be nil
func (d *dispatcher) serveDNS(q *dns.Msg) *dns.Msg {
	requestLogger := d.entry.WithFields(logrus.Fields{
		"id":       q.Id,
		"question": q.Question,
	})

	var localOnly, localBlocked bool
	if d.localAllowedDomainList != nil {
		if inDomainList(q, d.localAllowedDomainList) {
			localOnly = true
			requestLogger.Debug("serveDNS: is local domain")
		} else {
			if d.localFDLIsWhitelist {
				localBlocked = true
				requestLogger.Debug("serveDNS: block non local domain")
			}
		}
	}

	if d.localBlockedDomainList != nil && !localBlocked && inDomainList(q, d.localBlockedDomainList) {
		localBlocked = true
		requestLogger.Debug("serveDNS: local: is blocked domain")
	}

	var doLocal, doRemote bool
	if d.hasLocal() {
		switch {
		case localOnly:
			doLocal = true
		case localBlocked:
			doLocal = false
		case isUnusualType(q):
			doLocal = !d.localServerBlockUnusualType
		default:
			doLocal = true
		}
	} else {
		doLocal = false
	}

	if d.hasRemote() {
		switch {
		case localOnly:
			doRemote = false
		case localBlocked:
			doRemote = true
		default:
			doRemote = true
		}
	} else {
		doRemote = false
	}

	resChan := make(chan *dns.Msg, 1)
	wgChan := make(chan struct{}, 0)
	wg := sync.WaitGroup{}
	var localServerDone chan struct{}
	var localServerFailed chan struct{}

	// local
	if doLocal {
		localServerDone = make(chan struct{})
		localServerFailed = make(chan struct{})
		wg.Add(1)
		go func() {
			defer wg.Done()
			requestLogger.Debug("serveDNS: query local server")
			res, rtt, err := d.queryLocal(q, requestLogger)
			if err != nil {
				requestLogger.Warnf("serveDNS: local server failed: %v", err)
				close(localServerFailed)
				return
			}

			requestLogger.Debugf("serveDNS: get reply from local, rtt: %dms", rtt.Milliseconds())
			if !localOnly && d.dropLoaclRes(res, requestLogger) {
				requestLogger.Debug("serveDNS: local result droped")
				close(localServerFailed)
				return
			}

			select {
			case resChan <- res:
			default:
			}
			close(localServerDone)
			requestLogger.Debug("serveDNS: local result accepted")
		}()
	}

	// remote
	if doRemote {
		wg.Add(1)
		go func() {
			defer wg.Done()

			if doLocal && d.remoteServerDelayStart > 0 {
				timer := getTimer(d.remoteServerDelayStart)
				select {
				case <-localServerDone:
					releaseTimer(timer)
					return
				case <-localServerFailed:
				case <-timer.C:
				}
				releaseTimer(timer)
			}

			requestLogger.Debug("serveDNS: query remote server")
			res, rtt, err := d.queryRemote(q, requestLogger)
			if err != nil {
				requestLogger.Warnf("serveDNS: remote server failed: %v", err)
				return
			}
			requestLogger.Debugf("serveDNS: get reply from remote, rtt: %dms", rtt.Milliseconds())

			select {
			case resChan <- res:
			default:
			}
		}()
	}

	// watcher
	go func() {
		wg.Wait()
		close(wgChan)
	}()

	timeoutTimer := getTimer(queryTimeout)
	defer releaseTimer(timeoutTimer)

	select {
	case r := <-resChan:
		return r
	case <-wgChan:
		requestLogger.Warn("serveDNS: query failed: all servers failed")
		r := new(dns.Msg)
		r.SetReply(q)
		r.Rcode = dns.RcodeServerFailure
		return r
	case <-timeoutTimer.C:
		requestLogger.Warn("serveDNS: query failed: timeout")
		return nil
	}
}

func (d *dispatcher) queryLocal(q *dns.Msg, requestLogger *logrus.Entry) (*dns.Msg, time.Duration, error) {
	if d.localECS != nil {
		q = appendECSIfNotExist(q, d.localECS)
	}
	return d.localClient.Exchange(q, requestLogger)
}

//queryRemote WARNING: to save memory we may modify q directly.
func (d *dispatcher) queryRemote(q *dns.Msg, requestLogger *logrus.Entry) (*dns.Msg, time.Duration, error) {
	if d.remoteECS != nil {
		q = appendECSIfNotExist(q, d.remoteECS)
	}
	return d.remoteClient.Exchange(q, requestLogger)
}

// both q and ecs shouldn't be nil, the returned msg is a deep-copy if ecs is appended.
func appendECSIfNotExist(q *dns.Msg, ecs *dns.EDNS0_SUBNET) *dns.Msg {
	opt := q.IsEdns0()
	if opt == nil { // we need a new opt
		o := new(dns.OPT)
		o.SetUDPSize(4096) // TODO: is this big enough?
		o.Hdr.Name = "."
		o.Hdr.Rrtype = dns.TypeOPT
		o.Option = []dns.EDNS0{ecs}
		qCopy := q.Copy()
		qCopy.Extra = append(qCopy.Extra, o)
		return qCopy
	}

	hasECS := false // check if msg q already has a ECS section
	for o := range opt.Option {
		if opt.Option[o].Option() == dns.EDNS0SUBNET {
			hasECS = true
			break
		}
	}

	if !hasECS {
		qCopy := q.Copy()
		opt := qCopy.IsEdns0()
		opt.Option = append(opt.Option, ecs)
		return qCopy
	}

	return q
}

// check if local result should be droped, res can be nil.
func (d *dispatcher) dropLoaclRes(res *dns.Msg, requestLogger *logrus.Entry) bool {
	if res == nil {
		requestLogger.Debug("dropLoaclRes: true: result is nil")
		return true
	}

	if res.Rcode != dns.RcodeSuccess {
		requestLogger.Debugf("dropLoaclRes: true: Rcode=%s", dns.RcodeToString[res.Rcode])
		return true
	}

	if len(res.Answer) == 0 {
		requestLogger.Debug("dropLoaclRes: true: empty answer")
		return true
	}

	isUT := isUnusualType(res)
	if d.localServerBlockUnusualType && isUT {
		requestLogger.Debug("dropLoaclRes: true: unusual type")
		return true
	}

	if !isUT { // A and AAAA has IP
		if d.localBlockedIPList != nil && anwsersMatchNetList(res.Answer, d.localBlockedIPList, requestLogger) {
			requestLogger.Debug("dropLoaclRes: true: IP in blacklist")
			return true
		}

		if d.localAllowedIPList != nil {
			if anwsersMatchNetList(res.Answer, d.localAllowedIPList, requestLogger) {
				requestLogger.Debug("dropLoaclRes: false: IP in whitelist")
				return false
			}
			requestLogger.Debug("dropLoaclRes: true: IP not in whitelist")
			return true
		}
	}

	// no b/w list, don't drop
	requestLogger.Debug("dropLoaclRes: false: unusual type")
	return false
}

// list can not be nil
func anwsersMatchNetList(anwser []dns.RR, list *netlist.List, requestLogger *logrus.Entry) bool {
	var matched bool
	for i := range anwser {
		var ip netlist.IPv6
		var err error
		switch tmp := anwser[i].(type) {
		case *dns.A:
			ip, err = netlist.Conv(tmp.A)
		case *dns.AAAA:
			ip, err = netlist.Conv(tmp.AAAA)
		default:
			continue
		}
		if err != nil {
			continue
		}
		matched = true
		if list.Contains(ip) {
			return true
		}
	}
	if !matched {
		requestLogger.Debug("anwsersMatchNetList: no A/4A record")
	}
	return false
}

func caPath2Pool(ca string) (*x509.CertPool, error) {
	certPEMBlock, err := ioutil.ReadFile(ca)
	if err != nil {
		return nil, fmt.Errorf("ReadFile: %w", err)
	}

	cert, err := x509.ParseCertificate(certPEMBlock)
	if err != nil {
		return nil, fmt.Errorf("ParseCertificate: %w", err)
	}
	rootCAs := x509.NewCertPool()
	rootCAs.AddCert(cert)
	return rootCAs, nil
}

func newClient(addr, prot, url, ca string) (upstream, error) {
	var client upstream
	switch prot {
	case "tcp", "udp", "":
		client = &upstreamTCPUDP{
			client: dns.Client{
				Timeout:        queryTimeout,
				UDPSize:        1480,
				Net:            prot,
				SingleInflight: false,
			},
			addr: addr,
		}
	case "doh":
		var rootCA *x509.CertPool
		var err error
		if len(ca) != 0 {
			rootCA, err = caPath2Pool(ca)
			if err != nil {
				return nil, fmt.Errorf("caPath2Pool: %w", err)
			}
		}
		tlsConf := &tls.Config{
			// don't have to set servername here, fasthttp will do it itself.
			RootCAs:            rootCA,
			ClientSessionCache: tls.NewLRUClientSessionCache(64),
		}

		if len(url) == 0 {
			return nil, fmt.Errorf("protocol [%s] needs URL", prot)
		}
		client = dohclient.NewClient(url, addr, tlsConf, dns.MaxMsgSize, queryTimeout)
	default:
		return nil, fmt.Errorf("unsupport protocol: %s", prot)
	}

	return client, nil
}
