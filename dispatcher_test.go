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
	"bytes"
	"net"
	"testing"
	"time"

	"github.com/sirupsen/logrus"

	netlist "github.com/IrineSistiana/net-list"

	"github.com/miekg/dns"
)

type vServer struct {
	latency time.Duration
	ip      net.IP
}

func (s *vServer) ServeDNS(w dns.ResponseWriter, q *dns.Msg) {

	name := q.Question[0].Name

	r := new(dns.Msg)
	r.SetReply(q)
	var rr dns.RR
	hdr := dns.RR_Header{
		Name:     name,
		Class:    dns.ClassINET,
		Ttl:      300,
		Rdlength: 0,
	}

	hdr.Rrtype = dns.TypeA

	rr = &dns.A{Hdr: hdr, A: s.ip}
	r.Answer = append(r.Answer, rr)

	time.Sleep(s.latency)
	w.WriteMsg(r)
}

func initTestDispatherAndServer(lLatency, rLatency time.Duration, lIP, rIP net.IP, allow, block string) (*dispatcher, func(), error) {
	c := Config{}

	//local
	localServerUDPConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		return nil, nil, err
	}
	c.LocalServerAddr = localServerUDPConn.LocalAddr().String()
	ls := dns.Server{PacketConn: localServerUDPConn, Handler: &vServer{ip: lIP, latency: lLatency}}
	go ls.ActivateAndServe()

	//remote
	remoteServerUDPConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		return nil, nil, err
	}
	c.RemoteServerAddr = remoteServerUDPConn.LocalAddr().String()
	rs := dns.Server{PacketConn: remoteServerUDPConn, Handler: &vServer{ip: rIP, latency: rLatency}}
	go rs.ActivateAndServe()

	c.BindAddr = "127.0.0.1:0"
	d, err := initDispather(&c, logrus.NewEntry(logrus.StandardLogger()))
	if err != nil {
		return nil, nil, err
	}

	allowedIP, err := netlist.NewListFromReader(bytes.NewReader([]byte(allow)))
	if err != nil {
		return nil, nil, err
	}
	d.localAllowedIPList = allowedIP

	blockedIP, err := netlist.NewListFromReader(bytes.NewReader([]byte(block)))
	if err != nil {
		return nil, nil, err
	}
	d.localBlockedIPList = blockedIP

	return d, func() {
		ls.Shutdown()
		rs.Shutdown()
	}, nil
}

func Test_dispatcher_ServeDNS_FastServer(t *testing.T) {
	logrus.SetLevel(logrus.DebugLevel)

	lIP := net.IPv4(1, 1, 1, 1)
	rIP := net.IPv4(1, 1, 1, 2)

	test := func(ll, rl time.Duration, want net.IP) {
		d, closeServer, err := initTestDispatherAndServer(ll, rl, lIP, rIP, "0.0.0.0/0", "")
		if err != nil {
			t.Fatalf("init dispather, %v", err)
		}
		defer closeServer()

		q := new(dns.Msg)
		q.SetQuestion(dns.Fqdn("example.com"), dns.TypeA)
		r := d.serveDNS(q)
		if r == nil || r.Rcode != dns.RcodeSuccess {
			t.Fatal("invalied r")
		}

		a := r.Answer[0].(*dns.A)
		if !a.A.Equal(want) {
			t.Fatal("not the server we want")
		}
	}

	//应该接受local的回复
	test(0, time.Second, lIP)

	//应该接受remote的回复
	test(time.Second, 0, rIP)
}

func Test_dispatcher_ServeDNS_AllowedIP(t *testing.T) {
	logrus.SetLevel(logrus.DebugLevel)

	allowedList := "0.0.0.0/1"

	lIPBlocked := net.IPv4(128, 1, 1, 1) // not allowed
	lIPAllowed := net.IPv4(127, 1, 1, 1) // allowed
	rIP := net.IPv4(1, 1, 1, 2)

	test := func(ll, rl time.Duration, lIP, want net.IP) {
		d, closeServer, err := initTestDispatherAndServer(ll, rl, lIP, rIP, allowedList, "")
		if err != nil {
			t.Fatalf("init dispather, %v", err)
		}
		defer closeServer()

		q := new(dns.Msg)
		q.SetQuestion(dns.Fqdn("example.com"), dns.TypeA)
		r := d.serveDNS(q)
		if r == nil || r.Rcode != dns.RcodeSuccess {
			t.Fatal("invalied r")
		}

		a := r.Answer[0].(*dns.A)
		if !a.A.Equal(want) {
			t.Fatal("not the server we want")
		}
	}

	//即使local延时更低，但结果被过滤，应该接受remote的回复
	test(0, time.Millisecond*500, lIPBlocked, rIP)
	//允许的IP, 接受
	test(0, time.Millisecond*500, lIPAllowed, lIPAllowed)
}

func Test_dispatcher_ServeDNS_BlockedIP(t *testing.T) {
	logrus.SetLevel(logrus.DebugLevel)

	allowedList := "0.0.0.0/0" // allow all
	blockedList := "128.0.0.0/1"

	lIPBlocked := net.IPv4(128, 1, 1, 1) // not allowed
	lIPAllowed := net.IPv4(127, 1, 1, 1) // allowed
	rIP := net.IPv4(1, 1, 1, 2)

	test := func(ll, rl time.Duration, lIP, want net.IP) {
		d, closeServer, err := initTestDispatherAndServer(ll, rl, lIP, rIP, allowedList, blockedList)
		if err != nil {
			t.Fatalf("init dispather, %v", err)
		}
		defer closeServer()

		q := new(dns.Msg)
		q.SetQuestion(dns.Fqdn("example.com"), dns.TypeA)
		r := d.serveDNS(q)
		if r == nil || r.Rcode != dns.RcodeSuccess {
			t.Fatal("invalied r")
		}

		a := r.Answer[0].(*dns.A)
		if !a.A.Equal(want) {
			t.Fatal("not the server we want")
		}
	}

	//即使local延时更低，但结果被过滤，应该接受remote的回复
	test(0, time.Millisecond*500, lIPBlocked, rIP)
	//允许的IP, 接受
	test(0, time.Millisecond*500, lIPAllowed, lIPAllowed)
}
