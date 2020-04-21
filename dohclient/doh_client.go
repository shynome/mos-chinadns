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

package dohclient

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"

	"github.com/sirupsen/logrus"

	"github.com/miekg/dns"

	"github.com/valyala/fasthttp"
)

// err
var (
	ErrNoResult = errors.New("unexpected nil result")
)

type DoHClient struct {
	preparedURL []byte
	timeout     time.Duration

	// why using pointer: uint64 atomic value inside HostClient.
	// avoids 32-bit system encountering "invalid memory address" panic
	fasthttpClient *fasthttp.HostClient

	group singleflight.Group
}

// NewClient returns a doh client
func NewClient(url, addr string, tlsConfig *tls.Config, maxSize int, timeout time.Duration) *DoHClient {
	// for ease to use, overwrite maxSize.
	switch {
	case maxSize > dns.MaxMsgSize:
		maxSize = dns.MaxMsgSize
	case maxSize < dns.MinMsgSize:
		maxSize = dns.MinMsgSize
	}

	u := fasthttp.URI{}
	u.Update(url)
	host := string(u.Host())
	if len(host) == 0 {
		host = addr
	}

	c := &DoHClient{
		preparedURL: []byte(url + "?dns="),
		timeout:     timeout,
		fasthttpClient: &fasthttp.HostClient{
			Addr: host,
			Dial: func(_ string) (net.Conn, error) {
				d := net.Dialer{Timeout: timeout}
				return d.Dial("tcp", addr)
			},
			IsTLS:                         true,
			TLSConfig:                     tlsConfig,
			ReadTimeout:                   timeout,
			WriteTimeout:                  timeout,
			MaxResponseBodySize:           maxSize,
			DisableHeaderNamesNormalizing: true,
			DisablePathNormalizing:        true,
			NoDefaultUserAgentHeader:      true,
		},
	}
	return c
}

// some consistent string vars
var (
	headerCanonicalKeyAccept = []byte("Accept")
	headerValueMediaType     = []byte("application/dns-message")
)

// buf pool for dns.pack only
var packBufPool = &sync.Pool{}

var bytesBufPool = sync.Pool{
	New: func() interface{} {
		return &bytes.Buffer{}
	},
}

func (c *DoHClient) Exchange(q *dns.Msg, requestLogger *logrus.Entry) (*dns.Msg, time.Duration, error) {
	t := time.Now()
	r, err := c.exchange(q, requestLogger)
	return r, time.Since(t), err
}

func (c *DoHClient) exchange(q *dns.Msg, requestLogger *logrus.Entry) (*dns.Msg, error) {

	// In order to maximize HTTP cache friendliness, DoH clients using media
	// formats that include the ID field from the DNS message header, such
	// as "application/dns-message", SHOULD use a DNS ID of 0 in every DNS
	// request.
	// https://tools.ietf.org/html/rfc8484 4.1

	qCopy := *q // just shadow copy, we only need to change q.Id
	qCopy.Id = 0

	buf, _ := packBufPool.Get().([]byte)
	wireMsg, err := qCopy.PackBuffer(buf)

	if err != nil {
		return nil, fmt.Errorf("PackBuffer: %w", err)
	}
	defer packBufPool.Put(wireMsg[:cap(wireMsg)])

	payload := string(wireMsg)
	vr, err, shared := c.group.Do(payload, func() (interface{}, error) {
		defer c.group.Forget(payload)
		return c.doFasthttp(wireMsg, requestLogger)
	})

	if err != nil {
		return nil, fmt.Errorf("group.Do doFasthttp: %w", err)
	}
	r := vr.(*dns.Msg)
	// change r.Id back
	if shared {
		requestLogger.Debug("Exchange: shared payload detected")
		rCopy := *r
		rCopy.Id = q.Id
		return &rCopy, nil
	}
	r.Id = q.Id
	return r, nil
}

func (c *DoHClient) doFasthttp(wireMsg []byte, requestLogger *logrus.Entry) (*dns.Msg, error) {

	urlBuf := bytesBufPool.Get().(*bytes.Buffer)
	defer bytesBufPool.Put(urlBuf)
	urlBuf.Grow(len(c.preparedURL) + base64.RawURLEncoding.EncodedLen(len(wireMsg)))
	urlBuf.Reset()
	urlBuf.Write(c.preparedURL)

	// Padding characters for base64url MUST NOT be included.
	// See: https://tools.ietf.org/html/rfc8484 6
	encoder := base64.NewEncoder(base64.RawURLEncoding, urlBuf)
	encoder.Write(wireMsg)
	encoder.Close()

	//Note: It is forbidden copying Request instances. Create new instances and use CopyTo instead.
	//Request instance MUST NOT be used from concurrently running goroutines.
	req := fasthttp.AcquireRequest()
	defer fasthttp.ReleaseRequest(req)
	req.SetRequestURIBytes(urlBuf.Bytes())
	req.Header.SetMethod(fasthttp.MethodGet)
	req.Header.SetCanonical(headerCanonicalKeyAccept, headerValueMediaType)
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseResponse(resp)

	if err := c.fasthttpClient.DoTimeout(req, resp, c.timeout); err != nil {
		return nil, fmt.Errorf("DoTimeout: %w", err)
	}

	statusCode := resp.StatusCode()
	if statusCode != fasthttp.StatusOK {
		if requestLogger.Logger.IsLevelEnabled(logrus.DebugLevel) {
			requestLogger.Debugf("doFasthttp: HTTP status codes [%d] body [%s]", statusCode, resp.Body())
		}
		return nil, fmt.Errorf("HTTP status codes [%d]", statusCode)
	}

	if resp.IsBodyStream() {
		return nil, fmt.Errorf("resp body is stream")
	}

	r := new(dns.Msg)
	err := r.Unpack(resp.Body())
	if err != nil {
		return nil, fmt.Errorf("Unpack: %w", err)
	}
	return r, nil
}
