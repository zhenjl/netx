// Copyright (c) 2014 Dataence, LLC. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// For the portions of the code I copied from golang.org/x/net/{ipv4,icmp},
// and go1.3.3/src/pkg/net/http/server.go:1699
//
// Copyright 2012 The Go Authors.  All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
//
// https://github.com/golang/net
// https://github.com/golang/net/blob/master/LICENSE

package netx

import (
	"bytes"
	"encoding/binary"
	"encoding/gob"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/surgebase/glog"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

const (
	icmpHeaderSize   = 8
	defaultInterval  = 100 * time.Millisecond
	defaultMaxRTT    = 100 * time.Millisecond
	defaultTTL       = 32
	defaultSize      = 8
	ProtocolICMP     = 1
	ProtocolIPv6ICMP = 58
)

// Ping sends ICMP ECHO_REQUEST to a single IP address, wait for the ECHO_REPLY,
// and returns the result.
func Ping(ip string) (*PingResult, error) {
	pinger := &Pinger{}
	pinger.AddIPs([]string{ip})

	res, err := pinger.Start()
	if err != nil {
		return nil, err
	}

	select {
	case pr := <-res:
		return pr, nil

	case <-time.Tick(100 * time.Millisecond):
		return nil, fmt.Errorf("ping/Ping: timed out waiting for echo reply")
	}
}

// PingResult is the result from sending an ICMP ECHO_REQUEST to a specific host.
// When successful, all the fields are filled in and Err is nil.
// When failed, only the fields Src, ID, Seq and Err are available.
type PingResult struct {
	// Source IP = remote host
	Src net.IP

	// Destination IP = localhost IP
	Dst net.IP

	// Type of Service
	TOS int

	// Time to live (# of hops, really)
	TTL int

	// ICMP Type: Type of Message
	// http://en.wikipedia.org/wiki/Internet_Control_Message_Protocol#Control_messages
	Type icmp.Type

	// ICMP Subtype
	// http://en.wikipedia.org/wiki/Internet_Control_Message_Protocol#Control_messages
	Code int

	// Message ID
	ID int

	// Message sequence number
	Seq int

	// Payload size
	Size int

	// Round trip time
	RTT time.Duration

	// Any errors encountered
	Err error
}

func (this *PingResult) GobDecode(p []byte) error {
	buf := bytes.NewBuffer(p)
	dec := gob.NewDecoder(buf)

	if err := dec.Decode(&this.Src); err != nil {
		return err
	}

	if err := dec.Decode(&this.Dst); err != nil {
		return err
	}

	if err := dec.Decode(&this.TOS); err != nil {
		return err
	}

	if err := dec.Decode(&this.TTL); err != nil {
		return err
	}

	//if err := dec.Decode(&this.Type); err != nil {
	//	return err
	//}

	if err := dec.Decode(&this.Code); err != nil {
		return err
	}

	if err := dec.Decode(&this.ID); err != nil {
		return err
	}

	if err := dec.Decode(&this.Seq); err != nil {
		return err
	}

	if err := dec.Decode(&this.Size); err != nil {
		return err
	}

	if err := dec.Decode(&this.RTT); err != nil {
		return err
	}

	var errstr string
	if err := dec.Decode(&errstr); err != nil && err != io.EOF {
		return err
	} else if err != io.EOF {
		this.Err = errors.New(errstr)
	}

	return nil
}

func (this PingResult) GobEncode() ([]byte, error) {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)

	if err := enc.Encode(this.Src); err != nil {
		return nil, err
	}

	if err := enc.Encode(this.Dst); err != nil {
		return nil, err
	}

	if err := enc.Encode(this.TOS); err != nil {
		return nil, err
	}

	if err := enc.Encode(this.TTL); err != nil {
		return nil, err
	}

	//if err := enc.Encode(this.Type); err != nil {
	//	return nil, err
	//}

	if err := enc.Encode(this.Code); err != nil {
		return nil, err
	}

	if err := enc.Encode(this.ID); err != nil {
		return nil, err
	}

	if err := enc.Encode(this.Seq); err != nil {
		return nil, err
	}

	if err := enc.Encode(this.Size); err != nil {
		return nil, err
	}

	if err := enc.Encode(this.RTT); err != nil {
		return nil, err
	}

	if this.Err != nil {
		if err := enc.Encode(this.Err.Error()); err != nil {
			return nil, err
		}
	}

	return buf.Bytes(), nil
}

func (this PingResult) String() string {
	if this.Err != nil {
		return fmt.Sprintf("%v", this.Err)
	}

	return fmt.Sprintf("%d bytes from %v: seq=%d ttl=%d tos=%d time=%v",
		this.Size, this.Src, this.Seq, this.TTL, this.TOS, this.RTT)
}

// Pinger sends ICMP ECHO_REQQUEST to a list of IPv4 addresses and waits for the
// ICMP ECHO_REPLY from each of them.
//
// The process using Pinger must be run as root.
type Pinger struct {
	iplist

	// Interval is the amount of time to wait between sending each ICMP packet.
	// Realistically this shouldn't be less than 25 or 50ms as the process of the
	// ECHO_REPLY packets will take some time. So if the ECHO_REQUEST packets are
	// sent too fast, then the round trip time will be skewed.
	//
	// Default 100ms.
	Interval time.Duration

	// MaxRTT is the maximum round trip time a response is to be expected.
	// Default 100ms.
	MaxRTT time.Duration

	// ICMP payload size, in bytes. Minimum 8 bytes.
	Size int

	// Copied from `man ping` on CentOS
	// Set  Quality of Service -related bits in ICMP datagrams. Traditionally (RFC1349),
	// these have been interpreted as: 0 for reserved (currently being redefined as
	// congestion  control),  1-4  for  Type  of Service and 5-7 for Precedence.
	// Possible settings for Type of Service are: minimal cost: 0x02, reliability: 0x04,
	// throughput: 0x08, low delay: 0x10.  Multiple TOS bits should not be set
	// simultaneously.   Possible  settings  for special Precedence range from priority
	// (0x20) to net control (0xe0).  You must be root (CAP_NET_ADMIN capability) to
	// use Critical or higher precedence value.  You cannot set  bit  0x01 (reserved)
	// unless  ECN  has been enabled in the kernel.  In RFC2474, these fields has been
	// redefined as 8-bit Differentiated Services (DS), consisting of: bits 0-1 of
	// separate data (ECN will be used, here), and bits  2-7 of Differentiated
	// Services Codepoint (DSCP).
	//
	// Default 0
	TOS int

	// Time to live for outgoing ECHO_REQUEST packets.
	//
	// Default 32.
	TTL int

	// Don't Fragment.
	//
	// Default false.
	DF bool

	pid int64

	seqnum int32

	payload []byte

	wg sync.WaitGroup

	mu sync.Mutex

	done chan struct{}

	stopOnce *sync.Once

	quitOnce *sync.Once

	pconn net.PacketConn

	rconn *ipv4.RawConn

	reschan chan *PingResult

	results map[string]*PingResult
}

// Start kicks off the pinging process. It takes the list of IP addresses added by
// AddIPs() and sends ICMP ECHO_REQUEST to all of them at the specified Interval.
// Results are sent via the returned channel. The caller is expected to read the
// channel so it won't get blocked.
//
// Only a single Start can be called at a time. If the second call to Start is made,
// and error will be returned.
func (this *Pinger) Start() (<-chan *PingResult, error) {
	if !atomic.CompareAndSwapInt64(&this.pid, 0, int64(os.Getpid()&0xffff)) {
		return nil, fmt.Errorf("ping/Start: Pinger already running")
	}

	switch runtime.GOOS {
	case "nacl", "plan9", "solaris", "windows":
		return nil, fmt.Errorf("ping/Start: Operation not supported on %q", runtime.GOOS)
	}

	if os.Getuid() != 0 {
		return nil, fmt.Errorf("ping/Start: User must be root")
	}

	this.updateParams()

	if len(this.payload) < this.Size {
		this.payload = make([]byte, this.Size)
	} else {
		this.payload = this.payload[:this.Size]
	}

	var err error

	this.pconn, err = net.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return nil, err
	}

	this.rconn, err = ipv4.NewRawConn(this.pconn)
	if err != nil {
		return nil, err
	}

	cf := ipv4.FlagTTL | ipv4.FlagDst | ipv4.FlagInterface

	if err := this.rconn.SetControlMessage(cf, true); err != nil {
		//glog.Errorf("ping/sender: Error setting control message: %v", err)
		return nil, err
	}

	this.wg.Add(1)
	go this.receiver()

	this.wg.Add(1)
	go this.sender()

	return this.reschan, nil
}

// Stop stops the pinging processes.
func (this *Pinger) Stop() {
	this.stopOnce.Do(func() {
		// Tell the goroutines it's time to quit
		this.quit()

		// Close the raw connection
		this.rconn.Close()

		// Close the network connection
		this.pconn.Close()

		this.wg.Wait()

		this.done = nil
		this.reschan = nil

		atomic.CompareAndSwapInt64(&this.pid, this.pid, 0)
	})
}

func (this *Pinger) quit() {
	this.quitOnce.Do(func() {
		close(this.done)
	})
}

func (this *Pinger) receiver() {
	defer func() {
		// Let's recover from panic
		if r := recover(); r != nil {
			glog.Errorf("Recovering from panic: %v", r)
		}

		this.wg.Done()
		close(this.reschan)
		this.Stop()
	}()

	rb := make([]byte, ipv4.HeaderLen+icmpHeaderSize+this.Size)

	var tempDelay time.Duration // how long to sleep on accept failure

loop:
	for {
		rh, b, _, err := this.rconn.ReadFrom(rb)
		if err != nil {
			select {
			case <-this.done:
				break loop

			default:
			}

			// Borrowed from go1.3.3/src/pkg/net/http/server.go:1699
			if ne, ok := err.(net.Error); ok && ne.Temporary() {
				if tempDelay == 0 {
					tempDelay = 5 * time.Millisecond
				} else {
					tempDelay *= 2
				}
				if max := this.MaxRTT; tempDelay > max {
					tempDelay = max
				}
				glog.Errorf("Accept error: %v; retrying in %v", err, tempDelay)
				time.Sleep(tempDelay)
				continue
			}

			break loop
		}

		m, err := icmp.ParseMessage(ProtocolICMP, b)
		if err != nil {
			// Hm...bad message?
			continue
		}

		if runtime.GOOS == "linux" && m.Type == ipv4.ICMPTypeEcho {
			// On Linux we must handle own sent packets.
			continue
		}

		if m.Type != ipv4.ICMPTypeEchoReply || m.Code != 0 {
			glog.Errorf("got type=%v, code=%v; want type=%v, code=%v", m.Type, m.Code, ipv4.ICMPTypeEchoReply, 0)
			continue
		}

		// Echo Reply
		er, ok := m.Body.(*icmp.Echo)
		if !ok {
			glog.Errorf("Error type requireing m.Body to *icmp.Echo")
			continue
		}

		if er.ID != int(this.pid) || er.Seq > int(this.seqnum) {
			glog.Debugf("%d != %d, %d != %d", er.ID, this.pid, er.Seq, this.seqnum)
			continue
		}

		rtt := time.Since(time.Unix(0, int64(binary.BigEndian.Uint64(er.Data))))

		src := make(net.IP, len(rh.Src))
		copy(src, rh.Src)

		dst := make(net.IP, len(rh.Dst))
		copy(dst, rh.Dst)

		pr := &PingResult{
			TOS:  rh.TOS,
			TTL:  rh.TTL,
			Type: m.Type,
			Code: m.Code,
			ID:   er.ID,
			Seq:  er.Seq,
			RTT:  rtt,
			Src:  src,
			Dst:  dst,
			Size: len(er.Data),
		}
		this.mu.Lock()
		this.results[src.String()] = pr
		this.mu.Unlock()

		this.reschan <- pr
	}

	for ip, pr := range this.results {
		if pr == nil {
			this.reschan <- &PingResult{
				Src: net.ParseIP(ip),
				ID:  int(this.pid),
				Seq: int(this.seqnum),
				Err: fmt.Errorf("%s: Request timed out for seq %d", ip, this.seqnum),
			}
		}
	}
}

func (this *Pinger) sender() {
	defer func() {
		this.wg.Done()

		// Tell the receiver the sender has quit
		this.quit()
	}()

	id := int(this.pid)

	m := &icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &icmp.Echo{
			ID:   id,
			Seq:  this.seq(),
			Data: this.payload,
		},
	}

	var hf ipv4.HeaderFlags
	if this.DF {
		hf |= ipv4.DontFragment
	}

	wh := &ipv4.Header{
		Version:  ipv4.Version,
		Len:      ipv4.HeaderLen,
		TOS:      this.TOS,
		TTL:      this.TTL,
		Protocol: 1,
		Flags:    hf,
	}

	err := this.sendMessage(m, wh)
	if err != nil {
		glog.Errorf("ping/sender: Error sending echo requests: %v", err)
	}
}

func (this *Pinger) sendMessage(m *icmp.Message, wh *ipv4.Header) error {
	select {
	case <-this.done:
		return nil

	default:
	}

	var (
		wb        []byte
		tempDelay time.Duration // how long to sleep on accept failure
		ticker    = time.NewTicker(this.Interval)
	)

	for i, dst := range this.IPs() {
		if i != 0 {
			<-ticker.C
		}

		binary.BigEndian.PutUint64(this.payload, uint64(time.Now().UnixNano()))

		wb, err := this.marshalMessage(m, wb)
		if err != nil {
			glog.Errorf("Error creating ICMP payload: %v", err)
			continue
		}

		wh.TotalLen = ipv4.HeaderLen + len(wb)
		wh.Dst = dst

		glog.Debugf("Pinging %s", wh.Dst)
		this.mu.Lock()
		this.results[wh.Dst.String()] = nil
		this.mu.Unlock()

		if err := this.rconn.SetWriteDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
			return err
		}

		if err := this.rconn.WriteTo(wh, wb, nil); err != nil {
			select {
			case <-this.done:
				return nil

			default:
			}

			// Borrowed from go1.3.3/src/pkg/net/http/server.go:1699
			if ne, ok := err.(net.Error); ok && ne.Temporary() {
				if tempDelay == 0 {
					tempDelay = 5 * time.Millisecond
				} else {
					tempDelay *= 2
				}

				if max := 1 * time.Second; tempDelay > max {
					tempDelay = max
				}

				glog.Errorf("write error: %v; retrying in %v", err, tempDelay)
				time.Sleep(tempDelay)
				continue // out of the IP list, wait for next tick
			}

			return err
		}
	}

	if err := this.rconn.SetReadDeadline(time.Now().Add(this.MaxRTT)); err != nil {
		return err
	}

	return nil
}

// marshalMessage encodes an icmp.Message into the supplied buffer p. If p has enough
// capacity, then it will be used. If p does not have enough capacity, then a new
// buffer will be allocated. The updated buffer, p or the new one, will be returned
// and the length will be set to the length of the echo message.
func (this *Pinger) marshalMessage(m *icmp.Message, p []byte) ([]byte, error) {
	if m.Type.Protocol() == ProtocolIPv6ICMP {
		return nil, fmt.Errorf("ping/marshalMessage: IPv6 not yet supported")
	}

	var mtype, proto int
	switch typ := m.Type.(type) {
	case ipv4.ICMPType:
		mtype = int(typ)
		proto = ProtocolICMP
	case ipv6.ICMPType:
		mtype = int(typ)
		proto = ProtocolIPv6ICMP
	default:
		return nil, syscall.EINVAL
	}

	// http://en.wikipedia.org/wiki/Ping_(networking_utility)
	// 1 byte Type
	// 1 byte Code
	// 2 bytes checksum
	total := 4 + m.Body.Len(proto)
	if cap(p) < total {
		p = make([]byte, total)
	}
	p = p[0:total]

	// p[0] is the Type
	// p[1] is the Code
	// p[2,3] is the checksum, which is not set yet
	p[0], p[1], p[2], p[3] = byte(mtype), byte(m.Code), 0, 0

	// Copy the echo message
	if m.Body != nil && m.Body.Len(proto) != 0 {
		er, ok := m.Body.(*icmp.Echo)
		if !ok {
			return nil, fmt.Errorf("ping/marshalMessage: Error type requireing m.Body to *icmp.Echo")
		}

		p[4], p[5] = byte(er.ID>>8), byte(er.ID)
		p[6], p[7] = byte(er.Seq>>8), byte(er.Seq)
		copy(p[8:], er.Data)
	}

	csumcv := len(p) - 1 // checksum coverage
	s := uint32(0)

	for i := 0; i < csumcv; i += 2 {
		s += uint32(p[i+1])<<8 | uint32(p[i])
	}

	if csumcv&1 == 0 {
		s += uint32(p[csumcv])
	}

	s = s>>16 + s&0xffff
	s = s + s>>16

	// Place checksum back in header; using ^= avoids the
	// assumption the checksum bytes are zero.
	p[2] ^= byte(^s)
	p[3] ^= byte(^s >> 8)

	return p, nil
}

func (this *Pinger) seq() int {
	return int(atomic.AddInt32(&this.seqnum, 1) & 0xffff)
}

// updateParams should only be called from Start()
func (this *Pinger) updateParams() {
	if this.TTL == 0 {
		this.TTL = defaultTTL
	}

	if this.Size < 8 {
		this.Size = defaultSize
	}

	if this.MaxRTT == 0 {
		this.MaxRTT = defaultMaxRTT
	}

	if this.Interval == 0 {
		this.Interval = defaultInterval
	}

	this.done = make(chan struct{})

	this.reschan = make(chan *PingResult, 100)

	this.results = make(map[string]*PingResult, len(this.IPs()))

	this.quitOnce = &sync.Once{}

	this.stopOnce = &sync.Once{}
}
