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

package netx

import (
	"net"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/surgebase/glog"
)

type IPAdder interface {
	AddIPs(ips []string) error
	IPs() []net.IP
}

func TestIPList(t *testing.T) {
	ipl := &iplist{}
	testAddIPs(t, ipl)
}

func testAddIPs(t *testing.T, adder IPAdder) {
	err := adder.AddIPs([]string{"10.1.1.1", "10.1.1.2", "10.1.1.3-4", "10.1.1.5,6,7"})
	require.NoError(t, err)

	m1 := make(map[[4]byte]struct{})
	tmp := [4]byte{10, 1, 1, 1}
	m1[tmp] = struct{}{}
	tmp = [4]byte{10, 1, 1, 2}
	m1[tmp] = struct{}{}
	tmp = [4]byte{10, 1, 1, 3}
	m1[tmp] = struct{}{}
	tmp = [4]byte{10, 1, 1, 4}
	m1[tmp] = struct{}{}
	tmp = [4]byte{10, 1, 1, 5}
	m1[tmp] = struct{}{}
	tmp = [4]byte{10, 1, 1, 6}
	m1[tmp] = struct{}{}
	tmp = [4]byte{10, 1, 1, 7}
	m1[tmp] = struct{}{}

	m2 := make(map[[4]byte]struct{})

	for _, ip := range adder.IPs() {
		var tmp [4]byte
		copy(tmp[:], ip)
		m2[tmp] = struct{}{}
	}

	require.Equal(t, m1, m2)
}

func TestParseIPv4Success(t *testing.T) {
	for i, ip := range ips {
		glog.Debugf("Parsing %d %s", i, ip)
		res, err := ParseIP(ip)
		require.NoError(t, err)

		m := make(map[[4]byte]bool)

		for _, ip2 := range res {
			var tmp [4]byte
			copy(tmp[:], ip2.To4())
			m[tmp] = true
		}

		require.Equal(t, results[i], m)
	}
}

func TestParseIPv4Failure(t *testing.T) {
	_, err := ParseIP("10.1.1.1,10.1.1.2")
	require.Error(t, err)

	_, err = ParseIP("10.1.1.1.")
	require.Error(t, err)

	_, err = ParseIP("10.1.1.a")
	require.Error(t, err)

	_, err = ParseIP("10.1.1.256")
	require.Error(t, err)
}
