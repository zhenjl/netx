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
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/surgebase/glog"
)

func TestPingerAddIPs(t *testing.T) {
	pinger := &Pinger{}
	testAddIPs(t, pinger)
}

func TestPingerPing(t *testing.T) {
	if skipRawSocketTests() {
		t.Skip("Test skipped due to non-root")
	}

	pr, err := Ping("127.0.0.1")
	require.NoError(t, err)
	glog.Debugf("%v", pr)
}

func TestPingerStartOnce(t *testing.T) {
	if skipRawSocketTests() {
		t.Skip("Test skipped due to non-root")
	}

	ips := []string{"127.0.0.1"}

	pinger := &Pinger{}
	pinger.AddIPs(ips)

	done := make(chan struct{})
	cnt := 0

	res, err := pinger.Start()
	require.NoError(t, err)
	require.NotNil(t, res)

	go func() {
		for pr := range res {
			glog.Debugf("%v", pr)
			cnt++
		}
		close(done)
	}()

	select {
	case <-time.Tick(time.Duration(len(pinger.IPs())) * time.Second):
		require.FailNow(t, "Test timed out")

	case <-done:
		require.Equal(t, len(pinger.IPs()), cnt)
	}

	pinger.Stop()
}

func TestPingerStartMultiple(t *testing.T) {
	if skipRawSocketTests() {
		t.Skip("Test skipped due to non-root")
	}

	pinger := &Pinger{}
	pinger.AddIPs([]string{"127.0.0.1"})

	for i := 0; i < 5; i++ {
		done := make(chan struct{})
		cnt := 0

		res, err := pinger.Start()
		require.NoError(t, err)
		require.NotNil(t, res)

		go func() {
			for pr := range res {
				glog.Debugf("%v", pr)
				cnt++
			}
			close(done)
		}()

		select {
		case <-time.Tick(time.Duration(len(pinger.IPs())) * time.Second):
			require.FailNow(t, "Test timed out")

		case <-done:
			require.Equal(t, len(pinger.IPs()), cnt)
		}

		pinger.Stop()
	}
}

func TestPingerSetDF(t *testing.T) {
	if skipRawSocketTests() {
		t.Skip("Test skipped due to non-root")
	}

	pinger := &Pinger{
		DF:   true,
		Size: 1800,
	}
	pinger.AddIPs([]string{"8.8.8.8"})

	res, err := pinger.Start()
	require.NoError(t, err)
	require.NotNil(t, res)

	go func() {
		for pr := range res {
			glog.Debugf("%v", pr)
		}
	}()

	select {
	case <-time.Tick(time.Duration(len(pinger.IPs())) * time.Second):
	}

	pinger.Stop()
}

func skipRawSocketTests() bool {
	if os.Getuid() != 0 {
		return true
	}

	return false
}
