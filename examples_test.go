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

import "fmt"

func ExampleParseIP() {
	ips, _ := ParseIP("10.1.1,2.1,2")
	fmt.Println(len(ips))

	// Output: 4
	// err should be nil, and ips should contain 10.1.1.1, 10.1.1.2, 10.1.2.1 and 10.1.2.2
}

func ExamplePing() {
	pr, _ := Ping("127.0.0.1")
	fmt.Printf("%v", pr)
	// Output: 8 bytes from 127.0.0.1: seq=1 ttl=64 tos=0 time=346.372us
}

func ExamplePinger() {
	pinger := &Pinger{Size: 64}
	pinger.AddIPs([]string{"127.0.0.1", "127.0.0.2"})

	res, _ := pinger.Start()

	for pr := range res {
		fmt.Printf("%v", pr)
	}

	// Output: 64 bytes from 127.0.0.1: seq=1 ttl=64 tos=0 time=346.372us
	// 127.0.0.2: Request timed out for seq 1
}

func ExamplePinger_dF() {
	pinger := &Pinger{
		DF:   true,
		Size: 1800,
	}
	pinger.AddIPs([]string{"8.8.8.8"})

	res, _ := pinger.Start()

	for pr := range res {
		fmt.Printf("%v", pr)
	}

	// Output: Should output error:
	// ping/sender: Error sending echo requests: write ip4: message too long
}
