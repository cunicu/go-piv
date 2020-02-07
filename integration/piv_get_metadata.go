// Copyright 2020 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"fmt"
	"log"
	"strings"

	"github.com/ericchiang/piv-go/piv"
)

func main() {
	cards, err := piv.Cards()
	if err != nil {
		log.Fatalf("listing cards: %v", err)
	}
	yubikey := ""
	for _, card := range cards {
		if strings.Contains(strings.ToLower(card), "yubikey") {
			yubikey = card
			break
		}
	}
	if yubikey == "" {
		log.Fatalf("no yubikeys available")
	}
	yk, err := piv.Open(yubikey)
	if err != nil {
		log.Fatalf("opening yubikey: %v", err)
	}
	defer yk.Close()
	md, err := yk.Metadata(piv.DefaultPIN)
	if err != nil {
		log.Fatalf("getting protected metadata: %v", err)
	}
	if md.ManagementKey == nil {
		log.Fatalf("protected metadata had no management key")
	}
	fmt.Printf("%x\n", *md.ManagementKey)
}