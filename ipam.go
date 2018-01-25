// Copyright (C) 2017 Nippon Telegraph and Telephone Corporation.
// Copyright (C) 2018 VA Linux Systems Japan K.K.
// Copyright (C) 2018 Fumihiko Kakuma <kakuma at valinux co jp>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	bgptable "github.com/osrg/gobgp/table"
	log "github.com/sirupsen/logrus"
)

type IpamCache struct {
	prefixes      []string
	mu            sync.RWMutex
	m             map[string]*IpPool
	server        *Server
	updateHandler func(*IpPool) error
	cache         map[string]string
	lastcache     map[string]string
}

type IpPool struct {
	CIDR string `json:"cidr"`
	IPIP string `json:"ipip"`
	Mode string `json:"ipip_mode"`
}

func (lhs *IpPool) Equal(rhs *IpPool) bool {
	if lhs == rhs {
		return true
	}
	if lhs == nil || rhs == nil {
		return false
	}
	return lhs.CIDR == rhs.CIDR && lhs.IPIP == rhs.IPIP && lhs.Mode == rhs.Mode
}

// Contain returns true if this IpPool contains 'prefix'
func (p *IpPool) Contain(prefix string) bool {
	k := bgptable.CidrToRadixkey(prefix)
	l := bgptable.CidrToRadixkey(p.CIDR)
	return strings.HasPrefix(k, l)
}

// create new IPAM cache
func NewIPAMCache(server *Server, updateHandler func(*IpPool) error) *IpamCache {
	return &IpamCache{
		prefixes:      []string{CALICO_IPAM},
		m:             make(map[string]*IpPool),
		server:        server,
		updateHandler: updateHandler,
	}
}

func (c *IpamCache) GetPrefixes() []string {
	return c.prefixes
}

func (c *IpamCache) SetCache(last map[string]string, curr map[string]string) {
	c.cache = curr
	c.lastcache = last
}

func (c *IpamCache) InitialSetting() error {
	values, err := c.server.Client.GetValues(c.prefixes)
	if err != nil {
		return err
	}
	for key, value := range values {
		if err := c.sync(Act_Add, key, []string{value}); err != nil {
			return err
		}
	}
	err = c.server.Client.UpdateLastCache(values)
	if err != nil {
		return err
	}
	return nil
}

// Process handles the changes for /calico/v1/ipam prefix.
func (c *IpamCache) Process(acts map[string]map[string][]string) error {
	for act, actmap := range acts {
		for key, values := range actmap {
			for _, prefix := range c.prefixes {
				if strings.HasPrefix(key, prefix) {
					err := c.sync(act, key, values)
					if err != nil {
						return err
					}
					break
				}
			}
		}
	}
	log.Debugln("Done ipam Process")
	return nil
}

// Match checks whether we have an IP pool which contains the given prefix.
// If we have, it returns the pool.
func (c *IpamCache) Match(prefix string) *IpPool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	for _, p := range c.m {
		if p.Contain(prefix) {
			return p
		}
	}
	return nil
}

func (c *IpamCache) update(p *IpPool, del bool) error {
	if p.CIDR == "" {
		return fmt.Errorf("empty cidr: %#v", *p)
	}
	q := c.m[p.CIDR]
	if del {
		delete(c.m, p.CIDR)
		return nil
	} else if p.Equal(q) {
		return nil
	}

	c.m[p.CIDR] = p

	if c.updateHandler != nil {
		return c.updateHandler(p)
	}
	return nil
}

// update updates the internal map with IPAM updates when the update
// is new addtion to the map or changes the existing item, it calls
// updateHandler
func (c *IpamCache) Update(ippool string, del bool) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	log.Printf("update ipam cache: %s %t", ippool, del)
	if ippool == "" {
		return nil
	}
	p := &IpPool{}
	if err := json.Unmarshal([]byte(ippool), p); err != nil {
		return err
	}
	if err := c.update(p, del); err != nil {
		return err
	}
	return nil
}

// sync synchronizes the contents under /calico/v1/ipam
func (c *IpamCache) sync(action string, key string, values []string) error {
	log.Debugf("ipam sync action: %s key:%s values:%s", action, key, values)
	if strings.HasPrefix(key, fmt.Sprintf("%s/v4/pool/", CALICO_IPAM)) || strings.HasPrefix(key, fmt.Sprintf("%s/v6/pool/", CALICO_IPAM)) {
		del := false
		if action == Act_Del {
			del = true
		}
		if err := c.Update(values[0], del); err != nil {
			return err
		}
	}
	return nil
}
