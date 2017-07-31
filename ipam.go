// Copyright (C) 2017 Nippon Telegraph and Telephone Corporation.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
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

	etcd "github.com/coreos/etcd/client"
	log "github.com/Sirupsen/logrus"
	"github.com/osrg/gobgp/table"
	"golang.org/x/net/context"
)

type ipPool struct {
	CIDR string `json:"cidr"`
	IPIP string `json:"ipip"`
	Mode string `json:"ipip_mode"`
}

func (lhs *ipPool) equal(rhs *ipPool) bool {
	if lhs == rhs {
		return true
	}
	if lhs == nil || rhs == nil {
		return false
	}
	return lhs.CIDR == rhs.CIDR && lhs.IPIP == rhs.IPIP && lhs.Mode == rhs.Mode
}

// Contain returns true if this ipPool contains 'prefix'
func (p *ipPool) contain(prefix string) bool {
	k := table.CidrToRadixkey(prefix)
	l := table.CidrToRadixkey(p.CIDR)
	return strings.HasPrefix(k, l)
}

type ipamCache struct {
	mu            sync.RWMutex
	m             map[string]*ipPool
	etcdAPI       etcd.KeysAPI
	updateHandler func(*ipPool) error
}

// match checks whether we have an IP pool which contains the given prefix.
// If we have, it returns the pool.
func (c *ipamCache) match(prefix string) *ipPool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	for _, p := range c.m {
		if p.contain(prefix) {
			return p
		}
	}
	return nil
}

// update updates the internal map with IPAM updates when the update
// is new addtion to the map or changes the existing item, it calls
// updateHandler
func (c *ipamCache) update(node *etcd.Node, del bool) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	log.Printf("update ipam cache: %s, %v, %t", node.Key, node.Value, del)
	if node.Dir {
		return nil
	}
	p := &ipPool{}
	if err := json.Unmarshal([]byte(node.Value), p); err != nil {
		return err
	}
	if p.CIDR == "" {
		return fmt.Errorf("empty cidr: %s", node.Value)
	}
	q := c.m[p.CIDR]
	if del {
		delete(c.m, p.CIDR)
		return nil
	} else if p.equal(q) {
		return nil
	}

	c.m[p.CIDR] = p

	if c.updateHandler != nil {
		return c.updateHandler(p)
	}
	return nil
}

func (c *ipamCache) syncsubr(n *etcd.Node) error {
	for _, node := range n.Nodes {
		if node.Dir {
			if err := c.syncsubr(node); err != nil {
				return err
			}
		} else {
			if err := c.update(node, false); err != nil {
				return err
			}
		}
	}
	return nil
}

// sync synchronizes the contents under /calico/v1/ipam
func (c *ipamCache) sync() error {
	res, err := c.etcdAPI.Get(context.Background(), CALICO_IPAM, &etcd.GetOptions{Recursive: true})
	if err != nil {
		return err
	}

	var index uint64
	for _, node := range res.Node.Nodes {
		if node.ModifiedIndex > index {
			index = node.ModifiedIndex
		}
		if err = c.syncsubr(node); err != nil {
			return err
		}
	}

	watcher := c.etcdAPI.Watcher(CALICO_IPAM, &etcd.WatcherOptions{Recursive: true, AfterIndex: index})
	for {
		res, err := watcher.Next(context.Background())
		if err != nil {
			return err
		}
		del := false
		node := res.Node
		switch res.Action {
		case "set", "create", "update", "compareAndSwap":
		case "delete":
			del = true
			node = res.PrevNode
		default:
			log.Printf("unhandled action: %s", res.Action)
			continue
		}
		if err = c.update(node, del); err != nil {
			return err
		}
	}
	return nil
}

// create new IPAM cache
func newIPAMCache(api etcd.KeysAPI, updateHandler func(*ipPool) error) *ipamCache {
	return &ipamCache{
		m:             make(map[string]*ipPool),
		updateHandler: updateHandler,
		etcdAPI:       api,
	}
}
