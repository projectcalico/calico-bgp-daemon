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
	"fmt"
	"strings"

	bgptable "github.com/osrg/gobgp/table"
	log "github.com/sirupsen/logrus"
)

type Aggr struct {
	prefixes  []string
	server    *Server
	cache     map[string]string
	lastcache map[string]string
}

func NewAGGR(server *Server) *Aggr {
	return &Aggr{
		prefixes: []string{CALICO_AGGR},
		server:   server,
	}
}

func (a *Aggr) GetPrefixes() []string {
	return a.prefixes
}

func (a *Aggr) SetCache(last map[string]string, curr map[string]string) {
	a.cache = curr
	a.lastcache = last
}

func (a *Aggr) InitialSetting() error {
	values, err := a.server.Client.GetValues(a.prefixes)
	if err != nil {
		return err
	}
	last := make(map[string]string)
	acts := CompareCache(last, values)
	if err = a.Process(acts); err != nil {
		return err
	}
	if err = a.server.Client.UpdateLastCache(values); err != nil {
		return err
	}
	return nil
}

// Process handles the changes for /calico/ipam/v2/host prefix.
// This add/delete aggregated routes which are assigned to the node.
// This function also updates policy appropriately.
func (a *Aggr) Process(acts map[string]map[string][]string) error {
	var ps []*bgptable.Path
	for act, actmap := range acts {
		for key, _ := range actmap {
			path, err := a.makePath(act, key)
			if err != nil {
				return err
			}
			if path != nil {
				log.Printf("aggr add path: %s", path)
				ps = append(ps, path)
			}
		}
	}
	if err := a.updatePath(ps); err != nil {
		return err
	}
	log.Debugln("Done aggr Process")
	return nil
}

func datastoreKeyToPrefix(key string) string {
	path := strings.Split(key, "/")
	return strings.Replace(path[len(path)-1], "-", "/", 1)
}

// This is a wrapped method of MakePath() in main.go.
// This calls MakePath() with result of checking an action parameter.
func (a *Aggr) makePath(action string, key string) (*bgptable.Path, error) {
	if strings.HasPrefix(key, fmt.Sprintf("%s/%s/ipv4/block/", CALICO_AGGR, a.server.NodeName)) || strings.HasPrefix(key, fmt.Sprintf("%s/%s/ipv6/block/", CALICO_AGGR, a.server.NodeName)) {
		log.Debugf("aggr target key:%s", key)
		dskey := datastoreKeyToPrefix(key)
		if action == Act_Del {
			return a.server.MakePath(dskey, true)
		} else {
			return a.server.MakePath(dskey, false)
		}
	}
	return nil, nil
}

func (a *Aggr) updatePath(ps []*bgptable.Path) error {
	if ps == nil {
		log.Debugln("No table path")
		return nil
	}
	if err := a.server.UpdatePrefixSet(ps); err != nil {
		return err
	}
	if _, err := a.server.BgpServer.AddPath("", ps); err != nil {
		return err
	}
	return nil
}
