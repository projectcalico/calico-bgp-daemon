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
	"errors"
	"fmt"
	"os"
	"strings"

	svbgpconfig "github.com/osrg/gobgp/config"
	"github.com/projectcalico/libcalico-go/lib/numorstring"
	log "github.com/sirupsen/logrus"
)

type BGPConfig struct {
	prefixes  []string
	server    *Server
	cache     map[string]string
	lastcache map[string]string
}

func NewBGPConfig(server *Server) *BGPConfig {
	return &BGPConfig{
		prefixes: []string{CALICO_BGP},
		server:   server,
	}
}

func (bc *BGPConfig) GetPrefixes() []string {
	return bc.prefixes
}

func (bc *BGPConfig) SetCache(last map[string]string, curr map[string]string) {
	bc.cache = curr
	bc.lastcache = last
}

func (bc *BGPConfig) InitialSetting() error {
	values, err := bc.server.Client.GetValues(bc.prefixes)
	if err != nil {
		return err
	}
	bc.cache = values
	neighborConfigs, err := bc.getNeighborConfigs()
	if err != nil {
		return err
	}
	log.Debugf("inital setting bgpconfig=%#v", neighborConfigs)
	for _, n := range neighborConfigs {
		if err = bc.server.BgpServer.AddNeighbor(n); err != nil {
			return err
		}
	}
	err = bc.server.Client.UpdateLastCache(values)
	if err != nil {
		return err
	}
	return nil
}

// Process handles the changes for /calico/bgp/v1 prefix.
func (bc *BGPConfig) Process(acts map[string]map[string][]string) error {
	for act, actmap := range acts {
		for key, values := range actmap {
			for _, prefix := range bc.prefixes {
				if strings.HasPrefix(key, prefix) {
					err := bc.updateBGPConfig(act, key, values)
					if err != nil {
						return err
					}
					break
				}
			}
		}
	}
	log.Debugln("Done bgpconfig Process")
	return nil
}

// getNeighborConfigFromPeer returns a BGP neighbor configuration struct from *etcd.Node
func getNeighborConfigFromPeer(peer string, neighborType string) (*svbgpconfig.Neighbor, error) {
	m := &struct {
		IP  string `json:"ip"`
		ASN string `json:"as_num"`
	}{}
	if err := json.Unmarshal([]byte(peer), m); err != nil {
		return nil, err
	}
	asn, err := numorstring.ASNumberFromString(m.ASN)
	if err != nil {
		return nil, err
	}
	return &svbgpconfig.Neighbor{
		Config: svbgpconfig.NeighborConfig{
			NeighborAddress: m.IP,
			PeerAs:          uint32(asn),
			Description:     fmt.Sprintf("%s_%s", strings.Title(neighborType), underscore(m.IP)),
		},
	}, nil
}

func (bc *BGPConfig) isMeshMode(cache map[string]string) (bool, error) {
	values, err := bc.server.GetValues(cache, []string{GlobalNodeMesh})
	if err != nil {
		return false, err
	}
	if values[GlobalNodeMesh] == GlobalNodeMeshTrue {
		return true, nil
	} else {
		return false, nil
	}
}

// getMeshNeighborConfigs returns the list of mesh BGP neighbor configuration struct
func (bc *BGPConfig) getMeshNeighborConfigs() ([]*svbgpconfig.Neighbor, error) {
	globalASN, err := bc.server.GetNodeASN(bc.cache)
	if err != nil {
		return nil, err
	}
	values, err := bc.server.GetValues(bc.cache, []string{AllNodes})
	if err != nil {
		return nil, err
	}
	nodes := GetNodeMap(values)
	ns := make([]*svbgpconfig.Neighbor, 0, len(nodes))
	for host, hostvals := range nodes {
		if host == bc.server.NodeName {
			continue
		}
		peerASN := globalASN
		if asn, ok := hostvals["as_num"]; ok == true {
			asn, err := numorstring.ASNumberFromString(asn)
			if err != nil {
				return nil, err
			}
			peerASN = asn
		}
		for _, key := range []string{KeyIPV4, KeyIPV6} {
			if ip, ok := hostvals[key]; ok == true && ip != "" {
				id := underscore(ip)
				log.Debugf("get mesh neighbor ip:%s id:%s", ip, id)
				ns = append(ns, &svbgpconfig.Neighbor{
					Config: svbgpconfig.NeighborConfig{
						NeighborAddress: ip,
						PeerAs:          uint32(peerASN),
						Description:     fmt.Sprintf("Mesh_%s", id),
					},
				})
			}
		}
	}
	return ns, nil
}

// getNonMeshNeighborConfigs returns the list of non-mesh BGP neighbor configuration struct
// valid neighborType is either "global" or "node"
func (bc *BGPConfig) getNonMeshNeighborConfigs(neighborType string) ([]*svbgpconfig.Neighbor, error) {
	var prefixes []string
	switch neighborType {
	case "global":
		prefixes = []string{fmt.Sprintf("%s/peer_", GlobalBGP)}
	case "node":
		prefixes = []string{fmt.Sprintf("%s/%s/peer_", AllNodes, bc.server.NodeName)}
	default:
		return nil, fmt.Errorf("invalid neighbor type: %s", neighborType)
	}
	values, err := bc.server.GetValues(bc.cache, prefixes)
	if err != nil {
		return nil, err
	}
	ns := make([]*svbgpconfig.Neighbor, 0, len(values))
	for _, peer := range values {
		n, err := getNeighborConfigFromPeer(peer, neighborType)
		if err != nil {
			return nil, err
		}
		ns = append(ns, n)
	}
	return ns, nil
}

// getGlobalNeighborConfigs returns the list of global BGP neighbor configuration struct
func (bc *BGPConfig) getGlobalNeighborConfigs() ([]*svbgpconfig.Neighbor, error) {
	return bc.getNonMeshNeighborConfigs("global")
}

// getNodeNeighborConfigs returns the list of node specific BGP neighbor configuration struct
func (bc *BGPConfig) getNodeSpecificNeighborConfigs() ([]*svbgpconfig.Neighbor, error) {
	return bc.getNonMeshNeighborConfigs("node")
}

// getNeighborConfigs returns the complete list of BGP neighbor configuration
// which the node should peer.
func (bc *BGPConfig) getNeighborConfigs() ([]*svbgpconfig.Neighbor, error) {
	var neighbors []*svbgpconfig.Neighbor
	// --- Node-to-node mesh ---
	if mesh, err := bc.isMeshMode(bc.cache); err == nil && mesh {
		ns, err := bc.getMeshNeighborConfigs()
		if err != nil {
			return nil, err
		}
		neighbors = append(neighbors, ns...)
	} else if err != nil {
		return nil, err
	}
	// --- Global peers ---
	if ns, err := bc.getGlobalNeighborConfigs(); err != nil {
		return nil, err
	} else {
		neighbors = append(neighbors, ns...)
	}
	// --- Node-specific peers ---
	if ns, err := bc.getNodeSpecificNeighborConfigs(); err != nil {
		return nil, err
	} else {
		neighbors = append(neighbors, ns...)
	}
	return neighbors, nil
}

// Though this method tries to minimize effects to the existing BGP peers,
// when /calico/bgp/v1/host/$NODENAME or /calico/global/as_num is changed,
// give up handling the change and return error (this leads calico-bgp-daemon to be restarted)
func (bc *BGPConfig) updateBGPConfig(action string, key string, values []string) error {
	value := values[0]
	nodeName := bc.server.NodeName
	handleNonMeshNeighbor := func(neighborType string, peer string) error {
		n, err := getNeighborConfigFromPeer(peer, neighborType)
		if err != nil {
			return err
		}
		switch action {
		case Act_Del:
			return bc.server.BgpServer.DeleteNeighbor(n)
		case Act_Add, Act_Upd:
			return bc.server.BgpServer.AddNeighbor(n)
		}
		log.Printf("Unhandled action: %s", action)
		return nil
	}

	var err error = nil
	log.Debugf("updateBGPConfig action: %s key:%s values:%s", action, key, values)
	switch {
	case strings.HasPrefix(key, fmt.Sprintf("%s/peer_", GlobalBGP)):
		err = handleNonMeshNeighbor("global", value)
	case strings.HasPrefix(key, fmt.Sprintf("%s/%s/peer_", AllNodes, nodeName)):
		err = handleNonMeshNeighbor("node", value)
	case strings.HasPrefix(key, fmt.Sprintf("%s/%s", AllNodes, nodeName)):
		log.Println("Local host config update. Restart")
		os.Exit(1)
	case strings.HasPrefix(key, AllNodes):
		elems := strings.Split(key, "/")
		if len(elems) < 4 {
			log.Printf("Unhandled key: %s", key)
			return nil
		}
		log.Debugf("updateBGPConfig split key: %s", elems)
		deleteNeighbor := func(address string) error {
			if address == "" {
				return nil
			}
			n := &svbgpconfig.Neighbor{
				Config: svbgpconfig.NeighborConfig{
					NeighborAddress: address,
				},
			}
			return bc.server.BgpServer.DeleteNeighbor(n)
		}

		isNeighbor := func(address string) bool {
			n := bc.server.BgpServer.GetNeighbor(address, false)
			if n != nil && len(n) != 0 {
				log.Debugf("neighbor for %s exists: %#v", address, n)
				return true
			}
			log.Debugf("neighbor for %s no exists", address)
			return false
		}

		isNeighborDel := func(address string) (bool, error) {
			if address == "" {
				return false, nil
			}
			if isNeighbor(address) {
				if err := deleteNeighbor(address); err != nil {
					log.Debugf("failed to delete neighbor for %s", address)
					return true, err
				}
				return true, nil
			}
			return false, nil
		}

		host := elems[len(elems)-2]
		switch elems[len(elems)-1] {
		case KeyIPV4, KeyIPV6:
			if action == Act_Del {
				if _, err := isNeighborDel(value); err != nil {
					return err
				}
			} else {
				if action == Act_Add {
					if isNeighbor(value) {
						return nil
					}
				}
				if action == Act_Upd {
					if err = deleteNeighbor(values[1]); err != nil {
						return err
					}
				}
				if value == "" {
					return nil
				}
				asn, err := bc.server.GetPeerASN(bc.cache, host)
				if err != nil {
					return err
				}
				n := &svbgpconfig.Neighbor{
					Config: svbgpconfig.NeighborConfig{
						NeighborAddress: value,
						PeerAs:          uint32(asn),
						Description:     fmt.Sprintf("Mesh_%s", underscore(value)),
					},
				}
				if err = bc.server.BgpServer.AddNeighbor(n); err != nil {
					return err
				}
			}
		case "as_num":
			var asn numorstring.ASNumber
			var values map[string]string
			hostkey := fmt.Sprintf("%s/%s", AllNodes, host)
			cache, err := bc.server.GetValues(bc.cache, []string{hostkey})
			if err != nil {
				return err
			}
			lastcache, err := bc.server.GetValues(bc.lastcache, []string{hostkey})
			if err != nil {
				return err
			}
			log.Debugf("updateBGPConfig key:%s, cache:%s", hostkey, cache)
			log.Debugf("updateBGPConfig key:%s, lastcache:%s", hostkey, lastcache)
			if action == Act_Del {
				asn, err = bc.server.GetNodeASN(bc.cache)
				if err != nil {
					return err
				}
				values = lastcache
			} else {
				asn, err = numorstring.ASNumberFromString(value)
				if err != nil {
					return err
				}
				values = cache
			}
			for _, key := range []string{KeyIPV4, KeyIPV6} {
				ipkey := fmt.Sprintf("%s/%s/%s", AllNodes, host, key)
				ip, ok := values[ipkey]
				if ok == false {
					return errors.New("ip address data not found")
				}
				log.Debugf("updateBGPConfig key:%s, ip:%s", ipkey, ip)
				if ip == "" {
					continue
				}
				ipdel := ip
				if action == Act_Upd {
					ipdel, ok = lastcache[ipkey]
					if ok == false {
						return errors.New("ip address data not found")
					}
				}
				if _, err := isNeighborDel(ipdel); err != nil {
					return err
				}
				n := &svbgpconfig.Neighbor{
					Config: svbgpconfig.NeighborConfig{
						NeighborAddress: ip,
						PeerAs:          uint32(asn),
						Description:     fmt.Sprintf("Mesh_%s", underscore(value)),
					},
				}
				if err = bc.server.BgpServer.AddNeighbor(n); err != nil {
					return err
				}
			}
		default:
			log.Printf("Unhandled key: %s", key)
		}
	case strings.HasPrefix(key, fmt.Sprintf("%s/as_num", GlobalBGP)):
		log.Println("Global AS number update. Restart")
		os.Exit(1)
	case strings.HasPrefix(key, fmt.Sprintf("%s/node_mesh", GlobalBGP)):
		mesh, err := bc.isMeshMode(bc.cache)
		if err != nil {
			return err
		}
		ns, err := bc.getMeshNeighborConfigs()
		if err != nil {
			return err
		}
		for _, n := range ns {
			if mesh {
				err = bc.server.BgpServer.AddNeighbor(n)
			} else {
				err = bc.server.BgpServer.DeleteNeighbor(n)
			}
			if err != nil {
				return err
			}
		}
	}
	return err
}
