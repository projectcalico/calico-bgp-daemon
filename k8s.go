// Copyright (c) 2013 Kelsey Hightower
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of
// this software and associated documentation files (the "Software"), to deal in
// the Software without restriction, including without limitation the rights to
// use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
// of the Software, and to permit persons to whom the Software is furnished to do
// so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// Copyright (C) 2017 VA Linux Systems Japan K.K.
// Copyright (C) 2017 Fumihiko Kakuma <kakuma at valinux co jp>
//
//    Licensed under the Apache License, Version 2.0 (the "License"); you may
//    not use this file except in compliance with the License. You may obtain
//    a copy of the License at
//
//         http://www.apache.org/licenses/LICENSE-2.0
//
//    Unless required by applicable law or agreed to in writing, software
//    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
//    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
//    License for the specific language governing permissions and limitations
//    under the License.
//
// NOTE:
//    Some codes of this file are from backends/k8s/client.go on
//    https://github.com/projectcalico/confd repository.

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"sync"
	"time"

	backendapi "github.com/projectcalico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/libcalico-go/lib/backend/compat"
	"github.com/projectcalico/libcalico-go/lib/backend/k8s/resources"
	"github.com/projectcalico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/libcalico-go/lib/numorstring"

	svbgpconfig "github.com/osrg/gobgp/config"
	svbgptable "github.com/osrg/gobgp/table"
	log "github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	kapiv1 "k8s.io/client-go/pkg/api/v1"
	"k8s.io/client-go/tools/clientcmd"
)

const (
	Act_add  = "add"
	Act_upd  = "upd"
	Act_del  = "del"
	Act_same = "same"
)

type ActionList struct {
	Add  []string
	Upd  []string
	Del  []string
	Same []string
}

func CompareMap(lasts map[string]string, currs map[string]string) ActionList {
	act := ActionList{}
	for key, last := range lasts {
		if cur, ok := currs[key]; ok == false {
			act.Del = append(act.Del, key)
		} else if last != cur {
			act.Upd = append(act.Upd, key)
		} else {
			act.Same = append(act.Same, key)
		}
	}
	for key, _ := range currs {
		if _, ok := lasts[key]; ok == false {
			act.Add = append(act.Add, key)
		}
	}
	return act
}

// populateFromKVPairs populates the vars KV map from the supplied set of
// KVPairs.  This uses the libcalico-go compat module and serialization functions
// to write out the KVPairs in etcdv2 format.  This works in conjunction with the
// etcdVarClient defined below which provides a "mock" etcd backend which actually
// just writes out data to the vars map.
func populateFromKVPairs(kvps []*model.KVPair, vars map[string]string) {
	// Create a etcdVarClient to write the KVP results in the vars map, using the
	// compat adaptor to write the values in etcdv2 format.
	client := compat.NewAdaptor(&etcdVarClient{vars: vars})
	for _, kvp := range kvps {
		if _, err := client.Apply(kvp); err != nil {
			log.Error("Failed to convert k8s data to etcdv2 equivalent: %s = %s", kvp.Key, kvp.Value)
		}
	}
}

type IntervalProcessor struct {
	interval int
	k8scli   *k8sClient
	ipam     *ipamCacheK8s
}

func (p *IntervalProcessor) IntervalLoop() error {
	if err := p.k8scli.updatePrefix(); err != nil {
		return err
	}
	if err := p.k8scli.initialNeighborConfigSetting(); err != nil {
		return err
	}
	ippool, err := p.ipam.getIPPools()
	if err != nil {
		return err
	}
	p.ipam.lastIPPool = ippool
	for {
		log.Debug("polling")
		p.ipam.sync()
		p.k8scli.checkBGPConfig()
		time.Sleep(time.Duration(p.interval) * time.Second)
	}
}

type k8sClient struct {
	node              string
	server            *Server
	k8scli            *kubernetes.Clientset
	nodeBgpPeerClient resources.K8sNodeResourceClient
	nodeBgpCfgClient  resources.K8sNodeResourceClient
	lastBgpconfig     map[string]string
}

// create new Kubernetes client
func NewK8sClient(s *Server) (*k8sClient, error) {
	loadingRules := clientcmd.ClientConfigLoadingRules{}
	config, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
		&loadingRules, &clientcmd.ConfigOverrides{}).ClientConfig()
	if err != nil {
		return nil, err
	}

	// Create the clientset
	cs, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, err
	}
	return &k8sClient{
		node:              os.Getenv(NODENAME),
		server:            s,
		k8scli:            cs,
		nodeBgpPeerClient: resources.NewNodeBGPPeerClient(cs),
		nodeBgpCfgClient:  resources.NewNodeBGPConfigClient(cs),
	}, nil
}

func (c *k8sClient) updatePrefix() error {
	var paths []*svbgptable.Path
	node, err := c.k8scli.Nodes().Get(c.node, metav1.GetOptions{})
	if err != nil {
		return err
	}
	cidr := node.Spec.PodCIDR
	path, err := c.server.makePath(cidr, false)
	log.Debugf("Set prefix: %#v", path)
	paths = append(paths, path)
	if err = c.server.updatePrefixSet(paths); err != nil {
		return err
	}
	if _, err := c.server.bgpServer.AddPath("", paths); err != nil {
		return err
	}
	return nil
}

func (c *k8sClient) initialNeighborConfigSetting() error {
	bgpconfig, err := c.getBGPConfig()
	if err != nil {
		return err
	}
	c.lastBgpconfig = bgpconfig
	neighborConfigs, err := c.getNeighborConfigs(c.lastBgpconfig)
	if err != nil {
		return err
	}
	for _, n := range neighborConfigs {
		if err = c.server.bgpServer.AddNeighbor(n); err != nil {
			return err
		}
	}
	return nil
}

// getNeighborConfigs returns the complete list of BGP neighbor configuration
// which the node should peer.
func (c *k8sClient) getNeighborConfigs(bgpconfig map[string]string) ([]*svbgpconfig.Neighbor, error) {
	var neighbors []*svbgpconfig.Neighbor
	if mesh, ok := bgpconfig[GlobalNodeMesh]; ok == false {
		return nil, errors.New("mesh data not found")
	} else if mesh == `{"enabled":true}` {
		log.Debug("enable mesh")
		ns, err := c.server.getMeshNeighborConfigs()
		if err != nil {
			return nil, err
		}
		neighbors = append(neighbors, ns...)
	}
	// --- Global peers ---
	if ns, err := c.server.getGlobalNeighborConfigs(); err != nil {
		return nil, err
	} else {
		neighbors = append(neighbors, ns...)
	}
	// --- Node-specific peers ---
	if ns, err := c.server.getNodeSpecificNeighborConfigs(); err != nil {
		return nil, err
	} else {
		neighbors = append(neighbors, ns...)
	}
	log.Debugf("neighbors=%s", neighbors)
	return neighbors, nil
}

// checkBGPConfig checks the difference from the last BGP config information.
// But in a case of the following changing, return error.
//   /calico/bgp/v1/host/$NODENAME or /calico/global/as_num
func (c *k8sClient) checkBGPConfig() error {
	curBgpconfig, err := c.getBGPConfig()
	if err != nil {
		return nil
	}
	log.Debugf("checkBGPConfig lastBgpconfig: %s", c.lastBgpconfig)
	if reflect.DeepEqual(c.lastBgpconfig, curBgpconfig) {
		return nil
	}
	act := CompareMap(c.lastBgpconfig, curBgpconfig)
	log.Debugf("checkBGPConfig action list: %#v", act)
	for _, key := range act.Add {
		if err := c.updateBGPConfig(Act_add, key, curBgpconfig); err != nil {
			return err
		}
	}
	for _, key := range act.Upd {
		if err := c.updateBGPConfig(Act_upd, key, curBgpconfig); err != nil {
			return err
		}
	}
	for _, key := range act.Del {
		if err := c.updateBGPConfig(Act_del, key, c.lastBgpconfig); err != nil {
			return err
		}
	}
	c.lastBgpconfig = curBgpconfig
	return nil
}

func (c *k8sClient) updateBGPConfig(action string, key string, bgpconfig map[string]string) error {

	handleNonMeshNeighbor := func(neighborType string, peer string) error {
		n, err := getNeighborConfigFromPeer(peer, neighborType)
		if err != nil {
			return err
		}
		switch action {
		case Act_del:
			return c.server.bgpServer.DeleteNeighbor(n)
		case Act_add, Act_upd:
			return c.server.bgpServer.AddNeighbor(n)
		}
		log.Printf("Unhandled action: %s", action)
		return nil
	}

	var err error = nil
	value := bgpconfig[key]
	switch {
	case strings.HasPrefix(key, fmt.Sprintf("%s/peer_", GlobalBGP)):
		err = handleNonMeshNeighbor("global", value)
	case strings.HasPrefix(key, fmt.Sprintf("%s/%s/peer_", AllNodes, c.node)):
		err = handleNonMeshNeighbor("node", value)
	case strings.HasPrefix(key, fmt.Sprintf("%s/%s", AllNodes, c.node)):
		log.Println("Local host config update. Restart")
		os.Exit(1)
	case strings.HasPrefix(key, AllNodes):
		elems := strings.Split(key, "/")
		if len(elems) < 4 {
			log.Printf("Unhandled key: %s", key)
			return nil
		}
		deleteNeighbor := func(address string) error {
			if address == "" {
				return nil
			}
			n := &svbgpconfig.Neighbor{
				Config: svbgpconfig.NeighborConfig{
					NeighborAddress: address,
				},
			}
			return c.server.bgpServer.DeleteNeighbor(n)
		}
		host := elems[len(elems)-2]
		switch elems[len(elems)-1] {
		case "ip_addr_v4", "ip_addr_v6":
			switch action {
			case Act_del:
				if err = deleteNeighbor(value); err != nil {
					return err
				}
			case Act_add, Act_upd:
				if action == Act_upd {
					if err = deleteNeighbor(c.lastBgpconfig[key]); err != nil {
						return err
					}
				}
				if value == "" {
					return nil
				}
				asn, err := c.server.getPeerASN(host)
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
				if err = c.server.bgpServer.AddNeighbor(n); err != nil {
					return err
				}
			}
		case "as_num":
			var asn numorstring.ASNumber
			if action == Act_upd {
				asn, err = numorstring.ASNumberFromString(value)
				if err != nil {
					return err
				}
			} else {
				asn, err = c.server.getNodeASN()
				if err != nil {
					return err
				}
			}
			for _, version := range []string{"v4", "v6"} {
				ip, ok := bgpconfig[fmt.Sprintf("%s/%s/ip_addr_%s", AllNodes, host, version)]
				if ok == false {
					return errors.New("ip address data not found")
				}
				if ip == "" {
					continue
				}
				if err = deleteNeighbor(ip); err != nil {
					return err
				}
				n := &svbgpconfig.Neighbor{
					Config: svbgpconfig.NeighborConfig{
						NeighborAddress: value,
						PeerAs:          uint32(asn),
						Description:     fmt.Sprintf("Mesh_%s", underscore(value)),
					},
				}
				if err = c.server.bgpServer.AddNeighbor(n); err != nil {
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
		mesh, err := c.server.isMeshMode()
		if err != nil {
			return err
		}
		ns, err := c.server.getMeshNeighborConfigs()
		if err != nil {
			return err
		}
		for _, n := range ns {
			if mesh {
				err = c.server.bgpServer.AddNeighbor(n)
			} else {
				err = c.server.bgpServer.DeleteNeighbor(n)
			}
			if err != nil {
				return err
			}
		}
	}
	return err
}

func (c *k8sClient) getBGPConfig() (map[string]string, error) {
	var bgpconfig = make(map[string]string)

	calicoK8sCl := c.server.client.Backend

	// Set default values for fields that we always expect to have.
	bgpconfig[GlobalLogging] = "info"
	bgpconfig[GlobalASN] = "64512"
	bgpconfig[GlobalNodeMesh] = `{"enabled":true}`

	// Global data consists of both global config and global peers.
	kvps, err := calicoK8sCl.List(model.GlobalBGPConfigListOptions{})
	if err != nil {
		return nil, err
	}
	populateFromKVPairs(kvps, bgpconfig)

	kvps, err = calicoK8sCl.List(model.GlobalBGPPeerListOptions{})
	if err != nil {
		return nil, err
	}
	populateFromKVPairs(kvps, bgpconfig)

	nodes, err := c.k8scli.Nodes().List(metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	for _, kNode := range nodes.Items {
		err := c.populateNodeDetails(&kNode, bgpconfig)
		if err != nil {
			return nil, err
		}
	}

	log.Debugf("Get bgp config: %s", bgpconfig)
	return bgpconfig, err
}

// populateNodeDetails populates the given kvps map with values we track from the k8s Node object.
func (c *k8sClient) populateNodeDetails(kNode *kapiv1.Node, vars map[string]string) error {
	kvps := []*model.KVPair{}

	// Start with the main Node configuration
	cNode, err := resources.K8sNodeToCalico(kNode)
	if err != nil {
		log.Error("Failed to parse k8s Node into Calico Node")
		return err
	}
	kvps = append(kvps, cNode)

	// Add per-node BGP config (each of the per-node resource clients also implements
	// the CustomK8sNodeResourceList interface, used to extract per-node resources from
	// the Node resource.
	if cfg, err := c.nodeBgpCfgClient.ExtractResourcesFromNode(kNode); err != nil {
		log.Error("Failed to parse BGP configs from node resource - skip config data")
	} else {
		kvps = append(kvps, cfg...)
	}

	if peers, err := c.nodeBgpPeerClient.ExtractResourcesFromNode(kNode); err != nil {
		log.Error("Failed to parse BGP peers from node resource - skip config data")
	} else {
		kvps = append(kvps, peers...)
	}

	// Populate the vars map from the KVPairs.
	populateFromKVPairs(kvps, vars)

	return nil
}

// etcdVarClient implements the libcalico-go backend api.Client interface.  It is used to
// write the KVPairs retrieved from the Kubernetes datastore driver into the KV map
// using etcdv2 naming scheme.
type etcdVarClient struct {
	vars map[string]string
}

func (c *etcdVarClient) Create(kvp *model.KVPair) (*model.KVPair, error) {
	log.Fatal("Create should not be invoked")
	return nil, nil
}

func (c *etcdVarClient) Update(kvp *model.KVPair) (*model.KVPair, error) {
	log.Fatal("Update should not be invoked")
	return nil, nil
}

func (c *etcdVarClient) Apply(kvp *model.KVPair) (*model.KVPair, error) {
	path, err := model.KeyToDefaultPath(kvp.Key)
	if err != nil {
		log.Error("Unable to create path from Key: %s", kvp.Key)
		return nil, err
	}
	value, err := model.SerializeValue(kvp)
	if err != nil {
		log.Error("Unable to serialize value: %s", kvp.Key)
		return nil, err
	}
	c.vars[path] = string(value)
	return kvp, nil
}

func (c *etcdVarClient) Delete(kvp *model.KVPair) error {
	// Delete may be invoked as part of the Apply processing for  multi-key resource.
	// However, since we start from an empty map each time, we never need to delete entries,
	// so just ignore this request.
	log.Debug("Delete ignored")
	return nil
}

func (c *etcdVarClient) Get(key model.Key) (*model.KVPair, error) {
	log.Fatal("Get should not be invoked")
	return nil, nil
}

func (c *etcdVarClient) List(list model.ListInterface) ([]*model.KVPair, error) {
	log.Fatal("List should not be invoked")
	return nil, nil
}

func (c *etcdVarClient) Syncer(callbacks backendapi.SyncerCallbacks) backendapi.Syncer {
	log.Fatal("Syncer should not be invoked")
	return nil
}

func (c *etcdVarClient) EnsureInitialized() error {
	log.Fatal("EnsureIntialized should not be invoked")
	return nil
}

func (c *etcdVarClient) EnsureCalicoNodeInitialized(node string) error {
	log.Fatal("EnsureCalicoNodeInitialized should not be invoked")
	return nil
}

type ipamCacheK8s struct {
	mu            sync.RWMutex
	m             map[string]*ipPool
	server        *Server
	updateHandler func(*ipPool) error
	lastIPPool    map[string]string
}

// create new IPAM cache
func NewIPAMCacheK8s(s *Server, updateHandler func(*ipPool) error) *ipamCacheK8s {
	return &ipamCacheK8s{
		m:             make(map[string]*ipPool),
		server:        s,
		updateHandler: updateHandler,
	}
}

// match checks whether we have an IP pool which contains the given prefix.
// If we have, it returns the pool.
func (c *ipamCacheK8s) match(prefix string) *ipPool {
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
func (c *ipamCacheK8s) update(ipPoolData interface{}, del bool) error {
	if reflect.TypeOf(ipPoolData) != reflect.TypeOf("") {
		log.Panicf("unknown parameter type: %s", reflect.TypeOf(ipPoolData))
	}
	ippool := ipPoolData.(string)
	c.mu.Lock()
	defer c.mu.Unlock()
	log.Printf("update ipam cache: %s %t", ippool, del)
	if ippool == "" {
		return nil
	}
	p := &ipPool{}
	if err := json.Unmarshal([]byte(ippool), p); err != nil {
		return err
	}
	if p.CIDR == "" {
		return fmt.Errorf("empty cidr: %s", ippool)
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

func (c *ipamCacheK8s) getIPPools() (map[string]string, error) {
	var ippools = make(map[string]string)
	kvps, err := c.server.client.Backend.List(model.IPPoolListOptions{})
	if err != nil {
		return nil, err
	}
	populateFromKVPairs(kvps, ippools)
	log.Debugf("Get ip pool: %s", ippools)
	return ippools, nil
}

// sync synchronizes the contents under /calico/v1/ipam
func (c *ipamCacheK8s) sync() error {
	currIPPool, err := c.getIPPools()
	if err != nil {
		return err
	}
	log.Debugf("sync lastIPPool: %s", c.lastIPPool)
	if reflect.DeepEqual(c.lastIPPool, currIPPool) {
		return nil
	}
	act := CompareMap(c.lastIPPool, currIPPool)
	log.Debugf("sync action list: %#v", act)
	for _, key := range append(act.Add, act.Upd...) {
		if err := c.update(currIPPool[key], false); err != nil {
			return err
		}
	}
	for _, key := range act.Del {
		if err := c.update(c.lastIPPool[key], true); err != nil {
			return err
		}
	}
	c.lastIPPool = currIPPool
	return nil
}
