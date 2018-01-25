// Copyright (C) 2016-2018 Nippon Telegraph and Telephone Corporation.
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
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"syscall"
	"time"

	svbgpapi "github.com/osrg/gobgp/api"
	svbgpconfig "github.com/osrg/gobgp/config"
	svbgp "github.com/osrg/gobgp/packet/bgp"
	bgpserver "github.com/osrg/gobgp/server"
	bgptable "github.com/osrg/gobgp/table"
	"github.com/projectcalico/libcalico-go/lib/apiconfig"
	"github.com/projectcalico/libcalico-go/lib/numorstring"
	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"gopkg.in/tomb.v2"
)

const (
	NODENAME      = "NODENAME"
	INTERVAL      = "BGPD_INTERVAL"
	AS            = "AS"
	CALICO_PREFIX = "/calico"
	CALICO_BGP    = CALICO_PREFIX + "/bgp/v1"
	CALICO_AGGR   = CALICO_PREFIX + "/ipam/v2/host"
	CALICO_IPAM   = CALICO_PREFIX + "/v1/ipam"

	IpPoolV4       = CALICO_IPAM + "/v4/pool"
	GlobalBGP      = CALICO_BGP + "/global"
	GlobalASN      = GlobalBGP + "/as_num"
	GlobalNodeMesh = GlobalBGP + "/node_mesh"
	GlobalLogging  = GlobalBGP + "/loglevel"
	AllNodes       = CALICO_BGP + "/host"

	KeyIPV4   = "ip_addr_v4"
	KeyIPV6   = "ip_addr_v6"
	KeyIPV4NW = "network_v4"
	KeyIPV6NW = "network_v6"

	DefaultASN         = "64512"
	GlobalNodeMeshTrue = `{"enabled":true}`

	aggregatedPrefixSetName = "aggregated"
	hostPrefixSetName       = "host"

	ProcNum       = 3
	ProcBGPConfig = 0
	ProcAGGR      = 1
	ProcIPAM      = 2

	RTPROT_GOBGP = 0x11

	Act_Add  = "add"
	Act_Upd  = "upd"
	Act_Del  = "del"
	Act_Same = "same"
)

type Processor interface {
	GetPrefixes() []string
	SetCache(last map[string]string, curr map[string]string)
	InitialSetting() error
	Process(acts map[string]map[string][]string) error
}

// VERSION is filled out during the build process (using git describe output)
var VERSION string

func underscore(ip string) string {
	return strings.Map(func(r rune) rune {
		switch r {
		case '.', ':':
			return '_'
		}
		return r
	}, ip)
}

// CompareCache return results compared the current cache with
// the last cache.
//     {Act_Add: {key1: {current-val1}, key2: {current-val2}, ...},
//      Act_Upd: {key1: {current-val1, last-val1}, ...},
//      Act_Del: {key1: {current-val1}, key2: {current-val2}, ...}}
func CompareCache(lasts map[string]string, currs map[string]string) map[string]map[string][]string {
	acts := map[string]map[string][]string{
		Act_Add: make(map[string][]string),
		Act_Upd: make(map[string][]string),
		Act_Del: make(map[string][]string),
	}
	same := make(map[string][]string)
	for key, last := range lasts {
		if cur, ok := currs[key]; ok == false {
			acts[Act_Del][key] = []string{last}
		} else if last != cur {
			acts[Act_Upd][key] = []string{cur, last}
		} else {
			same[key] = []string{cur}
		}
	}
	for key, cur := range currs {
		if _, ok := lasts[key]; ok == false {
			acts[Act_Add][key] = []string{cur}
		}
	}
	log.Debugf("results compared current with last cache: %v", acts)
	log.Debugf("same data of current and last cache: %v", same)
	return acts
}

// MatchesPrefix returns true if the key matches any of the supplied prefixes.
func MatchesPrefix(key string, prefixes []string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(key, p) {
			return true
		}
	}
	return false
}

// GetValuesLocalCache returns values for the required set of prefixes
// from a specified cache.
func GetValuesLocalCache(cache map[string]string, keys []string) (map[string]string, error) {
	log.Debugf("Requesting values for keys: %v", keys)
	values := make(map[string]string)
	for k, v := range cache {
		if MatchesPrefix(k, keys) {
			values[k] = v
		}
	}
	log.Debugf("Returning vlues: %#v", values)
	return values, nil
}

// GetNodeMap returns a set of key/value for each node.
//     {node1: {key1: val1, key2: val2, ...},
//      node2: {key1: val1, key2: val2, ...},
//      ...}
func GetNodeMap(values map[string]string) map[string]map[string]string {
	nodes := make(map[string]map[string]string)
	for key, value := range values {
		elems := strings.Split(key, "/")
		host := elems[len(elems)-2]
		key := elems[len(elems)-1]
		if _, ok := nodes[host]; ok == false {
			nodes[host] = make(map[string]string)
		}
		nodes[host][key] = value
	}
	log.Debugf("node map: %v", nodes)
	return nodes
}

// recursiveNexthopLookup returns bgpNexthop's actual nexthop
// In GCE environment, the interface address is /32 and the BGP nexthop is
// off-subnet. This function looks up kernel RIB and returns a nexthop to
// reach the BGP nexthop.
// When the BGP nexthop can be reached with a connected route,
// this function returns the BGP nexthop.
func recursiveNexthopLookup(bgpNexthop net.IP) (net.IP, error) {
	routes, err := netlink.RouteGet(bgpNexthop)
	if err != nil {
		return nil, err
	}
	if len(routes) == 0 {
		return nil, fmt.Errorf("no route for path: %s", bgpNexthop)
	}
	r := routes[0]
	if r.Gw != nil {
		return r.Gw, nil
	}
	// bgpNexthop can be reached by a connected route
	return bgpNexthop, nil
}

func cleanUpRoutes() error {
	log.Println("Clean up injected routes")
	filter := &netlink.Route{
		Protocol: RTPROT_GOBGP,
	}
	list4, err := netlink.RouteListFiltered(netlink.FAMILY_V4, filter, netlink.RT_FILTER_PROTOCOL)
	if err != nil {
		return err
	}
	list6, err := netlink.RouteListFiltered(netlink.FAMILY_V6, filter, netlink.RT_FILTER_PROTOCOL)
	if err != nil {
		return err
	}
	for _, route := range append(list4, list6...) {
		netlink.RouteDel(&route)
	}
	return nil
}

type Server struct {
	t          tomb.Tomb
	BgpServer  *bgpserver.BgpServer
	Client     StoreClient
	NodeName   string
	ipv4       string
	ipv6       string
	reloadCh   chan []*bgptable.Path
	processors [ProcNum]Processor
	ipam       *IpamCache
}

func NewServer() (*Server, error) {
	nodeName := os.Getenv("NODENAME")
	bgpServer := bgpserver.NewBgpServer()
	server := Server{
		BgpServer: bgpServer,
		NodeName:  nodeName,
		reloadCh:  make(chan []*bgptable.Path),
	}

	config, err := apiconfig.LoadClientConfigFromEnvironment()
	if err != nil {
		return nil, err
	}
	storeClient, err := NewDataStore(*config)
	if err != nil {
		return nil, err
	}
	server.Client = storeClient

	processors := [ProcNum]Processor{
		ProcBGPConfig: NewBGPConfig(&server),
		ProcAGGR:      NewAGGR(&server),
		ProcIPAM:      NewIPAMCache(&server, server.ipamUpdateHandler),
	}
	server.ipam = processors[ProcIPAM].(*IpamCache)
	watchprefixes := []string{}
	for _, p := range processors {
		watchprefixes = append(watchprefixes, p.GetPrefixes()...)
	}
	if err := storeClient.SetPrefixes(watchprefixes); err != nil {
		return nil, err
	}
	server.processors = processors

	values, err := server.GetNode(nil, nodeName)
	if err != nil {
		return nil, err
	}
	ipv4, ok := values[fmt.Sprintf("%s/%s/%s", AllNodes, nodeName, KeyIPV4)]
	if ok {
		server.ipv4 = ipv4
	}
	ipv6, ok := values[fmt.Sprintf("%s/%s/%s", AllNodes, nodeName, KeyIPV6)]
	if ok {
		server.ipv6 = ipv6
	}

	if server.ipv4 == "" && server.ipv6 == "" {
		return nil, fmt.Errorf("Calico is running in policy-only mode")
	}

	return &server, nil
}

func (s *Server) Serve() {
	s.t.Go(func() error {
		s.BgpServer.Serve()
		return nil
	})

	bgpAPIServer := svbgpapi.NewGrpcServer(s.BgpServer, ":50051")
	s.t.Go(bgpAPIServer.Serve)

	globalConfig, err := s.getBGPDGlobalConfig()
	if err != nil {
		log.Fatal(err)
	}

	if err := s.BgpServer.Start(globalConfig); err != nil {
		log.Fatal("failed to start BGP server:", err)
	}

	if err := s.initialPolicySetting(); err != nil {
		log.Fatal(err)
	}

	for _, p := range s.processors {
		if err := p.InitialSetting(); err != nil {
			log.Fatalf("failed to execute initial process %#v err:%s", p, err)
		}
	}
	// watch changes for /calico/bgp/v1, /calico/ipam/v2/host,
	// /calico/v1/ipam prefix.
	s.t.Go(func() error { return fmt.Errorf("watchPrefix: %s", s.watchPrefix()) })

	// watch routes from other BGP peers and update FIB
	s.t.Go(func() error { return fmt.Errorf("watchBGPPath: %s", s.watchBGPPath()) })

	// watch routes added by kernel and announce to other BGP peers
	s.t.Go(func() error { return fmt.Errorf("watchKernelRoute: %s", s.watchKernelRoute()) })

	<-s.t.Dying()

	if err := cleanUpRoutes(); err != nil {
		log.Fatalf("%s, also failed to clean up routes which we injected: %s", s.t.Err(), err)
	}
	log.Fatal(s.t.Err())

}

func (s *Server) watchPrefix() error {
	var err error
	var revision uint64
	var last map[string]string
	var curr map[string]string
	var acts map[string]map[string][]string

	log.Debugf("Run watchPrefix start revision: %d", revision)
	watchprefixes := []string{}
	for _, p := range s.processors {
		watchprefixes = append(watchprefixes, p.GetPrefixes()...)
	}
	log.Debugf("Watch prefix: %s", watchprefixes)
	for {
		err = s.Client.WatchPrefix(watchprefixes, revision)
		if err != nil {
			log.Errorf("Watch prefixes: %s", watchprefixes)
			return err
		}
		revision = s.Client.GetCurrentRevision()
		log.Debugf("run watchPrefix revision: %d", revision)
		last, curr = s.Client.SyncCache()
		if last == nil {
			continue
		}
		acts = CompareCache(last, curr)
		for _, p := range s.processors {
			log.Debugf("Process compared results: %#v", p)
			p.SetCache(last, curr)
			err = p.Process(acts)
			if err != nil {
				log.Errorf("watchPrefix: err=%s Process %#v", err, p)
				return err
			}
		}
	}
}

func (s *Server) GetValues(cache map[string]string, keys []string) (map[string]string, error) {
	var err error
	values := make(map[string]string)
	if cache == nil {
		values, err = s.Client.GetValues(keys)
	} else {
		values, err = GetValuesLocalCache(cache, keys)
	}
	if err != nil {
		return nil, err
	}
	return values, nil
}

func (s *Server) GetNode(cache map[string]string, nodeName string) (map[string]string, error) {
	prefixes := []string{fmt.Sprintf("%s/%s", AllNodes, nodeName)}
	return s.GetValues(cache, prefixes)
}

func isCrossSubnet(gw net.IP, subnet string) bool {
	p := &IpPool{CIDR: subnet}
	result := !p.Contain(gw.String() + "/32")
	return result
}

func (s *Server) ipamUpdateHandler(pool *IpPool) error {
	filter := &netlink.Route{
		Protocol: RTPROT_GOBGP,
	}
	list, err := netlink.RouteListFiltered(netlink.FAMILY_V4, filter, netlink.RT_FILTER_PROTOCOL)
	if err != nil {
		return err
	}
	values, err := s.GetNode(nil, s.NodeName)
	if err != nil {
		return err
	}
	ipv4, ok := values[fmt.Sprintf("%s/%s/%s", AllNodes, s.NodeName, KeyIPV4NW)]
	if ok == false || ipv4 == "" {
		return errors.New("ip address not found")
	}

	for _, route := range list {
		if route.Dst == nil {
			continue
		}
		prefix := route.Dst.String()
		if pool.Contain(prefix) {
			ipip := pool.IPIP != ""
			if pool.Mode == "cross-subnet" && !isCrossSubnet(route.Gw, ipv4) {
				ipip = false
			}
			if ipip {
				i, err := net.InterfaceByName(pool.IPIP)
				if err != nil {
					return err
				}
				route.LinkIndex = i.Index
				route.SetFlag(netlink.FLAG_ONLINK)
			} else {
				tbl, err := s.BgpServer.GetRib("", svbgp.RF_IPv4_UC, []*bgptable.LookupPrefix{
					&bgptable.LookupPrefix{
						Prefix: prefix,
					},
				})
				if err != nil {
					return err
				}
				bests := tbl.Bests("")
				if len(bests) == 0 {
					log.Printf("no best for %s", prefix)
					continue
				}
				best := bests[0]
				if best.IsLocal() {
					log.Printf("%s's best is local path", prefix)
					continue
				}
				gw, err := recursiveNexthopLookup(best.GetNexthop())
				if err != nil {
					return err
				}
				route.Gw = gw
				route.Flags = 0
				rs, err := netlink.RouteGet(gw)
				if err != nil {
					return err
				}
				if len(rs) == 0 {
					return fmt.Errorf("no route for path: %s", gw)
				}
				r := rs[0]
				route.LinkIndex = r.LinkIndex
			}
			return netlink.RouteReplace(&route)
		}
	}
	return nil
}

func (s *Server) GetNodeASN(cache map[string]string) (numorstring.ASNumber, error) {
	return s.GetPeerASN(cache, s.NodeName)
}

func (s *Server) GetPeerASN(cache map[string]string, host string) (numorstring.ASNumber, error) {
	values, err := s.GetNode(cache, s.NodeName)
	if err != nil {
		return 0, err
	}
	asn, ok := values[fmt.Sprintf("%s/%s/as_num", AllNodes, s.NodeName)]
	if ok == false {
		key := fmt.Sprintf("%s/global/as_num", AllNodes)
		values, err := s.GetValues(cache, []string{key})
		if err != nil {
			return 0, err
		}
		asn, ok = values[key]
		if ok == false {
			asn = DefaultASN
		}
	}
	return numorstring.ASNumberFromString(asn)
}

func (s *Server) getBGPDGlobalConfig() (*svbgpconfig.Global, error) {
	asn, err := s.GetNodeASN(nil)
	if err != nil {
		return nil, err
	}
	return &svbgpconfig.Global{
		Config: svbgpconfig.GlobalConfig{
			As:       uint32(asn),
			RouterId: s.ipv4,
		},
	}, nil
}

func (s *Server) MakePath(prefix string, isWithdrawal bool) (*bgptable.Path, error) {
	_, ipNet, err := net.ParseCIDR(prefix)
	if err != nil {
		return nil, err
	}

	p := ipNet.IP
	masklen, _ := ipNet.Mask.Size()
	v4 := true
	if p.To4() == nil {
		v4 = false
	}

	var nlri svbgp.AddrPrefixInterface
	attrs := []svbgp.PathAttributeInterface{
		svbgp.NewPathAttributeOrigin(0),
	}

	if v4 {
		nlri = svbgp.NewIPAddrPrefix(uint8(masklen), p.String())
		attrs = append(attrs, svbgp.NewPathAttributeNextHop(s.ipv4))
	} else {
		nlri = svbgp.NewIPv6AddrPrefix(uint8(masklen), p.String())
		attrs = append(attrs, svbgp.NewPathAttributeMpReachNLRI(s.ipv6, []svbgp.AddrPrefixInterface{nlri}))
	}
	log.Debugf("path isWithdrawal=%t attrs=%#v", isWithdrawal, attrs)

	return bgptable.NewPath(nil, nlri, isWithdrawal, attrs, time.Now(), false), nil
}

// watchKernelRoute receives netlink route update notification and announces
// kernel/boot routes using BGP.
func (s *Server) watchKernelRoute() error {
	err := s.loadKernelRoute()
	if err != nil {
		return err
	}

	ch := make(chan netlink.RouteUpdate)
	err = netlink.RouteSubscribe(ch, nil)
	if err != nil {
		return err
	}
	for update := range ch {
		log.Printf("kernel update: %s", update)
		if update.Table == syscall.RT_TABLE_MAIN && (update.Protocol == syscall.RTPROT_KERNEL || update.Protocol == syscall.RTPROT_BOOT) {
			// TODO: handle ipPool deletion. RTM_DELROUTE message
			// can belong to previously valid ipPool.
			if s.ipam.Match(update.Dst.String()) == nil {
				continue
			}
			isWithdrawal := false
			switch update.Type {
			case syscall.RTM_DELROUTE:
				isWithdrawal = true
			case syscall.RTM_NEWROUTE:
			default:
				log.Printf("unhandled rtm type: %d", update.Type)
				continue
			}
			path, err := s.MakePath(update.Dst.String(), isWithdrawal)
			if err != nil {
				return err
			}
			log.Printf("made path from kernel update: %s", path)
			if _, err = s.BgpServer.AddPath("", []*bgptable.Path{path}); err != nil {
				return err
			}
		} else if update.Table == syscall.RT_TABLE_LOCAL {
			// This means the interface address is updated
			// Some routes we injected may be deleted by the kernel
			// Reload routes from BGP RIB and inject again
			ip, _, _ := net.ParseCIDR(update.Dst.String())
			family := svbgp.RF_IPv4_UC
			if ip.To4() == nil {
				family = svbgp.RF_IPv6_UC
			}
			tbl, err := s.BgpServer.GetRib("", family, nil)
			if err != nil {
				return err
			}
			s.reloadCh <- tbl.Bests("")
		}
	}
	return fmt.Errorf("netlink route subscription ended")
}

func (s *Server) loadKernelRoute() error {
	filter := &netlink.Route{
		Table: syscall.RT_TABLE_MAIN,
	}
	list, err := netlink.RouteListFiltered(netlink.FAMILY_V4, filter, netlink.RT_FILTER_TABLE)
	if err != nil {
		return err
	}
	for _, route := range list {
		if route.Dst == nil {
			continue
		}
		if s.ipam.Match(route.Dst.String()) == nil {
			continue
		}
		if route.Protocol == syscall.RTPROT_KERNEL || route.Protocol == syscall.RTPROT_BOOT {
			path, err := s.MakePath(route.Dst.String(), false)
			if err != nil {
				return err
			}
			log.Printf("made path from kernel route: %s", path)
			if _, err = s.BgpServer.AddPath("", []*bgptable.Path{path}); err != nil {
				return err
			}
		}
	}
	return nil
}

// injectRoute is a helper function to inject BGP routes to linux kernel
// TODO: multipath support
func (s *Server) injectRoute(path *bgptable.Path) error {
	nexthop := path.GetNexthop()
	nlri := path.GetNlri()
	dst, _ := netlink.ParseIPNet(nlri.String())
	route := &netlink.Route{
		Dst:      dst,
		Gw:       nexthop,
		Protocol: RTPROT_GOBGP,
	}

	ipip := false
	if dst.IP.To4() != nil {
		if p := s.ipam.Match(nlri.String()); p != nil {
			ipip = p.IPIP != ""

			values, err := s.GetNode(nil, s.NodeName)
			if err != nil {
				return err
			}
			ipv4, ok := values[fmt.Sprintf("%s/%s/%s", AllNodes, s.NodeName, KeyIPV4NW)]
			if ok == false || ipv4 == "" {
				return errors.New("ip address not found")
			}

			if p.Mode == "cross-subnet" && !isCrossSubnet(route.Gw, ipv4) {
				ipip = false
			}
			if ipip {
				i, err := net.InterfaceByName(p.IPIP)
				if err != nil {
					return err
				}
				route.LinkIndex = i.Index
				route.SetFlag(netlink.FLAG_ONLINK)
			}
		}
		// TODO: if !IsWithdraw, we'd ignore that
	}

	if path.IsWithdraw {
		log.Printf("removed route %s from kernel", nlri)
		return netlink.RouteDel(route)
	}
	if !ipip {
		gw, err := recursiveNexthopLookup(path.GetNexthop())
		if err != nil {
			return err
		}
		route.Gw = gw
	}
	log.Printf("added route %s to kernel %s", nlri, route)
	return netlink.RouteReplace(route)
}

// watchBGPPath watches BGP routes from other peers and inject them into
// linux kernel
// TODO: multipath support
func (s *Server) watchBGPPath() error {
	watcher := s.BgpServer.Watch(bgpserver.WatchBestPath(false))
	for {
		var paths []*bgptable.Path
		select {
		case ev := <-watcher.Event():
			msg, ok := ev.(*bgpserver.WatchEventBestPath)
			if !ok {
				continue
			}
			paths = msg.PathList
		case paths = <-s.reloadCh:
		}
		for _, path := range paths {
			if path.IsLocal() {
				continue
			}
			if err := s.injectRoute(path); err != nil {
				return err
			}
		}
	}
}

// initialPolicySetting initialize BGP export policy.
// this creates two prefix-sets named 'aggregated' and 'host'.
// A route is allowed to be exported when it matches with 'aggregated' set,
// and not allowed when it matches with 'host' set.
func (s *Server) initialPolicySetting() error {
	createEmptyPrefixSet := func(name string) error {
		ps, err := bgptable.NewPrefixSet(svbgpconfig.PrefixSet{PrefixSetName: name})
		if err != nil {
			return err
		}
		return s.BgpServer.AddDefinedSet(ps)
	}
	for _, name := range []string{aggregatedPrefixSetName, hostPrefixSetName} {
		if err := createEmptyPrefixSet(name); err != nil {
			return err
		}
	}
	// intended to work as same as 'calico_pools' export filter of BIRD configuration
	definition := svbgpconfig.PolicyDefinition{
		Name: "calico_aggr",
		Statements: []svbgpconfig.Statement{
			svbgpconfig.Statement{
				Conditions: svbgpconfig.Conditions{
					MatchPrefixSet: svbgpconfig.MatchPrefixSet{
						PrefixSet: aggregatedPrefixSetName,
					},
				},
				Actions: svbgpconfig.Actions{
					RouteDisposition: svbgpconfig.ROUTE_DISPOSITION_ACCEPT_ROUTE,
				},
			},
			svbgpconfig.Statement{
				Conditions: svbgpconfig.Conditions{
					MatchPrefixSet: svbgpconfig.MatchPrefixSet{
						PrefixSet: hostPrefixSetName,
					},
				},
				Actions: svbgpconfig.Actions{
					RouteDisposition: svbgpconfig.ROUTE_DISPOSITION_REJECT_ROUTE,
				},
			},
		},
	}
	policy, err := bgptable.NewPolicy(definition)
	if err != nil {
		return err
	}
	if err = s.BgpServer.AddPolicy(policy, false); err != nil {
		return err
	}
	return s.BgpServer.AddPolicyAssignment("", bgptable.POLICY_DIRECTION_EXPORT,
		[]*svbgpconfig.PolicyDefinition{&definition},
		bgptable.ROUTE_TYPE_ACCEPT)
}

func (s *Server) UpdatePrefixSet(paths []*bgptable.Path) error {
	for _, path := range paths {
		err := s._updatePrefixSet(path.GetNlri().String(), path.IsWithdraw)
		if err != nil {
			return err
		}
	}
	return nil
}

// _updatePrefixSet updates 'aggregated' and 'host' prefix-sets
// we add the exact prefix to 'aggregated' set, and add corresponding longer
// prefixes to 'host' set.
//
// e.g. prefix: "192.168.1.0/26" del: false
//      add "192.168.1.0/26"     to 'aggregated' set
//      add "192.168.1.0/26..32" to 'host'       set
//
func (s *Server) _updatePrefixSet(prefix string, del bool) error {
	_, ipNet, err := net.ParseCIDR(prefix)
	if err != nil {
		return err
	}
	ps, err := bgptable.NewPrefixSet(svbgpconfig.PrefixSet{
		PrefixSetName: aggregatedPrefixSetName,
		PrefixList: []svbgpconfig.Prefix{
			svbgpconfig.Prefix{
				IpPrefix: prefix,
			},
		},
	})
	if err != nil {
		return err
	}
	if del {
		err = s.BgpServer.DeleteDefinedSet(ps, false)
	} else {
		err = s.BgpServer.AddDefinedSet(ps)
	}
	if err != nil {
		return err
	}
	min, _ := ipNet.Mask.Size()
	max := 32
	if ipNet.IP.To4() == nil {
		max = 128
	}
	ps, err = bgptable.NewPrefixSet(svbgpconfig.PrefixSet{
		PrefixSetName: hostPrefixSetName,
		PrefixList: []svbgpconfig.Prefix{
			svbgpconfig.Prefix{
				IpPrefix:        prefix,
				MasklengthRange: fmt.Sprintf("%d..%d", min, max),
			},
		},
	})
	if err != nil {
		return err
	}
	if del {
		return s.BgpServer.DeleteDefinedSet(ps, false)
	}
	return s.BgpServer.AddDefinedSet(ps)
}

func main() {

	// Display the version on "-v", otherwise just delegate to the skel code.
	// Use a new flag set so as not to conflict with existing libraries which use "flag"
	flagSet := flag.NewFlagSet("Calico", flag.ExitOnError)

	version := flagSet.Bool("v", false, "Display version")
	err := flagSet.Parse(os.Args[1:])
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	if *version {
		fmt.Println(VERSION)
		os.Exit(0)
	}

	rawloglevel := os.Getenv("CALICO_BGP_LOGSEVERITYSCREEN")
	loglevel := log.InfoLevel
	if rawloglevel != "" {
		loglevel, err = log.ParseLevel(rawloglevel)
		if err != nil {
			log.WithError(err).Error("Failed to parse loglevel, defaulting to info.")
			loglevel = log.InfoLevel
		}
	}
	log.SetLevel(loglevel)

	server, err := NewServer()
	if err != nil {
		log.Printf("failed to create new server")
		log.Fatal(err)
	}
	log.Debugf("server struct: %#v", server)

	server.Serve()
}
