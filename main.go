// Copyright (C) 2016 Nippon Telegraph and Telephone Corporation.
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
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/Sirupsen/logrus"
	etcd "github.com/coreos/etcd/client"
	"github.com/coreos/etcd/pkg/transport"
	bgpapi "github.com/osrg/gobgp/api"
	bgpconfig "github.com/osrg/gobgp/config"
	bgp "github.com/osrg/gobgp/packet/bgp"
	bgpserver "github.com/osrg/gobgp/server"
	bgptable "github.com/osrg/gobgp/table"
	calicoapi "github.com/projectcalico/libcalico-go/lib/api"
	calicocli "github.com/projectcalico/libcalico-go/lib/client"
	"github.com/projectcalico/libcalico-go/lib/numorstring"
	calicoscope "github.com/projectcalico/libcalico-go/lib/scope"
	"github.com/vishvananda/netlink"
	"golang.org/x/net/context"
	"gopkg.in/tomb.v2"
)

const (
	NODENAME      = "NODENAME"
	AS            = "AS"
	CALICO_PREFIX = "/calico"
	CALICO_BGP    = CALICO_PREFIX + "/bgp/v1"
	CALICO_AGGR   = CALICO_PREFIX + "/ipam/v2/host"

	defaultDialTimeout = 30 * time.Second

	aggregatedPrefixSetName = "aggregated"
	hostPrefixSetName       = "host"

	RTPROT_GOBGP = 0x11
)

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

func errorButKeyNotFound(err error) error {
	if e, ok := err.(etcd.Error); ok && e.Code == etcd.ErrorCodeKeyNotFound {
		return nil
	}
	return err
}

func getEtcdConfig(cfg *calicoapi.CalicoAPIConfig) (etcd.Config, error) {
	var config etcd.Config
	etcdcfg := cfg.Spec.EtcdConfig
	etcdEndpoints := etcdcfg.EtcdEndpoints
	if etcdEndpoints == "" {
		etcdEndpoints = fmt.Sprintf("%s://%s", etcdcfg.EtcdScheme, etcdcfg.EtcdAuthority)
	}
	tls := transport.TLSInfo{
		CAFile:   etcdcfg.EtcdCACertFile,
		CertFile: etcdcfg.EtcdCertFile,
		KeyFile:  etcdcfg.EtcdKeyFile,
	}
	t, err := transport.NewTransport(tls, defaultDialTimeout)
	if err != nil {
		return config, err
	}
	config.Endpoints = strings.Split(etcdEndpoints, ",")
	config.Transport = t
	return config, nil
}

type Server struct {
	t         tomb.Tomb
	bgpServer *bgpserver.BgpServer
	client    *calicocli.Client
	etcd      etcd.KeysAPI
	ipv4      net.IP
	ipv6      net.IP
}

func NewServer() (*Server, error) {
	config, err := calicocli.LoadClientConfigFromEnvironment()
	if err != nil {
		return nil, err
	}

	etcdConfig, err := getEtcdConfig(config)
	if err != nil {
		return nil, err
	}

	cli, err := etcd.New(etcdConfig)
	if err != nil {
		return nil, err
	}
	etcdCli := etcd.NewKeysAPI(cli)

	calicoCli, err := calicocli.New(*config)
	if err != nil {
		return nil, err
	}

	node, err := calicoCli.Nodes().Get(calicoapi.NodeMetadata{Name: os.Getenv(NODENAME)})
	if err != nil {
		return nil, err
	}

	if node.Spec.BGP == nil {
		return nil, fmt.Errorf("Calico is running in policy-only mode")
	}
	var ipv4, ipv6 net.IP
	if ipnet := node.Spec.BGP.IPv4Address; ipnet != nil {
		ipv4 = ipnet.IP
	}
	if ipnet := node.Spec.BGP.IPv6Address; ipnet != nil {
		ipv6 = ipnet.IP
	}

	bgpServer := bgpserver.NewBgpServer()

	return &Server{
		bgpServer: bgpServer,
		client:    calicoCli,
		etcd:      etcdCli,
		ipv4:      ipv4,
		ipv6:      ipv6,
	}, nil
}

func (s *Server) Serve() {
	s.t.Go(func() error {
		s.bgpServer.Serve()
		return nil
	})

	bgpAPIServer := bgpapi.NewGrpcServer(s.bgpServer, ":50051")
	s.t.Go(bgpAPIServer.Serve)

	globalConfig, err := s.getGlobalConfig()
	if err != nil {
		log.Fatal(err)
	}

	if err := s.bgpServer.Start(globalConfig); err != nil {
		log.Fatal(err)
	}

	if err := s.initialPolicySetting(); err != nil {
		log.Fatal(err)
	}

	// monitor routes from other BGP peers and update FIB
	s.t.Go(s.watchBGPPath)
	// watch prefix assigned and announce to other BGP peers
	s.t.Go(s.watchPrefix)
	// watch BGP configuration
	s.t.Go(s.watchBGPConfig)
	// watch routes added by kernel and announce to other BGP peers
	s.t.Go(s.watchKernelRoute)

	<-s.t.Dying()
	log.Fatal(s.t.Err())

}

func (s *Server) getNodeASN() (numorstring.ASNumber, error) {
	return s.getPeerASN(os.Getenv(NODENAME))
}

func (s *Server) getPeerASN(host string) (numorstring.ASNumber, error) {
	node, err := s.client.Nodes().Get(calicoapi.NodeMetadata{Name: host})
	if err != nil {
		return 0, err
	}
	if node.Spec.BGP == nil {
		return 0, fmt.Errorf("host %s is running in policy-only mode")
	}
	asn := node.Spec.BGP.ASNumber
	if asn == nil {
		return s.client.Config().GetGlobalASNumber()
	}
	return *asn, nil

}

func (s *Server) getGlobalConfig() (*bgpconfig.Global, error) {
	asn, err := s.getNodeASN()
	if err != nil {
		return nil, err
	}
	return &bgpconfig.Global{
		Config: bgpconfig.GlobalConfig{
			As:       uint32(asn),
			RouterId: s.ipv4.String(),
		},
	}, nil
}

func (s *Server) isMeshMode() (bool, error) {
	return s.client.Config().GetNodeToNodeMesh()
}

// getMeshNeighborConfigs returns the list of mesh BGP neighbor configuration struct
func (s *Server) getMeshNeighborConfigs() ([]*bgpconfig.Neighbor, error) {
	globalASN, err := s.getNodeASN()
	if err != nil {
		return nil, err
	}
	nodes, err := s.client.Nodes().List(calicoapi.NodeMetadata{})
	if err != nil {
		return nil, err
	}
	ns := make([]*bgpconfig.Neighbor, 0, len(nodes.Items))
	for _, node := range nodes.Items {
		if node.Metadata.Name == os.Getenv(NODENAME) {
			continue
		}
		peerASN := globalASN
		spec := node.Spec.BGP
		if spec == nil {
			continue
		}

		asn := spec.ASNumber
		if asn != nil {
			peerASN = *asn
		}
		if v4 := spec.IPv4Address; v4 != nil {
			ip := v4.IP.String()
			id := strings.Replace(ip, ".", "_", -1)
			ns = append(ns, &bgpconfig.Neighbor{
				Config: bgpconfig.NeighborConfig{
					NeighborAddress: ip,
					PeerAs:          uint32(peerASN),
					Description:     fmt.Sprintf("Mesh_%s", id),
				},
			})
		}
		if v6 := spec.IPv6Address; v6 != nil {
			ip := v6.IP.String()
			id := strings.Replace(ip, ":", "_", -1)
			ns = append(ns, &bgpconfig.Neighbor{
				Config: bgpconfig.NeighborConfig{
					NeighborAddress: ip,
					PeerAs:          uint32(peerASN),
					Description:     fmt.Sprintf("Mesh_%s", id),
				},
			})
		}
	}
	return ns, nil

}

// getNeighborConfigFromPeer returns a BGP neighbor configuration struct from *etcd.Node
func getNeighborConfigFromPeer(node *etcd.Node, neighborType string) (*bgpconfig.Neighbor, error) {
	m := &struct {
		IP  string `json:"ip"`
		ASN string `json:"as_num"`
	}{}
	if err := json.Unmarshal([]byte(node.Value), m); err != nil {
		return nil, err
	}
	asn, err := numorstring.ASNumberFromString(m.ASN)
	if err != nil {
		return nil, err
	}
	return &bgpconfig.Neighbor{
		Config: bgpconfig.NeighborConfig{
			NeighborAddress: m.IP,
			PeerAs:          uint32(asn),
			Description:     fmt.Sprintf("%s_%s", strings.Title(neighborType), underscore(m.IP)),
		},
	}, nil
}

// getNonMeshNeighborConfigs returns the list of non-mesh BGP neighbor configuration struct
// valid neighborType is either "global" or "node"
func (s *Server) getNonMeshNeighborConfigs(neighborType string) ([]*bgpconfig.Neighbor, error) {
	var metadata calicoapi.BGPPeerMetadata
	switch neighborType {
	case "global":
		metadata.Scope = calicoscope.Global
	case "node":
		metadata.Scope = calicoscope.Node
		metadata.Node = os.Getenv(NODENAME)
	default:
		return nil, fmt.Errorf("invalid neighbor type: %s", neighborType)
	}
	list, err := s.client.BGPPeers().List(metadata)
	if err != nil {
		return nil, err
	}
	ns := make([]*bgpconfig.Neighbor, 0, len(list.Items))
	for _, node := range list.Items {
		addr := node.Metadata.PeerIP.String()
		ns = append(ns, &bgpconfig.Neighbor{
			Config: bgpconfig.NeighborConfig{
				NeighborAddress: addr,
				PeerAs:          uint32(node.Spec.ASNumber),
				Description:     fmt.Sprintf("%s_%s", strings.Title(neighborType), underscore(addr)),
			},
		})
	}
	return ns, nil
}

// getGlobalNeighborConfigs returns the list of global BGP neighbor configuration struct
func (s *Server) getGlobalNeighborConfigs() ([]*bgpconfig.Neighbor, error) {
	return s.getNonMeshNeighborConfigs("global")
}

// getNodeNeighborConfigs returns the list of node specific BGP neighbor configuration struct
func (s *Server) getNodeSpecificNeighborConfigs() ([]*bgpconfig.Neighbor, error) {
	return s.getNonMeshNeighborConfigs("node")
}

// getNeighborConfigs returns the complete list of BGP neighbor configuration
// which the node should peer.
func (s *Server) getNeighborConfigs() ([]*bgpconfig.Neighbor, error) {
	var neighbors []*bgpconfig.Neighbor
	// --- Node-to-node mesh ---
	if mesh, err := s.isMeshMode(); err == nil && mesh {
		ns, err := s.getMeshNeighborConfigs()
		if err != nil {
			return nil, err
		}
		neighbors = append(neighbors, ns...)
	} else if err != nil {
		return nil, err
	}
	// --- Global peers ---
	if ns, err := s.getGlobalNeighborConfigs(); err != nil {
		return nil, err
	} else {
		neighbors = append(neighbors, ns...)
	}
	// --- Node-specific peers ---
	if ns, err := s.getNodeSpecificNeighborConfigs(); err != nil {
		return nil, err
	} else {
		neighbors = append(neighbors, ns...)
	}
	return neighbors, nil
}

func etcdKeyToPrefix(key string) string {
	path := strings.Split(key, "/")
	return strings.Replace(path[len(path)-1], "-", "/", 1)
}

func (s *Server) makePath(prefix string, isWithdrawal bool) (*bgptable.Path, error) {
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

	var nlri bgp.AddrPrefixInterface
	attrs := []bgp.PathAttributeInterface{
		bgp.NewPathAttributeOrigin(0),
	}

	if v4 {
		nlri = bgp.NewIPAddrPrefix(uint8(masklen), p.String())
		attrs = append(attrs, bgp.NewPathAttributeNextHop(s.ipv4.String()))
	} else {
		nlri = bgp.NewIPv6AddrPrefix(uint8(masklen), p.String())
		attrs = append(attrs, bgp.NewPathAttributeMpReachNLRI(s.ipv6.String(), []bgp.AddrPrefixInterface{nlri}))
	}

	return bgptable.NewPath(nil, nlri, isWithdrawal, attrs, time.Now(), false), nil
}

// getAssignedPrefixes retrives prefixes assigned to the node and returns them as a
// list of BGP path.
// using etcd directly since libcalico-go doesn't seem to have a method to return
// assigned prefixes yet.
func (s *Server) getAssignedPrefixes(api etcd.KeysAPI) ([]*bgptable.Path, error) {
	var ps []*bgptable.Path
	f := func(version string) error {
		res, err := api.Get(context.Background(), fmt.Sprintf("%s/%s/%s/block", CALICO_AGGR, os.Getenv(NODENAME), version), &etcd.GetOptions{Recursive: true})
		if err != nil {
			return err
		}
		for _, v := range res.Node.Nodes {
			path, err := s.makePath(etcdKeyToPrefix(v.Key), false)
			if err != nil {
				return err
			}
			ps = append(ps, path)
		}
		return nil
	}
	if s.ipv4 != nil {
		if err := f("ipv4"); err != nil {
			return nil, err
		}
	}
	if s.ipv6 != nil {
		if err := f("ipv6"); err != nil {
			return nil, err
		}
	}
	return ps, nil
}

// watchPrefix watches etcd /calico/ipam/v2/host/$NODENAME and add/delete
// aggregated routes which are assigned to the node.
// This function also updates policy appropriately.
func (s *Server) watchPrefix() error {

	paths, err := s.getAssignedPrefixes(s.etcd)
	if err != nil {
		return err
	}

	if err = s.updatePrefixSet(paths); err != nil {
		return err
	}

	if _, err := s.bgpServer.AddPath("", paths); err != nil {
		return err
	}

	watcher := s.etcd.Watcher(fmt.Sprintf("%s/%s", CALICO_AGGR, os.Getenv(NODENAME)), &etcd.WatcherOptions{Recursive: true})
	for {
		var err error
		res, err := watcher.Next(context.Background())
		if err != nil {
			return err
		}
		var path *bgptable.Path
		key := etcdKeyToPrefix(res.Node.Key)
		if res.Action == "delete" {
			path, err = s.makePath(key, true)
		} else {
			path, err = s.makePath(key, false)
		}
		if err != nil {
			return err
		}
		paths := []*bgptable.Path{path}
		if err = s.updatePrefixSet(paths); err != nil {
			return err
		}
		if _, err := s.bgpServer.AddPath("", paths); err != nil {
			return err
		}
		log.Printf("add path: %s", path)
	}
}

// watchBGPConfig watches etcd path /calico/bgp/v1 and handle various changes
// in etcd. Though this method tries to minimize effects to the existing BGP peers,
// when /calico/bgp/v1/host/$NODENAME or /calico/global/as_num is changed,
// give up handling the change and return error (this leads calico-bgp-daemon to be restarted)
func (s *Server) watchBGPConfig() error {

	neighborConfigs, err := s.getNeighborConfigs()
	if err != nil {
		return err
	}

	for _, n := range neighborConfigs {
		if err = s.bgpServer.AddNeighbor(n); err != nil {
			return err
		}
	}

	watcher := s.etcd.Watcher(fmt.Sprintf("%s", CALICO_BGP), &etcd.WatcherOptions{
		Recursive: true,
	})
	for {
		res, err := watcher.Next(context.Background())
		if err != nil {
			return err
		}
		log.Printf("watch: %v", res)

		handleNonMeshNeighbor := func(neighborType string) error {
			switch res.Action {
			case "delete":
				n, err := getNeighborConfigFromPeer(res.PrevNode, neighborType)
				if err != nil {
					return err
				}
				return s.bgpServer.DeleteNeighbor(n)
			case "set", "create", "update", "compareAndSwap":
				n, err := getNeighborConfigFromPeer(res.Node, neighborType)
				if err != nil {
					return err
				}
				return s.bgpServer.AddNeighbor(n)
			}
			log.Printf("unhandled action: %s", res.Action)
			return nil
		}

		key := res.Node.Key
		switch {
		case strings.HasPrefix(key, fmt.Sprintf("%s/global/peer_", CALICO_BGP)):
			err = handleNonMeshNeighbor("global")
		case strings.HasPrefix(key, fmt.Sprintf("%s/host/%s/peer_", CALICO_BGP, os.Getenv(NODENAME))):
			err = handleNonMeshNeighbor("node")
		case strings.HasPrefix(key, fmt.Sprintf("%s/host/%s", CALICO_BGP, os.Getenv(NODENAME))):
			log.Println("Local host config update. Restart")
			os.Exit(1)
		case strings.HasPrefix(key, fmt.Sprintf("%s/host", CALICO_BGP)):
			elems := strings.Split(key, "/")
			if len(elems) < 4 {
				log.Printf("unhandled key: %s", key)
				continue
			}
			deleteNeighbor := func(node *etcd.Node) error {
				n := &bgpconfig.Neighbor{
					Config: bgpconfig.NeighborConfig{
						NeighborAddress: node.Value,
					},
				}
				return s.bgpServer.DeleteNeighbor(n)
			}
			host := elems[len(elems)-2]
			switch elems[len(elems)-1] {
			case "ip_addr_v4", "ip_addr_v6":
				switch res.Action {
				case "delete":
					if err = deleteNeighbor(res.PrevNode); err != nil {
						return err
					}
				case "set":
					if res.PrevNode != nil {
						if err = deleteNeighbor(res.PrevNode); err != nil {
							return err
						}
					}
					asn, err := s.getPeerASN(host)
					if err != nil {
						return err
					}
					n := &bgpconfig.Neighbor{
						Config: bgpconfig.NeighborConfig{
							NeighborAddress: res.Node.Value,
							PeerAs:          uint32(asn),
							Description:     fmt.Sprintf("Mesh_%s", underscore(res.Node.Value)),
						},
					}
					if err = s.bgpServer.AddNeighbor(n); err != nil {
						return err
					}
				}
			case "as_num":
				var asn numorstring.ASNumber
				if res.Action == "set" {
					asn, err = numorstring.ASNumberFromString(res.Node.Value)
					if err != nil {
						return err
					}
				} else {
					asn, err = s.getNodeASN()
					if err != nil {
						return err
					}
				}
				for _, version := range []string{"v4", "v6"} {
					res, err := s.etcd.Get(context.Background(), fmt.Sprintf("%s/host/%s/ip_addr_%s", CALICO_BGP, host, version), nil)
					if errorButKeyNotFound(err) != nil {
						return err
					}
					if res == nil {
						continue
					}
					if err = deleteNeighbor(res.Node); err != nil {
						return err
					}
					ip := res.Node.Value
					n := &bgpconfig.Neighbor{
						Config: bgpconfig.NeighborConfig{
							NeighborAddress: ip,
							PeerAs:          uint32(asn),
							Description:     fmt.Sprintf("Mesh_%s", underscore(ip)),
						},
					}
					if err = s.bgpServer.AddNeighbor(n); err != nil {
						return err
					}
				}
			default:
				log.Printf("unhandled key: %s", key)
			}
		case strings.HasPrefix(key, fmt.Sprintf("%s/global/as_num", CALICO_BGP)):
			log.Println("Global AS number update. Restart")
			os.Exit(1)
		case strings.HasPrefix(key, fmt.Sprintf("%s/global/node_mesh", CALICO_BGP)):
			mesh, err := s.isMeshMode()
			if err != nil {
				return err
			}
			ns, err := s.getMeshNeighborConfigs()
			if err != nil {
				return err
			}
			for _, n := range ns {
				if mesh {
					err = s.bgpServer.AddNeighbor(n)
				} else {
					err = s.bgpServer.DeleteNeighbor(n)
				}
				if err != nil {
					return err
				}
			}
		}
		if err != nil {
			return err
		}
	}
}

// watchKernelRoute receives netlink route update notification and announces
// kernel/boot routes using BGP.
func (s *Server) watchKernelRoute() error {
	ch := make(chan netlink.RouteUpdate)
	err := netlink.RouteSubscribe(ch, nil)
	if err != nil {
		return err
	}
	for update := range ch {
		if update.Table == syscall.RT_TABLE_MAIN && (update.Protocol == syscall.RTPROT_KERNEL || update.Protocol == syscall.RTPROT_BOOT) {
			isWithdrawal := false
			switch update.Type {
			case syscall.RTM_DELROUTE:
				isWithdrawal = true
			case syscall.RTM_NEWROUTE:
			default:
				log.Printf("unhandled rtm type: %d", update.Type)
				continue
			}
			log.Printf("kernel update: %s", update)
			path, err := s.makePath(update.Dst.String(), isWithdrawal)
			if err != nil {
				return err
			}
			if _, err = s.bgpServer.AddPath("", []*bgptable.Path{path}); err != nil {
				return err
			}
		}
	}
	return fmt.Errorf("netlink route subscription ended")
}

// injectRoute is a helper function to inject BGP routes to linux kernel
// TODO: multipath support
func injectRoute(path *bgptable.Path) error {
	nexthop := path.GetNexthop()
	nlri := path.GetNlri()
	dst, _ := netlink.ParseIPNet(nlri.String())
	route := &netlink.Route{
		Dst:      dst,
		Gw:       nexthop,
		Protocol: RTPROT_GOBGP,
	}
	if path.IsWithdraw {
		log.Printf("removed route %s from kernel", nlri)
		return netlink.RouteDel(route)
	}
	log.Printf("added route %s to kernel", nlri)
	return netlink.RouteReplace(route)
}

// watchBGPPath watches BGP routes from other peers and inject them into
// linux kernel
// TODO: multipath support
func (s *Server) watchBGPPath() error {
	watcher := s.bgpServer.Watch(bgpserver.WatchBestPath())
	for {
		ev := <-watcher.Event()
		msg, ok := ev.(*bgpserver.WatchEventBestPath)
		if !ok {
			continue
		}
		for _, path := range msg.PathList {
			if path.IsLocal() {
				continue
			}
			if err := injectRoute(path); err != nil {
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
		ps, err := bgptable.NewPrefixSet(bgpconfig.PrefixSet{PrefixSetName: name})
		if err != nil {
			return err
		}
		return s.bgpServer.AddDefinedSet(ps)
	}
	for _, name := range []string{aggregatedPrefixSetName, hostPrefixSetName} {
		if err := createEmptyPrefixSet(name); err != nil {
			return err
		}
	}
	// intended to work as same as 'calico_pools' export filter of BIRD configuration
	definition := bgpconfig.PolicyDefinition{
		Name: "calico_aggr",
		Statements: []bgpconfig.Statement{
			bgpconfig.Statement{
				Conditions: bgpconfig.Conditions{
					MatchPrefixSet: bgpconfig.MatchPrefixSet{
						PrefixSet: aggregatedPrefixSetName,
					},
				},
				Actions: bgpconfig.Actions{
					RouteDisposition: bgpconfig.ROUTE_DISPOSITION_ACCEPT_ROUTE,
				},
			},
			bgpconfig.Statement{
				Conditions: bgpconfig.Conditions{
					MatchPrefixSet: bgpconfig.MatchPrefixSet{
						PrefixSet: hostPrefixSetName,
					},
				},
				Actions: bgpconfig.Actions{
					RouteDisposition: bgpconfig.ROUTE_DISPOSITION_REJECT_ROUTE,
				},
			},
		},
	}
	policy, err := bgptable.NewPolicy(definition)
	if err != nil {
		return err
	}
	if err = s.bgpServer.AddPolicy(policy, false); err != nil {
		return err
	}
	return s.bgpServer.AddPolicyAssignment("", bgptable.POLICY_DIRECTION_EXPORT,
		[]*bgpconfig.PolicyDefinition{&definition},
		bgptable.ROUTE_TYPE_ACCEPT)
}

func (s *Server) updatePrefixSet(paths []*bgptable.Path) error {
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
	ps, err := bgptable.NewPrefixSet(bgpconfig.PrefixSet{
		PrefixSetName: aggregatedPrefixSetName,
		PrefixList: []bgpconfig.Prefix{
			bgpconfig.Prefix{
				IpPrefix: prefix,
			},
		},
	})
	if err != nil {
		return err
	}
	if del {
		err = s.bgpServer.DeleteDefinedSet(ps, false)
	} else {
		err = s.bgpServer.AddDefinedSet(ps)
	}
	if err != nil {
		return err
	}
	min, _ := ipNet.Mask.Size()
	max := 32
	if ipNet.IP.To4() == nil {
		max = 128
	}
	ps, err = bgptable.NewPrefixSet(bgpconfig.PrefixSet{
		PrefixSetName: hostPrefixSetName,
		PrefixList: []bgpconfig.Prefix{
			bgpconfig.Prefix{
				IpPrefix:        prefix,
				MasklengthRange: fmt.Sprintf("%d..%d", min, max),
			},
		},
	})
	if err != nil {
		return err
	}
	if del {
		return s.bgpServer.DeleteDefinedSet(ps, false)
	}
	return s.bgpServer.AddDefinedSet(ps)
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

	logrus.SetLevel(logrus.DebugLevel)

	server, err := NewServer()
	if err != nil {
		log.Fatal(err)
	}

	server.Serve()
}
