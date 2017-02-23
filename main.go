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
	"strconv"
	"strings"
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
	cli       *calicocli.Client
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
		cli:       calicoCli,
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

	// monitor routes from other BGP peers and update FIB
	s.t.Go(s.monitorPath)
	// watch prefix assigned and announce to other BGP peers
	s.t.Go(s.watchPrefix)
	// watch BGP configuration
	s.t.Go(s.watchBGPConfig)

	<-s.t.Dying()
	log.Fatal(s.t.Err())

}

func (s *Server) getGlobalASN() (numorstring.ASNumber, error) {
	return s.cli.Config().GetGlobalASNumber()
}

func (s *Server) getPeerASN(host string) (numorstring.ASNumber, error) {
	node, err := s.cli.Nodes().Get(calicoapi.NodeMetadata{Name: host})
	if err != nil {
		return 0, err
	}
	if node.Spec.BGP == nil {
		return 0, fmt.Errorf("host %s is running in policy-only mode")
	}
	asn := node.Spec.BGP.ASNumber
	if asn == nil {
		return s.getGlobalASN()
	}
	return *asn, nil

}

func (s *Server) getGlobalConfig() (*bgpconfig.Global, error) {
	asn, err := s.getGlobalASN()
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
	return s.cli.Config().GetNodeToNodeMesh()
}

func (s *Server) getMeshNeighborConfigs() ([]*bgpconfig.Neighbor, error) {
	globalASN, err := s.getGlobalASN()
	if err != nil {
		return nil, err
	}
	nodes, err := s.cli.Nodes().List(calicoapi.NodeMetadata{})
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
	list, err := s.cli.BGPPeers().List(metadata)
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

func (s *Server) getGlobalNeighborConfigs() ([]*bgpconfig.Neighbor, error) {
	return s.getNonMeshNeighborConfigs("global")
}

func (s *Server) getNodeSpecificNeighborConfigs() ([]*bgpconfig.Neighbor, error) {
	return s.getNonMeshNeighborConfigs("node")
}

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

func (s *Server) makePath(key string, isWithdrawal bool) (*bgptable.Path, error) {
	path := strings.Split(key, "/")
	elems := strings.Split(path[len(path)-1], "-")
	if len(elems) != 2 {
		return nil, fmt.Errorf("invalid prefix format: %s", path[len(path)-1])
	}
	prefix := elems[0]
	masklen, err := strconv.ParseUint(elems[1], 10, 8)
	if err != nil {
		return nil, err
	}

	p := net.ParseIP(prefix)
	v4 := true
	if p == nil {
		return nil, fmt.Errorf("invalid prefix format: %s", key)
	} else if p.To4() == nil {
		v4 = false
	}

	var nlri bgp.AddrPrefixInterface
	attrs := []bgp.PathAttributeInterface{
		bgp.NewPathAttributeOrigin(0),
	}

	if v4 {
		nlri = bgp.NewIPAddrPrefix(uint8(masklen), prefix)
		attrs = append(attrs, bgp.NewPathAttributeNextHop(s.ipv4.String()))
	} else {
		nlri = bgp.NewIPv6AddrPrefix(uint8(masklen), prefix)
		attrs = append(attrs, bgp.NewPathAttributeMpReachNLRI(s.ipv6.String(), []bgp.AddrPrefixInterface{nlri}))
	}

	return bgptable.NewPath(nil, nlri, isWithdrawal, attrs, time.Now(), false), nil
}

func (s *Server) getAssignedPrefixes(api etcd.KeysAPI) ([]*bgptable.Path, error) {
	var ps []*bgptable.Path
	f := func(version string) error {
		res, err := api.Get(context.Background(), fmt.Sprintf("%s/%s/%s/block", CALICO_AGGR, os.Getenv(NODENAME), version), &etcd.GetOptions{Recursive: true})
		if err != nil {
			return err
		}
		for _, v := range res.Node.Nodes {
			path, err := s.makePath(v.Key, false)
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

func (s *Server) watchPrefix() error {

	paths, err := s.getAssignedPrefixes(s.etcd)
	if err != nil {
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
		if res.Action == "delete" {
			path, err = s.makePath(res.Node.Key, true)
		} else {
			path, err = s.makePath(res.Node.Key, false)
		}
		if err != nil {
			return err
		}
		if _, err := s.bgpServer.AddPath("", []*bgptable.Path{path}); err != nil {
			return err
		}
		log.Printf("add path: %s", path)
	}
}

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
			case "set":
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
					asn, err = s.getGlobalASN()
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

func injectRoute(path *bgptable.Path) error {
	nexthop := path.GetNexthop()
	nlri := path.GetNlri()
	var family int
	var d string

	switch f := path.GetRouteFamily(); f {
	case bgp.RF_IPv4_UC:
		family = netlink.FAMILY_V4
		d = "0.0.0.0/0"
	case bgp.RF_IPv6_UC:
		family = netlink.FAMILY_V6
		d = "::/0"
	default:
		log.Printf("only supports injecting ipv4/ipv6 unicast route: %s", f)
		return nil
	}

	dst, _ := netlink.ParseIPNet(nlri.String())
	route := &netlink.Route{
		Dst: dst,
		Gw:  nexthop,
	}
	routes, _ := netlink.RouteList(nil, family)
	for _, route := range routes {
		if route.Dst != nil {
			d = route.Dst.String()
		}
		if d == dst.String() {
			err := netlink.RouteDel(&route)
			if err != nil {
				return err
			}
		}
	}
	if path.IsWithdraw {
		log.Printf("removed route %s from kernel", nlri)
		return nil
	}
	log.Printf("added route %s to kernel", nlri)
	return netlink.RouteAdd(route)
}

func (s *Server) monitorPath() error {
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
