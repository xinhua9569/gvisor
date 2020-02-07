// Copyright 2019 The gVisor Authors.
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

package stack_test

import (
	"context"
	"encoding/binary"
	"fmt"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"gvisor.dev/gvisor/pkg/rand"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/checker"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

const (
	addr1                    = tcpip.Address("\x0a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01")
	addr2                    = tcpip.Address("\x0a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02")
	addr3                    = tcpip.Address("\x0a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03")
	linkAddr1                = tcpip.LinkAddress("\x02\x02\x03\x04\x05\x06")
	linkAddr2                = tcpip.LinkAddress("\x02\x02\x03\x04\x05\x07")
	linkAddr3                = tcpip.LinkAddress("\x02\x02\x03\x04\x05\x08")
	linkAddr4                = tcpip.LinkAddress("\x02\x02\x03\x04\x05\x09")
	defaultTimeout           = 100 * time.Millisecond
	defaultAsyncEventTimeout = time.Second
)

var (
	llAddr1 = header.LinkLocalAddr(linkAddr1)
	llAddr2 = header.LinkLocalAddr(linkAddr2)
	llAddr3 = header.LinkLocalAddr(linkAddr3)
	llAddr4 = header.LinkLocalAddr(linkAddr4)
	dstAddr = tcpip.FullAddress{
		Addr: "\x0a\x0b\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01",
		Port: 25,
	}
)

func addrForSubnet(subnet tcpip.Subnet, linkAddr tcpip.LinkAddress) tcpip.AddressWithPrefix {
	if !header.IsValidUnicastEthernetAddress(linkAddr) {
		return tcpip.AddressWithPrefix{}
	}

	addrBytes := []byte(subnet.ID())
	header.EthernetAdddressToModifiedEUI64IntoBuf(linkAddr, addrBytes[header.IIDOffsetInIPv6Address:])
	return tcpip.AddressWithPrefix{
		Address:   tcpip.Address(addrBytes),
		PrefixLen: 64,
	}
}

// prefixSubnetAddr returns a prefix (Address + Length), the prefix's equivalent
// tcpip.Subnet, and an address where the lower half of the address is composed
// of the EUI-64 of linkAddr if it is a valid unicast ethernet address.
func prefixSubnetAddr(offset uint8, linkAddr tcpip.LinkAddress) (tcpip.AddressWithPrefix, tcpip.Subnet, tcpip.AddressWithPrefix) {
	prefixBytes := []byte{1, 2, 3, 4, 5, 6, 7, 8 + offset, 0, 0, 0, 0, 0, 0, 0, 0}
	prefix := tcpip.AddressWithPrefix{
		Address:   tcpip.Address(prefixBytes),
		PrefixLen: 64,
	}

	subnet := prefix.Subnet()

	return prefix, subnet, addrForSubnet(subnet, linkAddr)
}

// ndpDADEvent is a set of parameters that was passed to
// ndpDispatcher.OnDuplicateAddressDetectionStatus.
type ndpDADEvent struct {
	nicID    tcpip.NICID
	addr     tcpip.Address
	resolved bool
	err      *tcpip.Error
}

type ndpRouterEvent struct {
	nicID tcpip.NICID
	addr  tcpip.Address
	// true if router was discovered, false if invalidated.
	discovered bool
}

type ndpPrefixEvent struct {
	nicID  tcpip.NICID
	prefix tcpip.Subnet
	// true if prefix was discovered, false if invalidated.
	discovered bool
}

type ndpAutoGenAddrEventType int

const (
	newAddr ndpAutoGenAddrEventType = iota
	deprecatedAddr
	invalidatedAddr
)

type ndpAutoGenAddrEvent struct {
	nicID     tcpip.NICID
	addr      tcpip.AddressWithPrefix
	eventType ndpAutoGenAddrEventType
}

type ndpRDNSS struct {
	addrs    []tcpip.Address
	lifetime time.Duration
}

type ndpRDNSSEvent struct {
	nicID tcpip.NICID
	rdnss ndpRDNSS
}

type ndpDHCPv6Event struct {
	nicID         tcpip.NICID
	configuration stack.DHCPv6ConfigurationFromNDPRA
}

var _ stack.NDPDispatcher = (*ndpDispatcher)(nil)

// ndpDispatcher implements NDPDispatcher so tests can know when various NDP
// related events happen for test purposes.
type ndpDispatcher struct {
	dadC                 chan ndpDADEvent
	routerC              chan ndpRouterEvent
	rememberRouter       bool
	prefixC              chan ndpPrefixEvent
	rememberPrefix       bool
	autoGenAddrC         chan ndpAutoGenAddrEvent
	rdnssC               chan ndpRDNSSEvent
	dhcpv6ConfigurationC chan ndpDHCPv6Event
}

// Implements stack.NDPDispatcher.OnDuplicateAddressDetectionStatus.
func (n *ndpDispatcher) OnDuplicateAddressDetectionStatus(nicID tcpip.NICID, addr tcpip.Address, resolved bool, err *tcpip.Error) {
	if n.dadC != nil {
		n.dadC <- ndpDADEvent{
			nicID,
			addr,
			resolved,
			err,
		}
	}
}

// Implements stack.NDPDispatcher.OnDefaultRouterDiscovered.
func (n *ndpDispatcher) OnDefaultRouterDiscovered(nicID tcpip.NICID, addr tcpip.Address) bool {
	if c := n.routerC; c != nil {
		c <- ndpRouterEvent{
			nicID,
			addr,
			true,
		}
	}

	return n.rememberRouter
}

// Implements stack.NDPDispatcher.OnDefaultRouterInvalidated.
func (n *ndpDispatcher) OnDefaultRouterInvalidated(nicID tcpip.NICID, addr tcpip.Address) {
	if c := n.routerC; c != nil {
		c <- ndpRouterEvent{
			nicID,
			addr,
			false,
		}
	}
}

// Implements stack.NDPDispatcher.OnOnLinkPrefixDiscovered.
func (n *ndpDispatcher) OnOnLinkPrefixDiscovered(nicID tcpip.NICID, prefix tcpip.Subnet) bool {
	if c := n.prefixC; c != nil {
		c <- ndpPrefixEvent{
			nicID,
			prefix,
			true,
		}
	}

	return n.rememberPrefix
}

// Implements stack.NDPDispatcher.OnOnLinkPrefixInvalidated.
func (n *ndpDispatcher) OnOnLinkPrefixInvalidated(nicID tcpip.NICID, prefix tcpip.Subnet) {
	if c := n.prefixC; c != nil {
		c <- ndpPrefixEvent{
			nicID,
			prefix,
			false,
		}
	}
}

func (n *ndpDispatcher) OnAutoGenAddress(nicID tcpip.NICID, addr tcpip.AddressWithPrefix) bool {
	if c := n.autoGenAddrC; c != nil {
		c <- ndpAutoGenAddrEvent{
			nicID,
			addr,
			newAddr,
		}
	}
	return true
}

func (n *ndpDispatcher) OnAutoGenAddressDeprecated(nicID tcpip.NICID, addr tcpip.AddressWithPrefix) {
	if c := n.autoGenAddrC; c != nil {
		c <- ndpAutoGenAddrEvent{
			nicID,
			addr,
			deprecatedAddr,
		}
	}
}

func (n *ndpDispatcher) OnAutoGenAddressInvalidated(nicID tcpip.NICID, addr tcpip.AddressWithPrefix) {
	if c := n.autoGenAddrC; c != nil {
		c <- ndpAutoGenAddrEvent{
			nicID,
			addr,
			invalidatedAddr,
		}
	}
}

// Implements stack.NDPDispatcher.OnRecursiveDNSServerOption.
func (n *ndpDispatcher) OnRecursiveDNSServerOption(nicID tcpip.NICID, addrs []tcpip.Address, lifetime time.Duration) {
	if c := n.rdnssC; c != nil {
		c <- ndpRDNSSEvent{
			nicID,
			ndpRDNSS{
				addrs,
				lifetime,
			},
		}
	}
}

// Implements stack.NDPDispatcher.OnDHCPv6Configuration.
func (n *ndpDispatcher) OnDHCPv6Configuration(nicID tcpip.NICID, configuration stack.DHCPv6ConfigurationFromNDPRA) {
	if c := n.dhcpv6ConfigurationC; c != nil {
		c <- ndpDHCPv6Event{
			nicID,
			configuration,
		}
	}
}

// Check e to make sure that the event is for addr on nic with ID 1, and the
// resolved flag set to resolved with the specified err.
func checkDADEvent(e ndpDADEvent, nicID tcpip.NICID, addr tcpip.Address, resolved bool, err *tcpip.Error) string {
	return cmp.Diff(ndpDADEvent{nicID: nicID, addr: addr, resolved: resolved, err: err}, e, cmp.AllowUnexported(e))
}

// TestDADDisabled tests that an address successfully resolves immediately
// when DAD is not enabled (the default for an empty stack.Options).
func TestDADDisabled(t *testing.T) {
	const nicID = 1
	ndpDisp := ndpDispatcher{
		dadC: make(chan ndpDADEvent, 1),
	}
	opts := stack.Options{
		NetworkProtocols: []stack.NetworkProtocol{ipv6.NewProtocol()},
		NDPDisp:          &ndpDisp,
	}

	e := channel.New(0, 1280, linkAddr1)
	s := stack.New(opts)
	if err := s.CreateNIC(nicID, e); err != nil {
		t.Fatalf("CreateNIC(%d, _) = %s", nicID, err)
	}

	if err := s.AddAddress(nicID, header.IPv6ProtocolNumber, addr1); err != nil {
		t.Fatalf("AddAddress(%d, %d, %s) = %s", nicID, header.IPv6ProtocolNumber, addr1, err)
	}

	// Should get the address immediately since we should not have performed
	// DAD on it.
	select {
	case e := <-ndpDisp.dadC:
		if diff := checkDADEvent(e, nicID, addr1, true, nil); diff != "" {
			t.Errorf("dad event mismatch (-want +got):\n%s", diff)
		}
	default:
		t.Fatal("expected DAD event")
	}
	addr, err := s.GetMainNICAddress(nicID, header.IPv6ProtocolNumber)
	if err != nil {
		t.Fatalf("stack.GetMainNICAddress(%d, %d) err = %s", nicID, header.IPv6ProtocolNumber, err)
	}
	if addr.Address != addr1 {
		t.Fatalf("got stack.GetMainNICAddress(%d, %d) = %s, want = %s", nicID, header.IPv6ProtocolNumber, addr, addr1)
	}

	// We should not have sent any NDP NS messages.
	if got := s.Stats().ICMP.V6PacketsSent.NeighborSolicit.Value(); got != 0 {
		t.Fatalf("got NeighborSolicit = %d, want = 0", got)
	}
}

// TestDADResolve tests that an address successfully resolves after performing
// DAD for various values of DupAddrDetectTransmits and RetransmitTimer.
// Included in the subtests is a test to make sure that an invalid
// RetransmitTimer (<1ms) values get fixed to the default RetransmitTimer of 1s.
func TestDADResolve(t *testing.T) {
	const nicID = 1

	tests := []struct {
		name                    string
		dupAddrDetectTransmits  uint8
		retransTimer            time.Duration
		expectedRetransmitTimer time.Duration
	}{
		{"1:1s:1s", 1, time.Second, time.Second},
		{"2:1s:1s", 2, time.Second, time.Second},
		{"1:2s:2s", 1, 2 * time.Second, 2 * time.Second},
		// 0s is an invalid RetransmitTimer timer and will be fixed to
		// the default RetransmitTimer value of 1s.
		{"1:0s:1s", 1, 0, time.Second},
	}

	for _, test := range tests {
		test := test

		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			ndpDisp := ndpDispatcher{
				dadC: make(chan ndpDADEvent),
			}
			opts := stack.Options{
				NetworkProtocols: []stack.NetworkProtocol{ipv6.NewProtocol()},
				NDPDisp:          &ndpDisp,
			}
			opts.NDPConfigs.RetransmitTimer = test.retransTimer
			opts.NDPConfigs.DupAddrDetectTransmits = test.dupAddrDetectTransmits

			e := channel.New(int(test.dupAddrDetectTransmits), 1280, linkAddr1)
			e.LinkEPCapabilities |= stack.CapabilityResolutionRequired
			s := stack.New(opts)
			if err := s.CreateNIC(nicID, e); err != nil {
				t.Fatalf("CreateNIC(%d, _) = %s", nicID, err)
			}

			if err := s.AddAddress(nicID, header.IPv6ProtocolNumber, addr1); err != nil {
				t.Fatalf("AddAddress(%d, %d, %s) = %s", nicID, header.IPv6ProtocolNumber, addr1, err)
			}

			// Address should not be considered bound to the NIC yet
			// (DAD ongoing).
			addr, err := s.GetMainNICAddress(nicID, header.IPv6ProtocolNumber)
			if err != nil {
				t.Fatalf("got stack.GetMainNICAddress(%d, %d) = (_, %v), want = (_, nil)", nicID, header.IPv6ProtocolNumber, err)
			}
			if want := (tcpip.AddressWithPrefix{}); addr != want {
				t.Fatalf("got stack.GetMainNICAddress(%d, %d) = (%s, nil), want = (%s, nil)", nicID, header.IPv6ProtocolNumber, addr, want)
			}

			// Wait for the remaining time - some delta (500ms), to
			// make sure the address is still not resolved.
			const delta = 500 * time.Millisecond
			time.Sleep(test.expectedRetransmitTimer*time.Duration(test.dupAddrDetectTransmits) - delta)
			addr, err = s.GetMainNICAddress(nicID, header.IPv6ProtocolNumber)
			if err != nil {
				t.Fatalf("got stack.GetMainNICAddress(%d, %d) = (_, %v), want = (_, nil)", nicID, header.IPv6ProtocolNumber, err)
			}
			if want := (tcpip.AddressWithPrefix{}); addr != want {
				t.Fatalf("got stack.GetMainNICAddress(%d, %d) = (%s, nil), want = (%s, nil)", nicID, header.IPv6ProtocolNumber, addr, want)
			}

			// Wait for DAD to resolve.
			select {
			case <-time.After(2 * delta):
				// We should get a resolution event after 500ms
				// (delta) since we wait for 500ms less than the
				// expected resolution time above to make sure
				// that the address did not yet resolve. Waiting
				// for 1s (2x delta) without a resolution event
				// means something is wrong.
				t.Fatal("timed out waiting for DAD resolution")
			case e := <-ndpDisp.dadC:
				if diff := checkDADEvent(e, nicID, addr1, true, nil); diff != "" {
					t.Errorf("dad event mismatch (-want +got):\n%s", diff)
				}
			}
			addr, err = s.GetMainNICAddress(nicID, header.IPv6ProtocolNumber)
			if err != nil {
				t.Fatalf("got stack.GetMainNICAddress(%d, %d) = (_, %v), want = (_, nil)", nicID, header.IPv6ProtocolNumber, err)
			}
			if addr.Address != addr1 {
				t.Fatalf("got stack.GetMainNICAddress(%d, %d) = %s, want = %s", nicID, header.IPv6ProtocolNumber, addr, addr1)
			}

			// Should not have sent any more NS messages.
			if got := s.Stats().ICMP.V6PacketsSent.NeighborSolicit.Value(); got != uint64(test.dupAddrDetectTransmits) {
				t.Fatalf("got NeighborSolicit = %d, want = %d", got, test.dupAddrDetectTransmits)
			}

			// Validate the sent Neighbor Solicitation messages.
			for i := uint8(0); i < test.dupAddrDetectTransmits; i++ {
				p, _ := e.ReadContext(context.Background())

				// Make sure its an IPv6 packet.
				if p.Proto != header.IPv6ProtocolNumber {
					t.Fatalf("got Proto = %d, want = %d", p.Proto, header.IPv6ProtocolNumber)
				}

				// Make sure the right remote link address is used.
				snmc := header.SolicitedNodeAddr(addr1)
				if want := header.EthernetAddressFromMulticastIPv6Address(snmc); p.Route.RemoteLinkAddress != want {
					t.Errorf("got remote link address = %s, want = %s", p.Route.RemoteLinkAddress, want)
				}

				// Check NDP NS packet.
				//
				// As per RFC 4861 section 4.3, a possible option is the Source Link
				// Layer option, but this option MUST NOT be included when the source
				// address of the packet is the unspecified address.
				checker.IPv6(t, p.Pkt.Header.View().ToVectorisedView().First(),
					checker.SrcAddr(header.IPv6Any),
					checker.DstAddr(snmc),
					checker.TTL(header.NDPHopLimit),
					checker.NDPNS(
						checker.NDPNSTargetAddress(addr1),
						checker.NDPNSOptions(nil),
					))
			}
		})
	}
}

// TestDADFail tests to make sure that the DAD process fails if another node is
// detected to be performing DAD on the same address (receive an NS message from
// a node doing DAD for the same address), or if another node is detected to own
// the address already (receive an NA message for the tentative address).
func TestDADFail(t *testing.T) {
	const nicID = 1

	tests := []struct {
		name    string
		makeBuf func(tgt tcpip.Address) buffer.Prependable
		getStat func(s tcpip.ICMPv6ReceivedPacketStats) *tcpip.StatCounter
	}{
		{
			"RxSolicit",
			func(tgt tcpip.Address) buffer.Prependable {
				hdr := buffer.NewPrependable(header.IPv6MinimumSize + header.ICMPv6NeighborSolicitMinimumSize)
				pkt := header.ICMPv6(hdr.Prepend(header.ICMPv6NeighborSolicitMinimumSize))
				pkt.SetType(header.ICMPv6NeighborSolicit)
				ns := header.NDPNeighborSolicit(pkt.NDPPayload())
				ns.SetTargetAddress(tgt)
				snmc := header.SolicitedNodeAddr(tgt)
				pkt.SetChecksum(header.ICMPv6Checksum(pkt, header.IPv6Any, snmc, buffer.VectorisedView{}))
				payloadLength := hdr.UsedLength()
				ip := header.IPv6(hdr.Prepend(header.IPv6MinimumSize))
				ip.Encode(&header.IPv6Fields{
					PayloadLength: uint16(payloadLength),
					NextHeader:    uint8(icmp.ProtocolNumber6),
					HopLimit:      255,
					SrcAddr:       header.IPv6Any,
					DstAddr:       snmc,
				})

				return hdr

			},
			func(s tcpip.ICMPv6ReceivedPacketStats) *tcpip.StatCounter {
				return s.NeighborSolicit
			},
		},
		{
			"RxAdvert",
			func(tgt tcpip.Address) buffer.Prependable {
				naSize := header.ICMPv6NeighborAdvertMinimumSize + header.NDPLinkLayerAddressSize
				hdr := buffer.NewPrependable(header.IPv6MinimumSize + naSize)
				pkt := header.ICMPv6(hdr.Prepend(naSize))
				pkt.SetType(header.ICMPv6NeighborAdvert)
				na := header.NDPNeighborAdvert(pkt.NDPPayload())
				na.SetSolicitedFlag(true)
				na.SetOverrideFlag(true)
				na.SetTargetAddress(tgt)
				na.Options().Serialize(header.NDPOptionsSerializer{
					header.NDPTargetLinkLayerAddressOption(linkAddr1),
				})
				pkt.SetChecksum(header.ICMPv6Checksum(pkt, tgt, header.IPv6AllNodesMulticastAddress, buffer.VectorisedView{}))
				payloadLength := hdr.UsedLength()
				ip := header.IPv6(hdr.Prepend(header.IPv6MinimumSize))
				ip.Encode(&header.IPv6Fields{
					PayloadLength: uint16(payloadLength),
					NextHeader:    uint8(icmp.ProtocolNumber6),
					HopLimit:      255,
					SrcAddr:       tgt,
					DstAddr:       header.IPv6AllNodesMulticastAddress,
				})

				return hdr

			},
			func(s tcpip.ICMPv6ReceivedPacketStats) *tcpip.StatCounter {
				return s.NeighborAdvert
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ndpDisp := ndpDispatcher{
				dadC: make(chan ndpDADEvent, 1),
			}
			ndpConfigs := stack.DefaultNDPConfigurations()
			opts := stack.Options{
				NetworkProtocols: []stack.NetworkProtocol{ipv6.NewProtocol()},
				NDPConfigs:       ndpConfigs,
				NDPDisp:          &ndpDisp,
			}
			opts.NDPConfigs.RetransmitTimer = time.Second * 2

			e := channel.New(0, 1280, linkAddr1)
			s := stack.New(opts)
			if err := s.CreateNIC(nicID, e); err != nil {
				t.Fatalf("CreateNIC(%d, _) = %s", nicID, err)
			}

			if err := s.AddAddress(nicID, header.IPv6ProtocolNumber, addr1); err != nil {
				t.Fatalf("AddAddress(%d, %d, %s) = %s", nicID, header.IPv6ProtocolNumber, addr1, err)
			}

			// Address should not be considered bound to the NIC yet
			// (DAD ongoing).
			addr, err := s.GetMainNICAddress(nicID, header.IPv6ProtocolNumber)
			if err != nil {
				t.Fatalf("got stack.GetMainNICAddress(%d, %d) = (_, %v), want = (_, nil)", nicID, header.IPv6ProtocolNumber, err)
			}
			if want := (tcpip.AddressWithPrefix{}); addr != want {
				t.Fatalf("got stack.GetMainNICAddress(%d, %d) = (%s, nil), want = (%s, nil)", nicID, header.IPv6ProtocolNumber, addr, want)
			}

			// Receive a packet to simulate multiple nodes owning or
			// attempting to own the same address.
			hdr := test.makeBuf(addr1)
			e.InjectInbound(header.IPv6ProtocolNumber, tcpip.PacketBuffer{
				Data: hdr.View().ToVectorisedView(),
			})

			stat := test.getStat(s.Stats().ICMP.V6PacketsReceived)
			if got := stat.Value(); got != 1 {
				t.Fatalf("got stat = %d, want = 1", got)
			}

			// Wait for DAD to fail and make sure the address did
			// not get resolved.
			select {
			case <-time.After(time.Duration(ndpConfigs.DupAddrDetectTransmits)*ndpConfigs.RetransmitTimer + time.Second):
				// If we don't get a failure event after the
				// expected resolution time + extra 1s buffer,
				// something is wrong.
				t.Fatal("timed out waiting for DAD failure")
			case e := <-ndpDisp.dadC:
				if diff := checkDADEvent(e, nicID, addr1, false, nil); diff != "" {
					t.Errorf("dad event mismatch (-want +got):\n%s", diff)
				}
			}
			addr, err = s.GetMainNICAddress(nicID, header.IPv6ProtocolNumber)
			if err != nil {
				t.Fatalf("got stack.GetMainNICAddress(%d, %d) = (_, %v), want = (_, nil)", nicID, header.IPv6ProtocolNumber, err)
			}
			if want := (tcpip.AddressWithPrefix{}); addr != want {
				t.Fatalf("got stack.GetMainNICAddress(%d, %d) = (%s, nil), want = (%s, nil)", nicID, header.IPv6ProtocolNumber, addr, want)
			}
		})
	}
}

// TestDADStop tests to make sure that the DAD process stops when an address is
// removed.
func TestDADStop(t *testing.T) {
	const nicID = 1

	ndpDisp := ndpDispatcher{
		dadC: make(chan ndpDADEvent, 1),
	}
	ndpConfigs := stack.NDPConfigurations{
		RetransmitTimer:        time.Second,
		DupAddrDetectTransmits: 2,
	}
	opts := stack.Options{
		NetworkProtocols: []stack.NetworkProtocol{ipv6.NewProtocol()},
		NDPDisp:          &ndpDisp,
		NDPConfigs:       ndpConfigs,
	}

	e := channel.New(0, 1280, linkAddr1)
	s := stack.New(opts)
	if err := s.CreateNIC(nicID, e); err != nil {
		t.Fatalf("CreateNIC(%d, _) = %s", nicID, err)
	}

	if err := s.AddAddress(nicID, header.IPv6ProtocolNumber, addr1); err != nil {
		t.Fatalf("AddAddress(%d, %d, %s) = %s", nicID, header.IPv6ProtocolNumber, addr1, err)
	}

	// Address should not be considered bound to the NIC yet (DAD ongoing).
	addr, err := s.GetMainNICAddress(nicID, header.IPv6ProtocolNumber)
	if err != nil {
		t.Fatalf("got stack.GetMainNICAddress(%d, %d) = (_, %v), want = (_, nil)", nicID, header.IPv6ProtocolNumber, err)
	}
	if want := (tcpip.AddressWithPrefix{}); addr != want {
		t.Fatalf("got stack.GetMainNICAddress(%d, %d) = (%s, nil), want = (%s, nil)", nicID, header.IPv6ProtocolNumber, addr, want)
	}

	// Remove the address. This should stop DAD.
	if err := s.RemoveAddress(nicID, addr1); err != nil {
		t.Fatalf("RemoveAddress(%d, %s) = %s", nicID, addr1, err)
	}

	// Wait for DAD to fail (since the address was removed during DAD).
	select {
	case <-time.After(time.Duration(ndpConfigs.DupAddrDetectTransmits)*ndpConfigs.RetransmitTimer + time.Second):
		// If we don't get a failure event after the expected resolution
		// time + extra 1s buffer, something is wrong.
		t.Fatal("timed out waiting for DAD failure")
	case e := <-ndpDisp.dadC:
		if diff := checkDADEvent(e, nicID, addr1, false, nil); diff != "" {
			t.Errorf("dad event mismatch (-want +got):\n%s", diff)
		}
	}
	addr, err = s.GetMainNICAddress(nicID, header.IPv6ProtocolNumber)
	if err != nil {
		t.Fatalf("got stack.GetMainNICAddress(%d, %d) = (_, %v), want = (_, nil)", nicID, header.IPv6ProtocolNumber, err)
	}
	if want := (tcpip.AddressWithPrefix{}); addr != want {
		t.Fatalf("got stack.GetMainNICAddress(%d, %d) = (%s, nil), want = (%s, nil)", nicID, header.IPv6ProtocolNumber, addr, want)
	}

	// Should not have sent more than 1 NS message.
	if got := s.Stats().ICMP.V6PacketsSent.NeighborSolicit.Value(); got > 1 {
		t.Fatalf("got NeighborSolicit = %d, want <= 1", got)
	}
}

// TestSetNDPConfigurationFailsForBadNICID tests to make sure we get an error if
// we attempt to update NDP configurations using an invalid NICID.
func TestSetNDPConfigurationFailsForBadNICID(t *testing.T) {
	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocol{ipv6.NewProtocol()},
	})

	// No NIC with ID 1 yet.
	if got := s.SetNDPConfigurations(1, stack.NDPConfigurations{}); got != tcpip.ErrUnknownNICID {
		t.Fatalf("got s.SetNDPConfigurations = %v, want = %s", got, tcpip.ErrUnknownNICID)
	}
}

// TestSetNDPConfigurations tests that we can update and use per-interface NDP
// configurations without affecting the default NDP configurations or other
// interfaces' configurations.
func TestSetNDPConfigurations(t *testing.T) {
	const nicID1 = 1
	const nicID2 = 2
	const nicID3 = 3

	tests := []struct {
		name                    string
		dupAddrDetectTransmits  uint8
		retransmitTimer         time.Duration
		expectedRetransmitTimer time.Duration
	}{
		{
			"OK",
			1,
			time.Second,
			time.Second,
		},
		{
			"Invalid Retransmit Timer",
			1,
			0,
			time.Second,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ndpDisp := ndpDispatcher{
				dadC: make(chan ndpDADEvent, 1),
			}
			e := channel.New(0, 1280, linkAddr1)
			s := stack.New(stack.Options{
				NetworkProtocols: []stack.NetworkProtocol{ipv6.NewProtocol()},
				NDPDisp:          &ndpDisp,
			})

			expectDADEvent := func(nicID tcpip.NICID, addr tcpip.Address) {
				select {
				case e := <-ndpDisp.dadC:
					if diff := checkDADEvent(e, nicID, addr, true, nil); diff != "" {
						t.Errorf("dad event mismatch (-want +got):\n%s", diff)
					}
				default:
					t.Fatalf("expected DAD event for %s", addr)
				}
			}

			// This NIC(1)'s NDP configurations will be updated to
			// be different from the default.
			if err := s.CreateNIC(nicID1, e); err != nil {
				t.Fatalf("CreateNIC(%d, _) = %s", nicID1, err)
			}

			// Created before updating NIC(1)'s NDP configurations
			// but updating NIC(1)'s NDP configurations should not
			// affect other existing NICs.
			if err := s.CreateNIC(nicID2, e); err != nil {
				t.Fatalf("CreateNIC(%d, _) = %s", nicID2, err)
			}

			// Update the NDP configurations on NIC(1) to use DAD.
			configs := stack.NDPConfigurations{
				DupAddrDetectTransmits: test.dupAddrDetectTransmits,
				RetransmitTimer:        test.retransmitTimer,
			}
			if err := s.SetNDPConfigurations(nicID1, configs); err != nil {
				t.Fatalf("got SetNDPConfigurations(%d, _) = %s", nicID1, err)
			}

			// Created after updating NIC(1)'s NDP configurations
			// but the stack's default NDP configurations should not
			// have been updated.
			if err := s.CreateNIC(nicID3, e); err != nil {
				t.Fatalf("CreateNIC(%d, _) = %s", nicID3, err)
			}

			// Add addresses for each NIC.
			if err := s.AddAddress(nicID1, header.IPv6ProtocolNumber, addr1); err != nil {
				t.Fatalf("AddAddress(%d, %d, %s) = %s", nicID1, header.IPv6ProtocolNumber, addr1, err)
			}
			if err := s.AddAddress(nicID2, header.IPv6ProtocolNumber, addr2); err != nil {
				t.Fatalf("AddAddress(%d, %d, %s) = %s", nicID2, header.IPv6ProtocolNumber, addr2, err)
			}
			expectDADEvent(nicID2, addr2)
			if err := s.AddAddress(nicID3, header.IPv6ProtocolNumber, addr3); err != nil {
				t.Fatalf("AddAddress(%d, %d, %s) = %s", nicID3, header.IPv6ProtocolNumber, addr3, err)
			}
			expectDADEvent(nicID3, addr3)

			// Address should not be considered bound to NIC(1) yet
			// (DAD ongoing).
			addr, err := s.GetMainNICAddress(nicID1, header.IPv6ProtocolNumber)
			if err != nil {
				t.Fatalf("got stack.GetMainNICAddress(%d, %d) = (_, %v), want = (_, nil)", nicID1, header.IPv6ProtocolNumber, err)
			}
			if want := (tcpip.AddressWithPrefix{}); addr != want {
				t.Fatalf("got stack.GetMainNICAddress(%d, %d) = (%s, nil), want = (%s, nil)", nicID1, header.IPv6ProtocolNumber, addr, want)
			}

			// Should get the address on NIC(2) and NIC(3)
			// immediately since we should not have performed DAD on
			// it as the stack was configured to not do DAD by
			// default and we only updated the NDP configurations on
			// NIC(1).
			addr, err = s.GetMainNICAddress(nicID2, header.IPv6ProtocolNumber)
			if err != nil {
				t.Fatalf("got stack.GetMainNICAddress(%d, %d) = (_, %v), want = (_, nil)", nicID2, header.IPv6ProtocolNumber, err)
			}
			if addr.Address != addr2 {
				t.Fatalf("got stack.GetMainNICAddress(%d, %d) = %s, want = %s", nicID2, header.IPv6ProtocolNumber, addr, addr2)
			}
			addr, err = s.GetMainNICAddress(nicID3, header.IPv6ProtocolNumber)
			if err != nil {
				t.Fatalf("got stack.GetMainNICAddress(%d, %d) = (_, %v), want = (_, nil)", nicID3, header.IPv6ProtocolNumber, err)
			}
			if addr.Address != addr3 {
				t.Fatalf("got stack.GetMainNICAddress(%d, %d) = %s, want = %s", nicID3, header.IPv6ProtocolNumber, addr, addr3)
			}

			// Sleep until right (500ms before) before resolution to
			// make sure the address didn't resolve on NIC(1) yet.
			const delta = 500 * time.Millisecond
			time.Sleep(time.Duration(test.dupAddrDetectTransmits)*test.expectedRetransmitTimer - delta)
			addr, err = s.GetMainNICAddress(nicID1, header.IPv6ProtocolNumber)
			if err != nil {
				t.Fatalf("got stack.GetMainNICAddress(%d, %d) = (_, %v), want = (_, nil)", nicID1, header.IPv6ProtocolNumber, err)
			}
			if want := (tcpip.AddressWithPrefix{}); addr != want {
				t.Fatalf("got stack.GetMainNICAddress(%d, %d) = (%s, nil), want = (%s, nil)", nicID1, header.IPv6ProtocolNumber, addr, want)
			}

			// Wait for DAD to resolve.
			select {
			case <-time.After(2 * delta):
				// We should get a resolution event after 500ms
				// (delta) since we wait for 500ms less than the
				// expected resolution time above to make sure
				// that the address did not yet resolve. Waiting
				// for 1s (2x delta) without a resolution event
				// means something is wrong.
				t.Fatal("timed out waiting for DAD resolution")
			case e := <-ndpDisp.dadC:
				if diff := checkDADEvent(e, nicID1, addr1, true, nil); diff != "" {
					t.Errorf("dad event mismatch (-want +got):\n%s", diff)
				}
			}
			addr, err = s.GetMainNICAddress(nicID1, header.IPv6ProtocolNumber)
			if err != nil {
				t.Fatalf("got stack.GetMainNICAddress(%d, %d) = (_, %v), want = (_, nil)", nicID1, header.IPv6ProtocolNumber, err)
			}
			if addr.Address != addr1 {
				t.Fatalf("got stack.GetMainNICAddress(%d, %d) = %s, want = %s", nicID1, header.IPv6ProtocolNumber, addr, addr1)
			}
		})
	}
}

// raBufWithOptsAndDHCPv6 returns a valid NDP Router Advertisement with options
// and DHCPv6 configurations specified.
func raBufWithOptsAndDHCPv6(ip tcpip.Address, rl uint16, managedAddress, otherConfigurations bool, optSer header.NDPOptionsSerializer) tcpip.PacketBuffer {
	icmpSize := header.ICMPv6HeaderSize + header.NDPRAMinimumSize + int(optSer.Length())
	hdr := buffer.NewPrependable(header.IPv6MinimumSize + icmpSize)
	pkt := header.ICMPv6(hdr.Prepend(icmpSize))
	pkt.SetType(header.ICMPv6RouterAdvert)
	pkt.SetCode(0)
	raPayload := pkt.NDPPayload()
	ra := header.NDPRouterAdvert(raPayload)
	// Populate the Router Lifetime.
	binary.BigEndian.PutUint16(raPayload[2:], rl)
	// Populate the Managed Address flag field.
	if managedAddress {
		// The Managed Addresses flag field is the 7th bit of byte #1 (0-indexing)
		// of the RA payload.
		raPayload[1] |= (1 << 7)
	}
	// Populate the Other Configurations flag field.
	if otherConfigurations {
		// The Other Configurations flag field is the 6th bit of byte #1
		// (0-indexing) of the RA payload.
		raPayload[1] |= (1 << 6)
	}
	opts := ra.Options()
	opts.Serialize(optSer)
	pkt.SetChecksum(header.ICMPv6Checksum(pkt, ip, header.IPv6AllNodesMulticastAddress, buffer.VectorisedView{}))
	payloadLength := hdr.UsedLength()
	iph := header.IPv6(hdr.Prepend(header.IPv6MinimumSize))
	iph.Encode(&header.IPv6Fields{
		PayloadLength: uint16(payloadLength),
		NextHeader:    uint8(icmp.ProtocolNumber6),
		HopLimit:      header.NDPHopLimit,
		SrcAddr:       ip,
		DstAddr:       header.IPv6AllNodesMulticastAddress,
	})

	return tcpip.PacketBuffer{Data: hdr.View().ToVectorisedView()}
}

// raBufWithOpts returns a valid NDP Router Advertisement with options.
//
// Note, raBufWithOpts does not populate any of the RA fields other than the
// Router Lifetime.
func raBufWithOpts(ip tcpip.Address, rl uint16, optSer header.NDPOptionsSerializer) tcpip.PacketBuffer {
	return raBufWithOptsAndDHCPv6(ip, rl, false, false, optSer)
}

// raBufWithDHCPv6 returns a valid NDP Router Advertisement with DHCPv6 related
// fields set.
//
// Note, raBufWithDHCPv6 does not populate any of the RA fields other than the
// DHCPv6 related ones.
func raBufWithDHCPv6(ip tcpip.Address, managedAddresses, otherConfiguratiosns bool) tcpip.PacketBuffer {
	return raBufWithOptsAndDHCPv6(ip, 0, managedAddresses, otherConfiguratiosns, header.NDPOptionsSerializer{})
}

// raBuf returns a valid NDP Router Advertisement.
//
// Note, raBuf does not populate any of the RA fields other than the
// Router Lifetime.
func raBuf(ip tcpip.Address, rl uint16) tcpip.PacketBuffer {
	return raBufWithOpts(ip, rl, header.NDPOptionsSerializer{})
}

// raBufWithPI returns a valid NDP Router Advertisement with a single Prefix
// Information option.
//
// Note, raBufWithPI does not populate any of the RA fields other than the
// Router Lifetime.
func raBufWithPI(ip tcpip.Address, rl uint16, prefix tcpip.AddressWithPrefix, onLink, auto bool, vl, pl uint32) tcpip.PacketBuffer {
	flags := uint8(0)
	if onLink {
		// The OnLink flag is the 7th bit in the flags byte.
		flags |= 1 << 7
	}
	if auto {
		// The Address Auto-Configuration flag is the 6th bit in the
		// flags byte.
		flags |= 1 << 6
	}

	// A valid header.NDPPrefixInformation must be 30 bytes.
	buf := [30]byte{}
	// The first byte in a header.NDPPrefixInformation is the Prefix Length
	// field.
	buf[0] = uint8(prefix.PrefixLen)
	// The 2nd byte within a header.NDPPrefixInformation is the Flags field.
	buf[1] = flags
	// The Valid Lifetime field starts after the 2nd byte within a
	// header.NDPPrefixInformation.
	binary.BigEndian.PutUint32(buf[2:], vl)
	// The Preferred Lifetime field starts after the 6th byte within a
	// header.NDPPrefixInformation.
	binary.BigEndian.PutUint32(buf[6:], pl)
	// The Prefix Address field starts after the 14th byte within a
	// header.NDPPrefixInformation.
	copy(buf[14:], prefix.Address)
	return raBufWithOpts(ip, rl, header.NDPOptionsSerializer{
		header.NDPPrefixInformation(buf[:]),
	})
}

// TestNoRouterDiscovery tests that router discovery will not be performed if
// configured not to.
func TestNoRouterDiscovery(t *testing.T) {
	// Being configured to discover routers means handle and
	// discover are set to true and forwarding is set to false.
	// This tests all possible combinations of the configurations,
	// except for the configuration where handle = true, discover =
	// true and forwarding = false (the required configuration to do
	// router discovery) - that will done in other tests.
	for i := 0; i < 7; i++ {
		handle := i&1 != 0
		discover := i&2 != 0
		forwarding := i&4 == 0

		t.Run(fmt.Sprintf("HandleRAs(%t), DiscoverDefaultRouters(%t), Forwarding(%t)", handle, discover, forwarding), func(t *testing.T) {
			t.Parallel()

			ndpDisp := ndpDispatcher{
				routerC: make(chan ndpRouterEvent, 1),
			}
			e := channel.New(0, 1280, linkAddr1)
			s := stack.New(stack.Options{
				NetworkProtocols: []stack.NetworkProtocol{ipv6.NewProtocol()},
				NDPConfigs: stack.NDPConfigurations{
					HandleRAs:              handle,
					DiscoverDefaultRouters: discover,
				},
				NDPDisp: &ndpDisp,
			})
			s.SetForwarding(forwarding)

			if err := s.CreateNIC(1, e); err != nil {
				t.Fatalf("CreateNIC(1) = %s", err)
			}

			// Rx an RA with non-zero lifetime.
			e.InjectInbound(header.IPv6ProtocolNumber, raBuf(llAddr2, 1000))
			select {
			case <-ndpDisp.routerC:
				t.Fatal("unexpectedly discovered a router when configured not to")
			default:
			}
		})
	}
}

// Check e to make sure that the event is for addr on nic with ID 1, and the
// discovered flag set to discovered.
func checkRouterEvent(e ndpRouterEvent, addr tcpip.Address, discovered bool) string {
	return cmp.Diff(ndpRouterEvent{nicID: 1, addr: addr, discovered: discovered}, e, cmp.AllowUnexported(e))
}

// TestRouterDiscoveryDispatcherNoRemember tests that the stack does not
// remember a discovered router when the dispatcher asks it not to.
func TestRouterDiscoveryDispatcherNoRemember(t *testing.T) {
	t.Parallel()

	ndpDisp := ndpDispatcher{
		routerC: make(chan ndpRouterEvent, 1),
	}
	e := channel.New(0, 1280, linkAddr1)
	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocol{ipv6.NewProtocol()},
		NDPConfigs: stack.NDPConfigurations{
			HandleRAs:              true,
			DiscoverDefaultRouters: true,
		},
		NDPDisp: &ndpDisp,
	})

	if err := s.CreateNIC(1, e); err != nil {
		t.Fatalf("CreateNIC(1) = %s", err)
	}

	// Receive an RA for a router we should not remember.
	const lifetimeSeconds = 1
	e.InjectInbound(header.IPv6ProtocolNumber, raBuf(llAddr2, lifetimeSeconds))
	select {
	case e := <-ndpDisp.routerC:
		if diff := checkRouterEvent(e, llAddr2, true); diff != "" {
			t.Errorf("router event mismatch (-want +got):\n%s", diff)
		}
	default:
		t.Fatal("expected router discovery event")
	}

	// Wait for the invalidation time plus some buffer to make sure we do
	// not actually receive any invalidation events as we should not have
	// remembered the router in the first place.
	select {
	case <-ndpDisp.routerC:
		t.Fatal("should not have received any router events")
	case <-time.After(lifetimeSeconds*time.Second + defaultTimeout):
	}
}

func TestRouterDiscovery(t *testing.T) {
	t.Parallel()

	ndpDisp := ndpDispatcher{
		routerC:        make(chan ndpRouterEvent, 1),
		rememberRouter: true,
	}
	e := channel.New(0, 1280, linkAddr1)
	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocol{ipv6.NewProtocol()},
		NDPConfigs: stack.NDPConfigurations{
			HandleRAs:              true,
			DiscoverDefaultRouters: true,
		},
		NDPDisp: &ndpDisp,
	})

	expectRouterEvent := func(addr tcpip.Address, discovered bool) {
		t.Helper()

		select {
		case e := <-ndpDisp.routerC:
			if diff := checkRouterEvent(e, addr, discovered); diff != "" {
				t.Errorf("router event mismatch (-want +got):\n%s", diff)
			}
		default:
			t.Fatal("expected router discovery event")
		}
	}

	expectAsyncRouterInvalidationEvent := func(addr tcpip.Address, timeout time.Duration) {
		t.Helper()

		select {
		case e := <-ndpDisp.routerC:
			if diff := checkRouterEvent(e, addr, false); diff != "" {
				t.Errorf("router event mismatch (-want +got):\n%s", diff)
			}
		case <-time.After(timeout):
			t.Fatal("timed out waiting for router discovery event")
		}
	}

	if err := s.CreateNIC(1, e); err != nil {
		t.Fatalf("CreateNIC(1) = %s", err)
	}

	// Rx an RA from lladdr2 with zero lifetime. It should not be
	// remembered.
	e.InjectInbound(header.IPv6ProtocolNumber, raBuf(llAddr2, 0))
	select {
	case <-ndpDisp.routerC:
		t.Fatal("unexpectedly discovered a router with 0 lifetime")
	default:
	}

	// Rx an RA from lladdr2 with a huge lifetime.
	e.InjectInbound(header.IPv6ProtocolNumber, raBuf(llAddr2, 1000))
	expectRouterEvent(llAddr2, true)

	// Rx an RA from another router (lladdr3) with non-zero lifetime.
	const l3LifetimeSeconds = 6
	e.InjectInbound(header.IPv6ProtocolNumber, raBuf(llAddr3, l3LifetimeSeconds))
	expectRouterEvent(llAddr3, true)

	// Rx an RA from lladdr2 with lesser lifetime.
	const l2LifetimeSeconds = 2
	e.InjectInbound(header.IPv6ProtocolNumber, raBuf(llAddr2, l2LifetimeSeconds))
	select {
	case <-ndpDisp.routerC:
		t.Fatal("Should not receive a router event when updating lifetimes for known routers")
	default:
	}

	// Wait for lladdr2's router invalidation timer to fire. The lifetime
	// of the router should have been updated to the most recent (smaller)
	// lifetime.
	//
	// Wait for the normal lifetime plus an extra bit for the
	// router to get invalidated. If we don't get an invalidation
	// event after this time, then something is wrong.
	expectAsyncRouterInvalidationEvent(llAddr2, l2LifetimeSeconds*time.Second+defaultAsyncEventTimeout)

	// Rx an RA from lladdr2 with huge lifetime.
	e.InjectInbound(header.IPv6ProtocolNumber, raBuf(llAddr2, 1000))
	expectRouterEvent(llAddr2, true)

	// Rx an RA from lladdr2 with zero lifetime. It should be invalidated.
	e.InjectInbound(header.IPv6ProtocolNumber, raBuf(llAddr2, 0))
	expectRouterEvent(llAddr2, false)

	// Wait for lladdr3's router invalidation timer to fire. The lifetime
	// of the router should have been updated to the most recent (smaller)
	// lifetime.
	//
	// Wait for the normal lifetime plus an extra bit for the
	// router to get invalidated. If we don't get an invalidation
	// event after this time, then something is wrong.
	expectAsyncRouterInvalidationEvent(llAddr3, l3LifetimeSeconds*time.Second+defaultAsyncEventTimeout)
}

// TestRouterDiscoveryMaxRouters tests that only
// stack.MaxDiscoveredDefaultRouters discovered routers are remembered.
func TestRouterDiscoveryMaxRouters(t *testing.T) {
	t.Parallel()

	ndpDisp := ndpDispatcher{
		routerC:        make(chan ndpRouterEvent, 1),
		rememberRouter: true,
	}
	e := channel.New(0, 1280, linkAddr1)
	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocol{ipv6.NewProtocol()},
		NDPConfigs: stack.NDPConfigurations{
			HandleRAs:              true,
			DiscoverDefaultRouters: true,
		},
		NDPDisp: &ndpDisp,
	})

	if err := s.CreateNIC(1, e); err != nil {
		t.Fatalf("CreateNIC(1) = %s", err)
	}

	// Receive an RA from 2 more than the max number of discovered routers.
	for i := 1; i <= stack.MaxDiscoveredDefaultRouters+2; i++ {
		linkAddr := []byte{2, 2, 3, 4, 5, 0}
		linkAddr[5] = byte(i)
		llAddr := header.LinkLocalAddr(tcpip.LinkAddress(linkAddr))

		e.InjectInbound(header.IPv6ProtocolNumber, raBuf(llAddr, 5))

		if i <= stack.MaxDiscoveredDefaultRouters {
			select {
			case e := <-ndpDisp.routerC:
				if diff := checkRouterEvent(e, llAddr, true); diff != "" {
					t.Errorf("router event mismatch (-want +got):\n%s", diff)
				}
			default:
				t.Fatal("expected router discovery event")
			}

		} else {
			select {
			case <-ndpDisp.routerC:
				t.Fatal("should not have discovered a new router after we already discovered the max number of routers")
			default:
			}
		}
	}
}

// TestNoPrefixDiscovery tests that prefix discovery will not be performed if
// configured not to.
func TestNoPrefixDiscovery(t *testing.T) {
	prefix := tcpip.AddressWithPrefix{
		Address:   tcpip.Address("\x01\x02\x03\x04\x05\x06\x07\x08\x00\x00\x00\x00\x00\x00\x00\x00"),
		PrefixLen: 64,
	}

	// Being configured to discover prefixes means handle and
	// discover are set to true and forwarding is set to false.
	// This tests all possible combinations of the configurations,
	// except for the configuration where handle = true, discover =
	// true and forwarding = false (the required configuration to do
	// prefix discovery) - that will done in other tests.
	for i := 0; i < 7; i++ {
		handle := i&1 != 0
		discover := i&2 != 0
		forwarding := i&4 == 0

		t.Run(fmt.Sprintf("HandleRAs(%t), DiscoverOnLinkPrefixes(%t), Forwarding(%t)", handle, discover, forwarding), func(t *testing.T) {
			t.Parallel()

			ndpDisp := ndpDispatcher{
				prefixC: make(chan ndpPrefixEvent, 1),
			}
			e := channel.New(0, 1280, linkAddr1)
			s := stack.New(stack.Options{
				NetworkProtocols: []stack.NetworkProtocol{ipv6.NewProtocol()},
				NDPConfigs: stack.NDPConfigurations{
					HandleRAs:              handle,
					DiscoverOnLinkPrefixes: discover,
				},
				NDPDisp: &ndpDisp,
			})
			s.SetForwarding(forwarding)

			if err := s.CreateNIC(1, e); err != nil {
				t.Fatalf("CreateNIC(1) = %s", err)
			}

			// Rx an RA with prefix with non-zero lifetime.
			e.InjectInbound(header.IPv6ProtocolNumber, raBufWithPI(llAddr2, 0, prefix, true, false, 10, 0))

			select {
			case <-ndpDisp.prefixC:
				t.Fatal("unexpectedly discovered a prefix when configured not to")
			default:
			}
		})
	}
}

// Check e to make sure that the event is for prefix on nic with ID 1, and the
// discovered flag set to discovered.
func checkPrefixEvent(e ndpPrefixEvent, prefix tcpip.Subnet, discovered bool) string {
	return cmp.Diff(ndpPrefixEvent{nicID: 1, prefix: prefix, discovered: discovered}, e, cmp.AllowUnexported(e))
}

// TestPrefixDiscoveryDispatcherNoRemember tests that the stack does not
// remember a discovered on-link prefix when the dispatcher asks it not to.
func TestPrefixDiscoveryDispatcherNoRemember(t *testing.T) {
	t.Parallel()

	prefix, subnet, _ := prefixSubnetAddr(0, "")

	ndpDisp := ndpDispatcher{
		prefixC: make(chan ndpPrefixEvent, 1),
	}
	e := channel.New(0, 1280, linkAddr1)
	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocol{ipv6.NewProtocol()},
		NDPConfigs: stack.NDPConfigurations{
			HandleRAs:              true,
			DiscoverDefaultRouters: false,
			DiscoverOnLinkPrefixes: true,
		},
		NDPDisp: &ndpDisp,
	})

	if err := s.CreateNIC(1, e); err != nil {
		t.Fatalf("CreateNIC(1) = %s", err)
	}

	// Receive an RA with prefix that we should not remember.
	const lifetimeSeconds = 1
	e.InjectInbound(header.IPv6ProtocolNumber, raBufWithPI(llAddr2, 0, prefix, true, false, lifetimeSeconds, 0))
	select {
	case e := <-ndpDisp.prefixC:
		if diff := checkPrefixEvent(e, subnet, true); diff != "" {
			t.Errorf("prefix event mismatch (-want +got):\n%s", diff)
		}
	default:
		t.Fatal("expected prefix discovery event")
	}

	// Wait for the invalidation time plus some buffer to make sure we do
	// not actually receive any invalidation events as we should not have
	// remembered the prefix in the first place.
	select {
	case <-ndpDisp.prefixC:
		t.Fatal("should not have received any prefix events")
	case <-time.After(lifetimeSeconds*time.Second + defaultTimeout):
	}
}

func TestPrefixDiscovery(t *testing.T) {
	t.Parallel()

	prefix1, subnet1, _ := prefixSubnetAddr(0, "")
	prefix2, subnet2, _ := prefixSubnetAddr(1, "")
	prefix3, subnet3, _ := prefixSubnetAddr(2, "")

	ndpDisp := ndpDispatcher{
		prefixC:        make(chan ndpPrefixEvent, 1),
		rememberPrefix: true,
	}
	e := channel.New(0, 1280, linkAddr1)
	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocol{ipv6.NewProtocol()},
		NDPConfigs: stack.NDPConfigurations{
			HandleRAs:              true,
			DiscoverOnLinkPrefixes: true,
		},
		NDPDisp: &ndpDisp,
	})

	if err := s.CreateNIC(1, e); err != nil {
		t.Fatalf("CreateNIC(1) = %s", err)
	}

	expectPrefixEvent := func(prefix tcpip.Subnet, discovered bool) {
		t.Helper()

		select {
		case e := <-ndpDisp.prefixC:
			if diff := checkPrefixEvent(e, prefix, discovered); diff != "" {
				t.Errorf("prefix event mismatch (-want +got):\n%s", diff)
			}
		default:
			t.Fatal("expected prefix discovery event")
		}
	}

	// Receive an RA with prefix1 in an NDP Prefix Information option (PI)
	// with zero valid lifetime.
	e.InjectInbound(header.IPv6ProtocolNumber, raBufWithPI(llAddr2, 0, prefix1, true, false, 0, 0))
	select {
	case <-ndpDisp.prefixC:
		t.Fatal("unexpectedly discovered a prefix with 0 lifetime")
	default:
	}

	// Receive an RA with prefix1 in an NDP Prefix Information option (PI)
	// with non-zero lifetime.
	e.InjectInbound(header.IPv6ProtocolNumber, raBufWithPI(llAddr2, 0, prefix1, true, false, 100, 0))
	expectPrefixEvent(subnet1, true)

	// Receive an RA with prefix2 in a PI.
	e.InjectInbound(header.IPv6ProtocolNumber, raBufWithPI(llAddr2, 0, prefix2, true, false, 100, 0))
	expectPrefixEvent(subnet2, true)

	// Receive an RA with prefix3 in a PI.
	e.InjectInbound(header.IPv6ProtocolNumber, raBufWithPI(llAddr2, 0, prefix3, true, false, 100, 0))
	expectPrefixEvent(subnet3, true)

	// Receive an RA with prefix1 in a PI with lifetime = 0.
	e.InjectInbound(header.IPv6ProtocolNumber, raBufWithPI(llAddr2, 0, prefix1, true, false, 0, 0))
	expectPrefixEvent(subnet1, false)

	// Receive an RA with prefix2 in a PI with lesser lifetime.
	lifetime := uint32(2)
	e.InjectInbound(header.IPv6ProtocolNumber, raBufWithPI(llAddr2, 0, prefix2, true, false, lifetime, 0))
	select {
	case <-ndpDisp.prefixC:
		t.Fatal("unexpectedly received prefix event when updating lifetime")
	default:
	}

	// Wait for prefix2's most recent invalidation timer plus some buffer to
	// expire.
	select {
	case e := <-ndpDisp.prefixC:
		if diff := checkPrefixEvent(e, subnet2, false); diff != "" {
			t.Errorf("prefix event mismatch (-want +got):\n%s", diff)
		}
	case <-time.After(time.Duration(lifetime)*time.Second + defaultAsyncEventTimeout):
		t.Fatal("timed out waiting for prefix discovery event")
	}

	// Receive RA to invalidate prefix3.
	e.InjectInbound(header.IPv6ProtocolNumber, raBufWithPI(llAddr2, 0, prefix3, true, false, 0, 0))
	expectPrefixEvent(subnet3, false)
}

func TestPrefixDiscoveryWithInfiniteLifetime(t *testing.T) {
	// Update the infinite lifetime value to a smaller value so we can test
	// that when we receive a PI with such a lifetime value, we do not
	// invalidate the prefix.
	const testInfiniteLifetimeSeconds = 2
	const testInfiniteLifetime = testInfiniteLifetimeSeconds * time.Second
	saved := header.NDPInfiniteLifetime
	header.NDPInfiniteLifetime = testInfiniteLifetime
	defer func() {
		header.NDPInfiniteLifetime = saved
	}()

	prefix := tcpip.AddressWithPrefix{
		Address:   tcpip.Address("\x01\x02\x03\x04\x05\x06\x07\x08\x00\x00\x00\x00\x00\x00\x00\x00"),
		PrefixLen: 64,
	}
	subnet := prefix.Subnet()

	ndpDisp := ndpDispatcher{
		prefixC:        make(chan ndpPrefixEvent, 1),
		rememberPrefix: true,
	}
	e := channel.New(0, 1280, linkAddr1)
	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocol{ipv6.NewProtocol()},
		NDPConfigs: stack.NDPConfigurations{
			HandleRAs:              true,
			DiscoverOnLinkPrefixes: true,
		},
		NDPDisp: &ndpDisp,
	})

	if err := s.CreateNIC(1, e); err != nil {
		t.Fatalf("CreateNIC(1) = %s", err)
	}

	expectPrefixEvent := func(prefix tcpip.Subnet, discovered bool) {
		t.Helper()

		select {
		case e := <-ndpDisp.prefixC:
			if diff := checkPrefixEvent(e, prefix, discovered); diff != "" {
				t.Errorf("prefix event mismatch (-want +got):\n%s", diff)
			}
		default:
			t.Fatal("expected prefix discovery event")
		}
	}

	// Receive an RA with prefix in an NDP Prefix Information option (PI)
	// with infinite valid lifetime which should not get invalidated.
	e.InjectInbound(header.IPv6ProtocolNumber, raBufWithPI(llAddr2, 0, prefix, true, false, testInfiniteLifetimeSeconds, 0))
	expectPrefixEvent(subnet, true)
	select {
	case <-ndpDisp.prefixC:
		t.Fatal("unexpectedly invalidated a prefix with infinite lifetime")
	case <-time.After(testInfiniteLifetime + defaultTimeout):
	}

	// Receive an RA with finite lifetime.
	// The prefix should get invalidated after 1s.
	e.InjectInbound(header.IPv6ProtocolNumber, raBufWithPI(llAddr2, 0, prefix, true, false, testInfiniteLifetimeSeconds-1, 0))
	select {
	case e := <-ndpDisp.prefixC:
		if diff := checkPrefixEvent(e, subnet, false); diff != "" {
			t.Errorf("prefix event mismatch (-want +got):\n%s", diff)
		}
	case <-time.After(testInfiniteLifetime):
		t.Fatal("timed out waiting for prefix discovery event")
	}

	// Receive an RA with finite lifetime.
	e.InjectInbound(header.IPv6ProtocolNumber, raBufWithPI(llAddr2, 0, prefix, true, false, testInfiniteLifetimeSeconds-1, 0))
	expectPrefixEvent(subnet, true)

	// Receive an RA with prefix with an infinite lifetime.
	// The prefix should not be invalidated.
	e.InjectInbound(header.IPv6ProtocolNumber, raBufWithPI(llAddr2, 0, prefix, true, false, testInfiniteLifetimeSeconds, 0))
	select {
	case <-ndpDisp.prefixC:
		t.Fatal("unexpectedly invalidated a prefix with infinite lifetime")
	case <-time.After(testInfiniteLifetime + defaultTimeout):
	}

	// Receive an RA with a prefix with a lifetime value greater than the
	// set infinite lifetime value.
	e.InjectInbound(header.IPv6ProtocolNumber, raBufWithPI(llAddr2, 0, prefix, true, false, testInfiniteLifetimeSeconds+1, 0))
	select {
	case <-ndpDisp.prefixC:
		t.Fatal("unexpectedly invalidated a prefix with infinite lifetime")
	case <-time.After((testInfiniteLifetimeSeconds+1)*time.Second + defaultTimeout):
	}

	// Receive an RA with 0 lifetime.
	// The prefix should get invalidated.
	e.InjectInbound(header.IPv6ProtocolNumber, raBufWithPI(llAddr2, 0, prefix, true, false, 0, 0))
	expectPrefixEvent(subnet, false)
}

// TestPrefixDiscoveryMaxRouters tests that only
// stack.MaxDiscoveredOnLinkPrefixes discovered on-link prefixes are remembered.
func TestPrefixDiscoveryMaxOnLinkPrefixes(t *testing.T) {
	t.Parallel()

	ndpDisp := ndpDispatcher{
		prefixC:        make(chan ndpPrefixEvent, stack.MaxDiscoveredOnLinkPrefixes+3),
		rememberPrefix: true,
	}
	e := channel.New(0, 1280, linkAddr1)
	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocol{ipv6.NewProtocol()},
		NDPConfigs: stack.NDPConfigurations{
			HandleRAs:              true,
			DiscoverDefaultRouters: false,
			DiscoverOnLinkPrefixes: true,
		},
		NDPDisp: &ndpDisp,
	})

	if err := s.CreateNIC(1, e); err != nil {
		t.Fatalf("CreateNIC(1) = %s", err)
	}

	optSer := make(header.NDPOptionsSerializer, stack.MaxDiscoveredOnLinkPrefixes+2)
	prefixes := [stack.MaxDiscoveredOnLinkPrefixes + 2]tcpip.Subnet{}

	// Receive an RA with 2 more than the max number of discovered on-link
	// prefixes.
	for i := 0; i < stack.MaxDiscoveredOnLinkPrefixes+2; i++ {
		prefixAddr := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, 0, 0, 0, 0, 0}
		prefixAddr[7] = byte(i)
		prefix := tcpip.AddressWithPrefix{
			Address:   tcpip.Address(prefixAddr[:]),
			PrefixLen: 64,
		}
		prefixes[i] = prefix.Subnet()
		buf := [30]byte{}
		buf[0] = uint8(prefix.PrefixLen)
		buf[1] = 128
		binary.BigEndian.PutUint32(buf[2:], 10)
		copy(buf[14:], prefix.Address)

		optSer[i] = header.NDPPrefixInformation(buf[:])
	}

	e.InjectInbound(header.IPv6ProtocolNumber, raBufWithOpts(llAddr1, 0, optSer))
	for i := 0; i < stack.MaxDiscoveredOnLinkPrefixes+2; i++ {
		if i < stack.MaxDiscoveredOnLinkPrefixes {
			select {
			case e := <-ndpDisp.prefixC:
				if diff := checkPrefixEvent(e, prefixes[i], true); diff != "" {
					t.Errorf("prefix event mismatch (-want +got):\n%s", diff)
				}
			default:
				t.Fatal("expected prefix discovery event")
			}
		} else {
			select {
			case <-ndpDisp.prefixC:
				t.Fatal("should not have discovered a new prefix after we already discovered the max number of prefixes")
			default:
			}
		}
	}
}

// Checks to see if list contains an IPv6 address, item.
func containsV6Addr(list []tcpip.ProtocolAddress, item tcpip.AddressWithPrefix) bool {
	protocolAddress := tcpip.ProtocolAddress{
		Protocol:          header.IPv6ProtocolNumber,
		AddressWithPrefix: item,
	}

	for _, i := range list {
		if i == protocolAddress {
			return true
		}
	}

	return false
}

// TestNoAutoGenAddr tests that SLAAC is not performed when configured not to.
func TestNoAutoGenAddr(t *testing.T) {
	prefix, _, _ := prefixSubnetAddr(0, "")

	// Being configured to auto-generate addresses means handle and
	// autogen are set to true and forwarding is set to false.
	// This tests all possible combinations of the configurations,
	// except for the configuration where handle = true, autogen =
	// true and forwarding = false (the required configuration to do
	// SLAAC) - that will done in other tests.
	for i := 0; i < 7; i++ {
		handle := i&1 != 0
		autogen := i&2 != 0
		forwarding := i&4 == 0

		t.Run(fmt.Sprintf("HandleRAs(%t), AutoGenAddr(%t), Forwarding(%t)", handle, autogen, forwarding), func(t *testing.T) {
			t.Parallel()

			ndpDisp := ndpDispatcher{
				autoGenAddrC: make(chan ndpAutoGenAddrEvent, 1),
			}
			e := channel.New(0, 1280, linkAddr1)
			s := stack.New(stack.Options{
				NetworkProtocols: []stack.NetworkProtocol{ipv6.NewProtocol()},
				NDPConfigs: stack.NDPConfigurations{
					HandleRAs:              handle,
					AutoGenGlobalAddresses: autogen,
				},
				NDPDisp: &ndpDisp,
			})
			s.SetForwarding(forwarding)

			if err := s.CreateNIC(1, e); err != nil {
				t.Fatalf("CreateNIC(1) = %s", err)
			}

			// Rx an RA with prefix with non-zero lifetime.
			e.InjectInbound(header.IPv6ProtocolNumber, raBufWithPI(llAddr2, 0, prefix, false, true, 10, 0))

			select {
			case <-ndpDisp.autoGenAddrC:
				t.Fatal("unexpectedly auto-generated an address when configured not to")
			default:
			}
		})
	}
}

// Check e to make sure that the event is for addr on nic with ID 1, and the
// event type is set to eventType.
func checkAutoGenAddrEvent(e ndpAutoGenAddrEvent, addr tcpip.AddressWithPrefix, eventType ndpAutoGenAddrEventType) string {
	return cmp.Diff(ndpAutoGenAddrEvent{nicID: 1, addr: addr, eventType: eventType}, e, cmp.AllowUnexported(e))
}

// TestAutoGenAddr tests that an address is properly generated and invalidated
// when configured to do so.
func TestAutoGenAddr(t *testing.T) {
	const newMinVL = 2
	newMinVLDuration := newMinVL * time.Second
	saved := stack.MinPrefixInformationValidLifetimeForUpdate
	defer func() {
		stack.MinPrefixInformationValidLifetimeForUpdate = saved
	}()
	stack.MinPrefixInformationValidLifetimeForUpdate = newMinVLDuration

	prefix1, _, addr1 := prefixSubnetAddr(0, linkAddr1)
	prefix2, _, addr2 := prefixSubnetAddr(1, linkAddr1)

	ndpDisp := ndpDispatcher{
		autoGenAddrC: make(chan ndpAutoGenAddrEvent, 1),
	}
	e := channel.New(0, 1280, linkAddr1)
	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocol{ipv6.NewProtocol()},
		NDPConfigs: stack.NDPConfigurations{
			HandleRAs:              true,
			AutoGenGlobalAddresses: true,
		},
		NDPDisp: &ndpDisp,
	})

	if err := s.CreateNIC(1, e); err != nil {
		t.Fatalf("CreateNIC(1) = %s", err)
	}

	expectAutoGenAddrEvent := func(addr tcpip.AddressWithPrefix, eventType ndpAutoGenAddrEventType) {
		t.Helper()

		select {
		case e := <-ndpDisp.autoGenAddrC:
			if diff := checkAutoGenAddrEvent(e, addr, eventType); diff != "" {
				t.Errorf("auto-gen addr event mismatch (-want +got):\n%s", diff)
			}
		default:
			t.Fatal("expected addr auto gen event")
		}
	}

	// Receive an RA with prefix1 in an NDP Prefix Information option (PI)
	// with zero valid lifetime.
	e.InjectInbound(header.IPv6ProtocolNumber, raBufWithPI(llAddr2, 0, prefix1, true, true, 0, 0))
	select {
	case <-ndpDisp.autoGenAddrC:
		t.Fatal("unexpectedly auto-generated an address with 0 lifetime")
	default:
	}

	// Receive an RA with prefix1 in an NDP Prefix Information option (PI)
	// with non-zero lifetime.
	e.InjectInbound(header.IPv6ProtocolNumber, raBufWithPI(llAddr2, 0, prefix1, true, true, 100, 0))
	expectAutoGenAddrEvent(addr1, newAddr)
	if !containsV6Addr(s.NICInfo()[1].ProtocolAddresses, addr1) {
		t.Fatalf("Should have %s in the list of addresses", addr1)
	}

	// Receive an RA with prefix2 in an NDP Prefix Information option (PI)
	// with preferred lifetime > valid lifetime
	e.InjectInbound(header.IPv6ProtocolNumber, raBufWithPI(llAddr2, 0, prefix1, true, true, 5, 6))
	select {
	case <-ndpDisp.autoGenAddrC:
		t.Fatal("unexpectedly auto-generated an address with preferred lifetime > valid lifetime")
	default:
	}

	// Receive an RA with prefix2 in a PI.
	e.InjectInbound(header.IPv6ProtocolNumber, raBufWithPI(llAddr2, 0, prefix2, true, true, 100, 0))
	expectAutoGenAddrEvent(addr2, newAddr)
	if !containsV6Addr(s.NICInfo()[1].ProtocolAddresses, addr1) {
		t.Fatalf("Should have %s in the list of addresses", addr1)
	}
	if !containsV6Addr(s.NICInfo()[1].ProtocolAddresses, addr2) {
		t.Fatalf("Should have %s in the list of addresses", addr2)
	}

	// Refresh valid lifetime for addr of prefix1.
	e.InjectInbound(header.IPv6ProtocolNumber, raBufWithPI(llAddr2, 0, prefix1, true, true, newMinVL, 0))
	select {
	case <-ndpDisp.autoGenAddrC:
		t.Fatal("unexpectedly auto-generated an address when we already have an address for a prefix")
	default:
	}

	// Wait for addr of prefix1 to be invalidated.
	select {
	case e := <-ndpDisp.autoGenAddrC:
		if diff := checkAutoGenAddrEvent(e, addr1, invalidatedAddr); diff != "" {
			t.Errorf("auto-gen addr event mismatch (-want +got):\n%s", diff)
		}
	case <-time.After(newMinVLDuration + defaultAsyncEventTimeout):
		t.Fatal("timed out waiting for addr auto gen event")
	}
	if containsV6Addr(s.NICInfo()[1].ProtocolAddresses, addr1) {
		t.Fatalf("Should not have %s in the list of addresses", addr1)
	}
	if !containsV6Addr(s.NICInfo()[1].ProtocolAddresses, addr2) {
		t.Fatalf("Should have %s in the list of addresses", addr2)
	}
}

// stackAndNdpDispatcherWithDefaultRoute returns an ndpDispatcher,
// channel.Endpoint and stack.Stack.
//
// stack.Stack will have a default route through the router (llAddr3) installed
// and a static link-address (linkAddr3) added to the link address cache for the
// router.
func stackAndNdpDispatcherWithDefaultRoute(t *testing.T, nicID tcpip.NICID) (*ndpDispatcher, *channel.Endpoint, *stack.Stack) {
	t.Helper()
	ndpDisp := &ndpDispatcher{
		autoGenAddrC: make(chan ndpAutoGenAddrEvent, 1),
	}
	e := channel.New(0, 1280, linkAddr1)
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocol{ipv6.NewProtocol()},
		TransportProtocols: []stack.TransportProtocol{udp.NewProtocol()},
		NDPConfigs: stack.NDPConfigurations{
			HandleRAs:              true,
			AutoGenGlobalAddresses: true,
		},
		NDPDisp: ndpDisp,
	})
	if err := s.CreateNIC(nicID, e); err != nil {
		t.Fatalf("CreateNIC(%d, _) = %s", nicID, err)
	}
	s.SetRouteTable([]tcpip.Route{{
		Destination: header.IPv6EmptySubnet,
		Gateway:     llAddr3,
		NIC:         nicID,
	}})
	s.AddLinkAddress(nicID, llAddr3, linkAddr3)
	return ndpDisp, e, s
}

// addrForNewConnectionTo returns the local address used when creating a new
// connection to addr.
func addrForNewConnectionTo(t *testing.T, s *stack.Stack, addr tcpip.FullAddress) tcpip.Address {
	t.Helper()

	wq := waiter.Queue{}
	we, ch := waiter.NewChannelEntry(nil)
	wq.EventRegister(&we, waiter.EventIn)
	defer wq.EventUnregister(&we)
	defer close(ch)
	ep, err := s.NewEndpoint(header.UDPProtocolNumber, header.IPv6ProtocolNumber, &wq)
	if err != nil {
		t.Fatalf("s.NewEndpoint(%d, %d, _): %s", header.UDPProtocolNumber, header.IPv6ProtocolNumber, err)
	}
	defer ep.Close()
	if err := ep.SetSockOptBool(tcpip.V6OnlyOption, true); err != nil {
		t.Fatalf("SetSockOpt(tcpip.V6OnlyOption, true): %s", err)
	}
	if err := ep.Connect(addr); err != nil {
		t.Fatalf("ep.Connect(%+v): %s", addr, err)
	}
	got, err := ep.GetLocalAddress()
	if err != nil {
		t.Fatalf("ep.GetLocalAddress(): %s", err)
	}
	return got.Addr
}

// addrForNewConnection returns the local address used when creating a new
// connection.
func addrForNewConnection(t *testing.T, s *stack.Stack) tcpip.Address {
	t.Helper()

	return addrForNewConnectionTo(t, s, dstAddr)
}

// addrForNewConnectionWithAddr returns the local address used when creating a
// new connection with a specific local address.
func addrForNewConnectionWithAddr(t *testing.T, s *stack.Stack, addr tcpip.FullAddress) tcpip.Address {
	t.Helper()

	wq := waiter.Queue{}
	we, ch := waiter.NewChannelEntry(nil)
	wq.EventRegister(&we, waiter.EventIn)
	defer wq.EventUnregister(&we)
	defer close(ch)
	ep, err := s.NewEndpoint(header.UDPProtocolNumber, header.IPv6ProtocolNumber, &wq)
	if err != nil {
		t.Fatalf("s.NewEndpoint(%d, %d, _): %s", header.UDPProtocolNumber, header.IPv6ProtocolNumber, err)
	}
	defer ep.Close()
	if err := ep.SetSockOptBool(tcpip.V6OnlyOption, true); err != nil {
		t.Fatalf("SetSockOpt(tcpip.V6OnlyOption, true): %s", err)
	}
	if err := ep.Bind(addr); err != nil {
		t.Fatalf("ep.Bind(%+v): %s", addr, err)
	}
	if err := ep.Connect(dstAddr); err != nil {
		t.Fatalf("ep.Connect(%+v): %s", dstAddr, err)
	}
	got, err := ep.GetLocalAddress()
	if err != nil {
		t.Fatalf("ep.GetLocalAddress(): %s", err)
	}
	return got.Addr
}

// TestAutoGenAddrDeprecateFromPI tests deprecating a SLAAC address when
// receiving a PI with 0 preferred lifetime.
func TestAutoGenAddrDeprecateFromPI(t *testing.T) {
	const nicID = 1

	prefix1, _, addr1 := prefixSubnetAddr(0, linkAddr1)
	prefix2, _, addr2 := prefixSubnetAddr(1, linkAddr1)

	ndpDisp, e, s := stackAndNdpDispatcherWithDefaultRoute(t, nicID)

	expectAutoGenAddrEvent := func(addr tcpip.AddressWithPrefix, eventType ndpAutoGenAddrEventType) {
		t.Helper()

		select {
		case e := <-ndpDisp.autoGenAddrC:
			if diff := checkAutoGenAddrEvent(e, addr, eventType); diff != "" {
				t.Errorf("auto-gen addr event mismatch (-want +got):\n%s", diff)
			}
		default:
			t.Fatal("expected addr auto gen event")
		}
	}

	expectPrimaryAddr := func(addr tcpip.AddressWithPrefix) {
		t.Helper()

		if got, err := s.GetMainNICAddress(nicID, header.IPv6ProtocolNumber); err != nil {
			t.Fatalf("s.GetMainNICAddress(%d, %d): %s", nicID, header.IPv6ProtocolNumber, err)
		} else if got != addr {
			t.Errorf("got s.GetMainNICAddress(%d, %d) = %s, want = %s", nicID, header.IPv6ProtocolNumber, got, addr)
		}

		if got := addrForNewConnection(t, s); got != addr.Address {
			t.Errorf("got addrForNewConnection = %s, want = %s", got, addr.Address)
		}
	}

	// Receive PI for prefix1.
	e.InjectInbound(header.IPv6ProtocolNumber, raBufWithPI(llAddr2, 0, prefix1, true, true, 100, 100))
	expectAutoGenAddrEvent(addr1, newAddr)
	if !containsV6Addr(s.NICInfo()[nicID].ProtocolAddresses, addr1) {
		t.Fatalf("should have %s in the list of addresses", addr1)
	}
	expectPrimaryAddr(addr1)

	// Deprecate addr for prefix1 immedaitely.
	e.InjectInbound(header.IPv6ProtocolNumber, raBufWithPI(llAddr2, 0, prefix1, true, true, 100, 0))
	expectAutoGenAddrEvent(addr1, deprecatedAddr)
	if !containsV6Addr(s.NICInfo()[nicID].ProtocolAddresses, addr1) {
		t.Fatalf("should have %s in the list of addresses", addr1)
	}
	// addr should still be the primary endpoint as there are no other addresses.
	expectPrimaryAddr(addr1)

	// Refresh lifetimes of addr generated from prefix1.
	e.InjectInbound(header.IPv6ProtocolNumber, raBufWithPI(llAddr2, 0, prefix1, true, true, 100, 100))
	select {
	case <-ndpDisp.autoGenAddrC:
		t.Fatal("unexpectedly got an auto-generated event")
	default:
	}
	expectPrimaryAddr(addr1)

	// Receive PI for prefix2.
	e.InjectInbound(header.IPv6ProtocolNumber, raBufWithPI(llAddr2, 0, prefix2, true, true, 100, 100))
	expectAutoGenAddrEvent(addr2, newAddr)
	if !containsV6Addr(s.NICInfo()[nicID].ProtocolAddresses, addr2) {
		t.Fatalf("should have %s in the list of addresses", addr2)
	}
	expectPrimaryAddr(addr2)

	// Deprecate addr for prefix2 immedaitely.
	e.InjectInbound(header.IPv6ProtocolNumber, raBufWithPI(llAddr2, 0, prefix2, true, true, 100, 0))
	expectAutoGenAddrEvent(addr2, deprecatedAddr)
	if !containsV6Addr(s.NICInfo()[nicID].ProtocolAddresses, addr2) {
		t.Fatalf("should have %s in the list of addresses", addr2)
	}
	// addr1 should be the primary endpoint now since addr2 is deprecated but
	// addr1 is not.
	expectPrimaryAddr(addr1)
	// addr2 is deprecated but if explicitly requested, it should be used.
	fullAddr2 := tcpip.FullAddress{Addr: addr2.Address, NIC: nicID}
	if got := addrForNewConnectionWithAddr(t, s, fullAddr2); got != addr2.Address {
		t.Errorf("got addrForNewConnectionWithAddr(_, _, %+v) = %s, want = %s", got, addr2.Address)
	}

	// Another PI w/ 0 preferred lifetime should not result in a deprecation
	// event.
	e.InjectInbound(header.IPv6ProtocolNumber, raBufWithPI(llAddr2, 0, prefix2, true, true, 100, 0))
	select {
	case <-ndpDisp.autoGenAddrC:
		t.Fatal("unexpectedly got an auto-generated event")
	default:
	}
	expectPrimaryAddr(addr1)
	if got := addrForNewConnectionWithAddr(t, s, fullAddr2); got != addr2.Address {
		t.Errorf("got addrForNewConnectionWithAddr(_, _, %+v) = %s, want = %s", got, addr2.Address)
	}

	// Refresh lifetimes of addr generated from prefix2.
	e.InjectInbound(header.IPv6ProtocolNumber, raBufWithPI(llAddr2, 0, prefix2, true, true, 100, 100))
	select {
	case <-ndpDisp.autoGenAddrC:
		t.Fatal("unexpectedly got an auto-generated event")
	default:
	}
	expectPrimaryAddr(addr2)
}

// TestAutoGenAddrTimerDeprecation tests that an address is properly deprecated
// when its preferred lifetime expires.
func TestAutoGenAddrTimerDeprecation(t *testing.T) {
	const nicID = 1
	const newMinVL = 2
	newMinVLDuration := newMinVL * time.Second
	saved := stack.MinPrefixInformationValidLifetimeForUpdate
	defer func() {
		stack.MinPrefixInformationValidLifetimeForUpdate = saved
	}()
	stack.MinPrefixInformationValidLifetimeForUpdate = newMinVLDuration

	prefix1, _, addr1 := prefixSubnetAddr(0, linkAddr1)
	prefix2, _, addr2 := prefixSubnetAddr(1, linkAddr1)

	ndpDisp, e, s := stackAndNdpDispatcherWithDefaultRoute(t, nicID)

	expectAutoGenAddrEvent := func(addr tcpip.AddressWithPrefix, eventType ndpAutoGenAddrEventType) {
		t.Helper()

		select {
		case e := <-ndpDisp.autoGenAddrC:
			if diff := checkAutoGenAddrEvent(e, addr, eventType); diff != "" {
				t.Errorf("auto-gen addr event mismatch (-want +got):\n%s", diff)
			}
		default:
			t.Fatal("expected addr auto gen event")
		}
	}

	expectAutoGenAddrEventAfter := func(addr tcpip.AddressWithPrefix, eventType ndpAutoGenAddrEventType, timeout time.Duration) {
		t.Helper()

		select {
		case e := <-ndpDisp.autoGenAddrC:
			if diff := checkAutoGenAddrEvent(e, addr, eventType); diff != "" {
				t.Errorf("auto-gen addr event mismatch (-want +got):\n%s", diff)
			}
		case <-time.After(timeout):
			t.Fatal("timed out waiting for addr auto gen event")
		}
	}

	expectPrimaryAddr := func(addr tcpip.AddressWithPrefix) {
		t.Helper()

		if got, err := s.GetMainNICAddress(nicID, header.IPv6ProtocolNumber); err != nil {
			t.Fatalf("s.GetMainNICAddress(%d, %d): %s", nicID, header.IPv6ProtocolNumber, err)
		} else if got != addr {
			t.Errorf("got s.GetMainNICAddress(%d, %d) = %s, want = %s", nicID, header.IPv6ProtocolNumber, got, addr)
		}

		if got := addrForNewConnection(t, s); got != addr.Address {
			t.Errorf("got addrForNewConnection = %s, want = %s", got, addr.Address)
		}
	}

	// Receive PI for prefix2.
	e.InjectInbound(header.IPv6ProtocolNumber, raBufWithPI(llAddr2, 0, prefix2, true, true, 100, 100))
	expectAutoGenAddrEvent(addr2, newAddr)
	if !containsV6Addr(s.NICInfo()[nicID].ProtocolAddresses, addr2) {
		t.Fatalf("should have %s in the list of addresses", addr2)
	}
	expectPrimaryAddr(addr2)

	// Receive a PI for prefix1.
	e.InjectInbound(header.IPv6ProtocolNumber, raBufWithPI(llAddr2, 0, prefix1, true, true, 100, 90))
	expectAutoGenAddrEvent(addr1, newAddr)
	if !containsV6Addr(s.NICInfo()[nicID].ProtocolAddresses, addr1) {
		t.Fatalf("should have %s in the list of addresses", addr1)
	}
	if !containsV6Addr(s.NICInfo()[nicID].ProtocolAddresses, addr2) {
		t.Fatalf("should have %s in the list of addresses", addr2)
	}
	expectPrimaryAddr(addr1)

	// Refresh lifetime for addr of prefix1.
	e.InjectInbound(header.IPv6ProtocolNumber, raBufWithPI(llAddr2, 0, prefix1, true, true, newMinVL, newMinVL-1))
	select {
	case <-ndpDisp.autoGenAddrC:
		t.Fatal("unexpectedly got an auto-generated event")
	default:
	}
	expectPrimaryAddr(addr1)

	// Wait for addr of prefix1 to be deprecated.
	expectAutoGenAddrEventAfter(addr1, deprecatedAddr, newMinVLDuration-time.Second+defaultAsyncEventTimeout)
	if !containsV6Addr(s.NICInfo()[nicID].ProtocolAddresses, addr1) {
		t.Fatalf("should not have %s in the list of addresses", addr1)
	}
	if !containsV6Addr(s.NICInfo()[nicID].ProtocolAddresses, addr2) {
		t.Fatalf("should have %s in the list of addresses", addr2)
	}
	// addr2 should be the primary endpoint now since addr1 is deprecated but
	// addr2 is not.
	expectPrimaryAddr(addr2)
	// addr1 is deprecated but if explicitly requested, it should be used.
	fullAddr1 := tcpip.FullAddress{Addr: addr1.Address, NIC: nicID}
	if got := addrForNewConnectionWithAddr(t, s, fullAddr1); got != addr1.Address {
		t.Errorf("got addrForNewConnectionWithAddr(_, _, %+v) = %s, want = %s", got, addr1.Address)
	}

	// Refresh valid lifetime for addr of prefix1, w/ 0 preferred lifetime to make
	// sure we do not get a deprecation event again.
	e.InjectInbound(header.IPv6ProtocolNumber, raBufWithPI(llAddr2, 0, prefix1, true, true, newMinVL, 0))
	select {
	case <-ndpDisp.autoGenAddrC:
		t.Fatal("unexpectedly got an auto-generated event")
	default:
	}
	expectPrimaryAddr(addr2)
	if got := addrForNewConnectionWithAddr(t, s, fullAddr1); got != addr1.Address {
		t.Errorf("got addrForNewConnectionWithAddr(_, _, %+v) = %s, want = %s", got, addr1.Address)
	}

	// Refresh lifetimes for addr of prefix1.
	e.InjectInbound(header.IPv6ProtocolNumber, raBufWithPI(llAddr2, 0, prefix1, true, true, newMinVL, newMinVL-1))
	select {
	case <-ndpDisp.autoGenAddrC:
		t.Fatal("unexpectedly got an auto-generated event")
	default:
	}
	// addr1 is the primary endpoint again since it is non-deprecated now.
	expectPrimaryAddr(addr1)

	// Wait for addr of prefix1 to be deprecated.
	expectAutoGenAddrEventAfter(addr1, deprecatedAddr, newMinVLDuration-time.Second+defaultAsyncEventTimeout)
	if !containsV6Addr(s.NICInfo()[nicID].ProtocolAddresses, addr1) {
		t.Fatalf("should not have %s in the list of addresses", addr1)
	}
	if !containsV6Addr(s.NICInfo()[nicID].ProtocolAddresses, addr2) {
		t.Fatalf("should have %s in the list of addresses", addr2)
	}
	// addr2 should be the primary endpoint now since it is not deprecated.
	expectPrimaryAddr(addr2)
	if got := addrForNewConnectionWithAddr(t, s, fullAddr1); got != addr1.Address {
		t.Errorf("got addrForNewConnectionWithAddr(_, _, %+v) = %s, want = %s", got, addr1.Address)
	}

	// Wait for addr of prefix1 to be invalidated.
	expectAutoGenAddrEventAfter(addr1, invalidatedAddr, time.Second+defaultAsyncEventTimeout)
	if containsV6Addr(s.NICInfo()[nicID].ProtocolAddresses, addr1) {
		t.Fatalf("should not have %s in the list of addresses", addr1)
	}
	if !containsV6Addr(s.NICInfo()[nicID].ProtocolAddresses, addr2) {
		t.Fatalf("should have %s in the list of addresses", addr2)
	}
	expectPrimaryAddr(addr2)

	// Refresh both lifetimes for addr of prefix2 to the same value.
	e.InjectInbound(header.IPv6ProtocolNumber, raBufWithPI(llAddr2, 0, prefix2, true, true, newMinVL, newMinVL))
	select {
	case <-ndpDisp.autoGenAddrC:
		t.Fatal("unexpectedly got an auto-generated event")
	default:
	}

	// Wait for a deprecation then invalidation events, or just an invalidation
	// event. We need to cover both cases but cannot deterministically hit both
	// cases because the deprecation and invalidation handlers could be handled in
	// either deprecation then invalidation, or invalidation then deprecation
	// (which should be cancelled by the invalidation handler).
	select {
	case e := <-ndpDisp.autoGenAddrC:
		if diff := checkAutoGenAddrEvent(e, addr2, deprecatedAddr); diff == "" {
			// If we get a deprecation event first, we should get an invalidation
			// event almost immediately after.
			select {
			case e := <-ndpDisp.autoGenAddrC:
				if diff := checkAutoGenAddrEvent(e, addr2, invalidatedAddr); diff != "" {
					t.Errorf("auto-gen addr event mismatch (-want +got):\n%s", diff)
				}
			case <-time.After(defaultAsyncEventTimeout):
				t.Fatal("timed out waiting for addr auto gen event")
			}
		} else if diff := checkAutoGenAddrEvent(e, addr2, invalidatedAddr); diff == "" {
			// If we get an invalidation  event first, we should not get a deprecation
			// event after.
			select {
			case <-ndpDisp.autoGenAddrC:
				t.Fatal("unexpectedly got an auto-generated event")
			case <-time.After(defaultTimeout):
			}
		} else {
			t.Fatalf("got unexpected auto-generated event")
		}

	case <-time.After(newMinVLDuration + defaultAsyncEventTimeout):
		t.Fatal("timed out waiting for addr auto gen event")
	}
	if containsV6Addr(s.NICInfo()[nicID].ProtocolAddresses, addr1) {
		t.Fatalf("should not have %s in the list of addresses", addr1)
	}
	if containsV6Addr(s.NICInfo()[nicID].ProtocolAddresses, addr2) {
		t.Fatalf("should not have %s in the list of addresses", addr2)
	}
	// Should not have any primary endpoints.
	if got, err := s.GetMainNICAddress(nicID, header.IPv6ProtocolNumber); err != nil {
		t.Fatalf("s.GetMainNICAddress(%d, %d): %s", nicID, header.IPv6ProtocolNumber, err)
	} else if want := (tcpip.AddressWithPrefix{}); got != want {
		t.Errorf("got s.GetMainNICAddress(%d, %d) = %s, want = %s", nicID, header.IPv6ProtocolNumber, got, want)
	}
	wq := waiter.Queue{}
	we, ch := waiter.NewChannelEntry(nil)
	wq.EventRegister(&we, waiter.EventIn)
	defer wq.EventUnregister(&we)
	defer close(ch)
	ep, err := s.NewEndpoint(header.UDPProtocolNumber, header.IPv6ProtocolNumber, &wq)
	if err != nil {
		t.Fatalf("s.NewEndpoint(%d, %d, _): %s", header.UDPProtocolNumber, header.IPv6ProtocolNumber, err)
	}
	defer ep.Close()
	if err := ep.SetSockOptBool(tcpip.V6OnlyOption, true); err != nil {
		t.Fatalf("SetSockOpt(tcpip.V6OnlyOption, true): %s", err)
	}

	if err := ep.Connect(dstAddr); err != tcpip.ErrNoRoute {
		t.Errorf("got ep.Connect(%+v) = %v, want = %s", dstAddr, err, tcpip.ErrNoRoute)
	}
}

// Tests transitioning a SLAAC address's valid lifetime between finite and
// infinite values.
func TestAutoGenAddrFiniteToInfiniteToFiniteVL(t *testing.T) {
	const infiniteVLSeconds = 2
	const minVLSeconds = 1
	savedIL := header.NDPInfiniteLifetime
	savedMinVL := stack.MinPrefixInformationValidLifetimeForUpdate
	defer func() {
		stack.MinPrefixInformationValidLifetimeForUpdate = savedMinVL
		header.NDPInfiniteLifetime = savedIL
	}()
	stack.MinPrefixInformationValidLifetimeForUpdate = minVLSeconds * time.Second
	header.NDPInfiniteLifetime = infiniteVLSeconds * time.Second

	prefix, _, addr := prefixSubnetAddr(0, linkAddr1)

	tests := []struct {
		name       string
		infiniteVL uint32
	}{
		{
			name:       "EqualToInfiniteVL",
			infiniteVL: infiniteVLSeconds,
		},
		// Our implementation supports changing header.NDPInfiniteLifetime for tests
		// such that a packet can be received where the lifetime field has a value
		// greater than header.NDPInfiniteLifetime. Because of this, we test to make
		// sure that receiving a value greater than header.NDPInfiniteLifetime is
		// handled the same as when receiving a value equal to
		// header.NDPInfiniteLifetime.
		{
			name:       "MoreThanInfiniteVL",
			infiniteVL: infiniteVLSeconds + 1,
		},
	}

	// This Run will not return until the parallel tests finish.
	//
	// We need this because we need to do some teardown work after the
	// parallel tests complete.
	//
	// See https://godoc.org/testing#hdr-Subtests_and_Sub_benchmarks for
	// more details.
	t.Run("group", func(t *testing.T) {
		for _, test := range tests {
			test := test

			t.Run(test.name, func(t *testing.T) {
				t.Parallel()

				ndpDisp := ndpDispatcher{
					autoGenAddrC: make(chan ndpAutoGenAddrEvent, 1),
				}
				e := channel.New(0, 1280, linkAddr1)
				s := stack.New(stack.Options{
					NetworkProtocols: []stack.NetworkProtocol{ipv6.NewProtocol()},
					NDPConfigs: stack.NDPConfigurations{
						HandleRAs:              true,
						AutoGenGlobalAddresses: true,
					},
					NDPDisp: &ndpDisp,
				})

				if err := s.CreateNIC(1, e); err != nil {
					t.Fatalf("CreateNIC(1) = %s", err)
				}

				// Receive an RA with finite prefix.
				e.InjectInbound(header.IPv6ProtocolNumber, raBufWithPI(llAddr2, 0, prefix, true, true, minVLSeconds, 0))
				select {
				case e := <-ndpDisp.autoGenAddrC:
					if diff := checkAutoGenAddrEvent(e, addr, newAddr); diff != "" {
						t.Errorf("auto-gen addr event mismatch (-want +got):\n%s", diff)
					}

				default:
					t.Fatal("expected addr auto gen event")
				}

				// Receive an new RA with prefix with infinite VL.
				e.InjectInbound(header.IPv6ProtocolNumber, raBufWithPI(llAddr2, 0, prefix, true, true, test.infiniteVL, 0))

				// Receive a new RA with prefix with finite VL.
				e.InjectInbound(header.IPv6ProtocolNumber, raBufWithPI(llAddr2, 0, prefix, true, true, minVLSeconds, 0))

				select {
				case e := <-ndpDisp.autoGenAddrC:
					if diff := checkAutoGenAddrEvent(e, addr, invalidatedAddr); diff != "" {
						t.Errorf("auto-gen addr event mismatch (-want +got):\n%s", diff)
					}

				case <-time.After(minVLSeconds*time.Second + defaultAsyncEventTimeout):
					t.Fatal("timeout waiting for addr auto gen event")
				}
			})
		}
	})
}

// TestAutoGenAddrValidLifetimeUpdates tests that the valid lifetime of an
// auto-generated address only gets updated when required to, as specified in
// RFC 4862 section 5.5.3.e.
func TestAutoGenAddrValidLifetimeUpdates(t *testing.T) {
	const infiniteVL = 4294967295
	const newMinVL = 4
	saved := stack.MinPrefixInformationValidLifetimeForUpdate
	defer func() {
		stack.MinPrefixInformationValidLifetimeForUpdate = saved
	}()
	stack.MinPrefixInformationValidLifetimeForUpdate = newMinVL * time.Second

	prefix, _, addr := prefixSubnetAddr(0, linkAddr1)

	tests := []struct {
		name string
		ovl  uint32
		nvl  uint32
		evl  uint32
	}{
		// Should update the VL to the minimum VL for updating if the
		// new VL is less than newMinVL but was originally greater than
		// it.
		{
			"LargeVLToVLLessThanMinVLForUpdate",
			9999,
			1,
			newMinVL,
		},
		{
			"LargeVLTo0",
			9999,
			0,
			newMinVL,
		},
		{
			"InfiniteVLToVLLessThanMinVLForUpdate",
			infiniteVL,
			1,
			newMinVL,
		},
		{
			"InfiniteVLTo0",
			infiniteVL,
			0,
			newMinVL,
		},

		// Should not update VL if original VL was less than newMinVL
		// and the new VL is also less than newMinVL.
		{
			"ShouldNotUpdateWhenBothOldAndNewAreLessThanMinVLForUpdate",
			newMinVL - 1,
			newMinVL - 3,
			newMinVL - 1,
		},

		// Should take the new VL if the new VL is greater than the
		// remaining time or is greater than newMinVL.
		{
			"MorethanMinVLToLesserButStillMoreThanMinVLForUpdate",
			newMinVL + 5,
			newMinVL + 3,
			newMinVL + 3,
		},
		{
			"SmallVLToGreaterVLButStillLessThanMinVLForUpdate",
			newMinVL - 3,
			newMinVL - 1,
			newMinVL - 1,
		},
		{
			"SmallVLToGreaterVLThatIsMoreThaMinVLForUpdate",
			newMinVL - 3,
			newMinVL + 1,
			newMinVL + 1,
		},
	}

	const delta = 500 * time.Millisecond

	// This Run will not return until the parallel tests finish.
	//
	// We need this because we need to do some teardown work after the
	// parallel tests complete.
	//
	// See https://godoc.org/testing#hdr-Subtests_and_Sub_benchmarks for
	// more details.
	t.Run("group", func(t *testing.T) {
		for _, test := range tests {
			test := test

			t.Run(test.name, func(t *testing.T) {
				t.Parallel()

				ndpDisp := ndpDispatcher{
					autoGenAddrC: make(chan ndpAutoGenAddrEvent, 10),
				}
				e := channel.New(10, 1280, linkAddr1)
				s := stack.New(stack.Options{
					NetworkProtocols: []stack.NetworkProtocol{ipv6.NewProtocol()},
					NDPConfigs: stack.NDPConfigurations{
						HandleRAs:              true,
						AutoGenGlobalAddresses: true,
					},
					NDPDisp: &ndpDisp,
				})

				if err := s.CreateNIC(1, e); err != nil {
					t.Fatalf("CreateNIC(1) = %s", err)
				}

				// Receive an RA with prefix with initial VL,
				// test.ovl.
				e.InjectInbound(header.IPv6ProtocolNumber, raBufWithPI(llAddr2, 0, prefix, true, true, test.ovl, 0))
				select {
				case e := <-ndpDisp.autoGenAddrC:
					if diff := checkAutoGenAddrEvent(e, addr, newAddr); diff != "" {
						t.Errorf("auto-gen addr event mismatch (-want +got):\n%s", diff)
					}
				default:
					t.Fatal("expected addr auto gen event")
				}

				// Receive an new RA with prefix with new VL,
				// test.nvl.
				e.InjectInbound(header.IPv6ProtocolNumber, raBufWithPI(llAddr2, 0, prefix, true, true, test.nvl, 0))

				//
				// Validate that the VL for the address got set
				// to test.evl.
				//

				// Make sure we do not get any invalidation
				// events until atleast 500ms (delta) before
				// test.evl.
				select {
				case <-ndpDisp.autoGenAddrC:
					t.Fatal("unexpectedly received an auto gen addr event")
				case <-time.After(time.Duration(test.evl)*time.Second - delta):
				}

				// Wait for another second (2x delta), but now
				// we expect the invalidation event.
				select {
				case e := <-ndpDisp.autoGenAddrC:
					if diff := checkAutoGenAddrEvent(e, addr, invalidatedAddr); diff != "" {
						t.Errorf("auto-gen addr event mismatch (-want +got):\n%s", diff)
					}

				case <-time.After(2 * delta):
					t.Fatal("timeout waiting for addr auto gen event")
				}
			})
		}
	})
}

// TestAutoGenAddrRemoval tests that when auto-generated addresses are removed
// by the user, its resources will be cleaned up and an invalidation event will
// be sent to the integrator.
func TestAutoGenAddrRemoval(t *testing.T) {
	t.Parallel()

	prefix, _, addr := prefixSubnetAddr(0, linkAddr1)

	ndpDisp := ndpDispatcher{
		autoGenAddrC: make(chan ndpAutoGenAddrEvent, 1),
	}
	e := channel.New(0, 1280, linkAddr1)
	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocol{ipv6.NewProtocol()},
		NDPConfigs: stack.NDPConfigurations{
			HandleRAs:              true,
			AutoGenGlobalAddresses: true,
		},
		NDPDisp: &ndpDisp,
	})

	if err := s.CreateNIC(1, e); err != nil {
		t.Fatalf("CreateNIC(1) = %s", err)
	}

	expectAutoGenAddrEvent := func(addr tcpip.AddressWithPrefix, eventType ndpAutoGenAddrEventType) {
		t.Helper()

		select {
		case e := <-ndpDisp.autoGenAddrC:
			if diff := checkAutoGenAddrEvent(e, addr, eventType); diff != "" {
				t.Errorf("auto-gen addr event mismatch (-want +got):\n%s", diff)
			}
		default:
			t.Fatal("expected addr auto gen event")
		}
	}

	// Receive a PI to auto-generate an address.
	const lifetimeSeconds = 1
	e.InjectInbound(header.IPv6ProtocolNumber, raBufWithPI(llAddr2, 0, prefix, true, true, lifetimeSeconds, 0))
	expectAutoGenAddrEvent(addr, newAddr)

	// Removing the address should result in an invalidation event
	// immediately.
	if err := s.RemoveAddress(1, addr.Address); err != nil {
		t.Fatalf("RemoveAddress(_, %s) = %s", addr.Address, err)
	}
	expectAutoGenAddrEvent(addr, invalidatedAddr)

	// Wait for the original valid lifetime to make sure the original timer
	// got stopped/cleaned up.
	select {
	case <-ndpDisp.autoGenAddrC:
		t.Fatal("unexpectedly received an auto gen addr event")
	case <-time.After(lifetimeSeconds*time.Second + defaultTimeout):
	}
}

// TestAutoGenAddrAfterRemoval tests adding a SLAAC address that was previously
// assigned to the NIC but is in the permanentExpired state.
func TestAutoGenAddrAfterRemoval(t *testing.T) {
	t.Parallel()

	const nicID = 1

	prefix1, _, addr1 := prefixSubnetAddr(0, linkAddr1)
	prefix2, _, addr2 := prefixSubnetAddr(1, linkAddr1)
	ndpDisp, e, s := stackAndNdpDispatcherWithDefaultRoute(t, nicID)

	expectAutoGenAddrEvent := func(addr tcpip.AddressWithPrefix, eventType ndpAutoGenAddrEventType) {
		t.Helper()

		select {
		case e := <-ndpDisp.autoGenAddrC:
			if diff := checkAutoGenAddrEvent(e, addr, eventType); diff != "" {
				t.Errorf("auto-gen addr event mismatch (-want +got):\n%s", diff)
			}
		default:
			t.Fatal("expected addr auto gen event")
		}
	}

	expectPrimaryAddr := func(addr tcpip.AddressWithPrefix) {
		t.Helper()

		if got, err := s.GetMainNICAddress(nicID, header.IPv6ProtocolNumber); err != nil {
			t.Fatalf("s.GetMainNICAddress(%d, %d): %s", nicID, header.IPv6ProtocolNumber, err)
		} else if got != addr {
			t.Errorf("got s.GetMainNICAddress(%d, %d) = %s, want = %s", nicID, header.IPv6ProtocolNumber, got, addr)
		}

		if got := addrForNewConnection(t, s); got != addr.Address {
			t.Errorf("got addrForNewConnection = %s, want = %s", got, addr.Address)
		}
	}

	// Receive a PI to auto-generate addr1 with a large valid and preferred
	// lifetime.
	const largeLifetimeSeconds = 999
	e.InjectInbound(header.IPv6ProtocolNumber, raBufWithPI(llAddr3, 0, prefix1, true, true, largeLifetimeSeconds, largeLifetimeSeconds))
	expectAutoGenAddrEvent(addr1, newAddr)
	expectPrimaryAddr(addr1)

	// Add addr2 as a static address.
	protoAddr2 := tcpip.ProtocolAddress{
		Protocol:          header.IPv6ProtocolNumber,
		AddressWithPrefix: addr2,
	}
	if err := s.AddProtocolAddressWithOptions(nicID, protoAddr2, stack.FirstPrimaryEndpoint); err != nil {
		t.Fatalf("AddProtocolAddressWithOptions(%d, %+v, %d, %s) = %s", nicID, protoAddr2, stack.FirstPrimaryEndpoint, err)
	}
	// addr2 should be more preferred now since it is at the front of the primary
	// list.
	expectPrimaryAddr(addr2)

	// Get a route using addr2 to increment its reference count then remove it
	// to leave it in the permanentExpired state.
	r, err := s.FindRoute(nicID, addr2.Address, addr3, header.IPv6ProtocolNumber, false)
	if err != nil {
		t.Fatalf("FindRoute(%d, %s, %s, %d, false): %s", nicID, addr2.Address, addr3, header.IPv6ProtocolNumber, err)
	}
	defer r.Release()
	if err := s.RemoveAddress(nicID, addr2.Address); err != nil {
		t.Fatalf("s.RemoveAddress(%d, %s): %s", nicID, addr2.Address, err)
	}
	// addr1 should be preferred again since addr2 is in the expired state.
	expectPrimaryAddr(addr1)

	// Receive a PI to auto-generate addr2 as valid and preferred.
	e.InjectInbound(header.IPv6ProtocolNumber, raBufWithPI(llAddr3, 0, prefix2, true, true, largeLifetimeSeconds, largeLifetimeSeconds))
	expectAutoGenAddrEvent(addr2, newAddr)
	// addr2 should be more preferred now that it is closer to the front of the
	// primary list and not deprecated.
	expectPrimaryAddr(addr2)

	// Removing the address should result in an invalidation event immediately.
	// It should still be in the permanentExpired state because r is still held.
	//
	// We remove addr2 here to make sure addr2 was marked as a SLAAC address
	// (it was previously marked as a static address).
	if err := s.RemoveAddress(1, addr2.Address); err != nil {
		t.Fatalf("RemoveAddress(_, %s) = %s", addr2.Address, err)
	}
	expectAutoGenAddrEvent(addr2, invalidatedAddr)
	// addr1 should be more preferred since addr2 is in the expired state.
	expectPrimaryAddr(addr1)

	// Receive a PI to auto-generate addr2 as valid and deprecated.
	e.InjectInbound(header.IPv6ProtocolNumber, raBufWithPI(llAddr3, 0, prefix2, true, true, largeLifetimeSeconds, 0))
	expectAutoGenAddrEvent(addr2, newAddr)
	// addr1 should still be more preferred since addr2 is deprecated, even though
	// it is closer to the front of the primary list.
	expectPrimaryAddr(addr1)

	// Receive a PI to refresh addr2's preferred lifetime.
	e.InjectInbound(header.IPv6ProtocolNumber, raBufWithPI(llAddr3, 0, prefix2, true, true, largeLifetimeSeconds, largeLifetimeSeconds))
	select {
	case <-ndpDisp.autoGenAddrC:
		t.Fatal("unexpectedly got an auto gen addr event")
	default:
	}
	// addr2 should be more preferred now that it is not deprecated.
	expectPrimaryAddr(addr2)

	if err := s.RemoveAddress(1, addr2.Address); err != nil {
		t.Fatalf("RemoveAddress(_, %s) = %s", addr2.Address, err)
	}
	expectAutoGenAddrEvent(addr2, invalidatedAddr)
	expectPrimaryAddr(addr1)
}

// TestAutoGenAddrStaticConflict tests that if SLAAC generates an address that
// is already assigned to the NIC, the static address remains.
func TestAutoGenAddrStaticConflict(t *testing.T) {
	t.Parallel()

	prefix, _, addr := prefixSubnetAddr(0, linkAddr1)

	ndpDisp := ndpDispatcher{
		autoGenAddrC: make(chan ndpAutoGenAddrEvent, 1),
	}
	e := channel.New(0, 1280, linkAddr1)
	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocol{ipv6.NewProtocol()},
		NDPConfigs: stack.NDPConfigurations{
			HandleRAs:              true,
			AutoGenGlobalAddresses: true,
		},
		NDPDisp: &ndpDisp,
	})

	if err := s.CreateNIC(1, e); err != nil {
		t.Fatalf("CreateNIC(1) = %s", err)
	}

	// Add the address as a static address before SLAAC tries to add it.
	if err := s.AddProtocolAddress(1, tcpip.ProtocolAddress{Protocol: header.IPv6ProtocolNumber, AddressWithPrefix: addr}); err != nil {
		t.Fatalf("AddAddress(_, %d, %s) = %s", header.IPv6ProtocolNumber, addr.Address, err)
	}
	if !containsV6Addr(s.NICInfo()[1].ProtocolAddresses, addr) {
		t.Fatalf("Should have %s in the list of addresses", addr1)
	}

	// Receive a PI where the generated address will be the same as the one
	// that we already have assigned statically.
	const lifetimeSeconds = 1
	e.InjectInbound(header.IPv6ProtocolNumber, raBufWithPI(llAddr2, 0, prefix, true, true, lifetimeSeconds, 0))
	select {
	case <-ndpDisp.autoGenAddrC:
		t.Fatal("unexpectedly received an auto gen addr event for an address we already have statically")
	default:
	}
	if !containsV6Addr(s.NICInfo()[1].ProtocolAddresses, addr) {
		t.Fatalf("Should have %s in the list of addresses", addr1)
	}

	// Should not get an invalidation event after the PI's invalidation
	// time.
	select {
	case <-ndpDisp.autoGenAddrC:
		t.Fatal("unexpectedly received an auto gen addr event")
	case <-time.After(lifetimeSeconds*time.Second + defaultTimeout):
	}
	if !containsV6Addr(s.NICInfo()[1].ProtocolAddresses, addr) {
		t.Fatalf("Should have %s in the list of addresses", addr1)
	}
}

// TestAutoGenAddrWithOpaqueIID tests that SLAAC generated addresses will use
// opaque interface identifiers when configured to do so.
func TestAutoGenAddrWithOpaqueIID(t *testing.T) {
	t.Parallel()

	const nicID = 1
	const nicName = "nic1"
	var secretKeyBuf [header.OpaqueIIDSecretKeyMinBytes]byte
	secretKey := secretKeyBuf[:]
	n, err := rand.Read(secretKey)
	if err != nil {
		t.Fatalf("rand.Read(_): %s", err)
	}
	if n != header.OpaqueIIDSecretKeyMinBytes {
		t.Fatalf("got rand.Read(_) = (%d, _), want = (%d, _)", n, header.OpaqueIIDSecretKeyMinBytes)
	}

	prefix1, subnet1, _ := prefixSubnetAddr(0, linkAddr1)
	prefix2, subnet2, _ := prefixSubnetAddr(1, linkAddr1)
	// addr1 and addr2 are the addresses that are expected to be generated when
	// stack.Stack is configured to generate opaque interface identifiers as
	// defined by RFC 7217.
	addrBytes := []byte(subnet1.ID())
	addr1 := tcpip.AddressWithPrefix{
		Address:   tcpip.Address(header.AppendOpaqueInterfaceIdentifier(addrBytes[:header.IIDOffsetInIPv6Address], subnet1, nicName, 0, secretKey)),
		PrefixLen: 64,
	}
	addrBytes = []byte(subnet2.ID())
	addr2 := tcpip.AddressWithPrefix{
		Address:   tcpip.Address(header.AppendOpaqueInterfaceIdentifier(addrBytes[:header.IIDOffsetInIPv6Address], subnet2, nicName, 0, secretKey)),
		PrefixLen: 64,
	}

	ndpDisp := ndpDispatcher{
		autoGenAddrC: make(chan ndpAutoGenAddrEvent, 1),
	}
	e := channel.New(0, 1280, linkAddr1)
	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocol{ipv6.NewProtocol()},
		NDPConfigs: stack.NDPConfigurations{
			HandleRAs:              true,
			AutoGenGlobalAddresses: true,
		},
		NDPDisp: &ndpDisp,
		OpaqueIIDOpts: stack.OpaqueInterfaceIdentifierOptions{
			NICNameFromID: func(_ tcpip.NICID, nicName string) string {
				return nicName
			},
			SecretKey: secretKey,
		},
	})
	opts := stack.NICOptions{Name: nicName}
	if err := s.CreateNICWithOptions(nicID, e, opts); err != nil {
		t.Fatalf("CreateNICWithOptions(%d, _, %+v, _) = %s", nicID, opts, err)
	}

	expectAutoGenAddrEvent := func(addr tcpip.AddressWithPrefix, eventType ndpAutoGenAddrEventType) {
		t.Helper()

		select {
		case e := <-ndpDisp.autoGenAddrC:
			if diff := checkAutoGenAddrEvent(e, addr, eventType); diff != "" {
				t.Errorf("auto-gen addr event mismatch (-want +got):\n%s", diff)
			}
		default:
			t.Fatal("expected addr auto gen event")
		}
	}

	// Receive an RA with prefix1 in a PI.
	const validLifetimeSecondPrefix1 = 1
	e.InjectInbound(header.IPv6ProtocolNumber, raBufWithPI(llAddr2, 0, prefix1, true, true, validLifetimeSecondPrefix1, 0))
	expectAutoGenAddrEvent(addr1, newAddr)
	if !containsV6Addr(s.NICInfo()[nicID].ProtocolAddresses, addr1) {
		t.Fatalf("should have %s in the list of addresses", addr1)
	}

	// Receive an RA with prefix2 in a PI with a large valid lifetime.
	e.InjectInbound(header.IPv6ProtocolNumber, raBufWithPI(llAddr2, 0, prefix2, true, true, 100, 0))
	expectAutoGenAddrEvent(addr2, newAddr)
	if !containsV6Addr(s.NICInfo()[nicID].ProtocolAddresses, addr1) {
		t.Fatalf("should have %s in the list of addresses", addr1)
	}
	if !containsV6Addr(s.NICInfo()[nicID].ProtocolAddresses, addr2) {
		t.Fatalf("should have %s in the list of addresses", addr2)
	}

	// Wait for addr of prefix1 to be invalidated.
	select {
	case e := <-ndpDisp.autoGenAddrC:
		if diff := checkAutoGenAddrEvent(e, addr1, invalidatedAddr); diff != "" {
			t.Errorf("auto-gen addr event mismatch (-want +got):\n%s", diff)
		}
	case <-time.After(validLifetimeSecondPrefix1*time.Second + defaultAsyncEventTimeout):
		t.Fatal("timed out waiting for addr auto gen event")
	}
	if containsV6Addr(s.NICInfo()[nicID].ProtocolAddresses, addr1) {
		t.Fatalf("should not have %s in the list of addresses", addr1)
	}
	if !containsV6Addr(s.NICInfo()[nicID].ProtocolAddresses, addr2) {
		t.Fatalf("should have %s in the list of addresses", addr2)
	}
}

// TestNDPRecursiveDNSServerDispatch tests that we properly dispatch an event
// to the integrator when an RA is received with the NDP Recursive DNS Server
// option with at least one valid address.
func TestNDPRecursiveDNSServerDispatch(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		opt      header.NDPRecursiveDNSServer
		expected *ndpRDNSS
	}{
		{
			"Unspecified",
			header.NDPRecursiveDNSServer([]byte{
				0, 0,
				0, 0, 0, 2,
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
			}),
			nil,
		},
		{
			"Multicast",
			header.NDPRecursiveDNSServer([]byte{
				0, 0,
				0, 0, 0, 2,
				255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
			}),
			nil,
		},
		{
			"OptionTooSmall",
			header.NDPRecursiveDNSServer([]byte{
				0, 0,
				0, 0, 0, 2,
				1, 2, 3, 4, 5, 6, 7, 8,
			}),
			nil,
		},
		{
			"0Addresses",
			header.NDPRecursiveDNSServer([]byte{
				0, 0,
				0, 0, 0, 2,
			}),
			nil,
		},
		{
			"Valid1Address",
			header.NDPRecursiveDNSServer([]byte{
				0, 0,
				0, 0, 0, 2,
				1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, 0, 0, 0, 0, 1,
			}),
			&ndpRDNSS{
				[]tcpip.Address{
					"\x01\x02\x03\x04\x05\x06\x07\x08\x00\x00\x00\x00\x00\x00\x00\x01",
				},
				2 * time.Second,
			},
		},
		{
			"Valid2Addresses",
			header.NDPRecursiveDNSServer([]byte{
				0, 0,
				0, 0, 0, 1,
				1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, 0, 0, 0, 0, 1,
				1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, 0, 0, 0, 0, 2,
			}),
			&ndpRDNSS{
				[]tcpip.Address{
					"\x01\x02\x03\x04\x05\x06\x07\x08\x00\x00\x00\x00\x00\x00\x00\x01",
					"\x01\x02\x03\x04\x05\x06\x07\x08\x00\x00\x00\x00\x00\x00\x00\x02",
				},
				time.Second,
			},
		},
		{
			"Valid3Addresses",
			header.NDPRecursiveDNSServer([]byte{
				0, 0,
				0, 0, 0, 0,
				1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, 0, 0, 0, 0, 1,
				1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, 0, 0, 0, 0, 2,
				1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, 0, 0, 0, 0, 3,
			}),
			&ndpRDNSS{
				[]tcpip.Address{
					"\x01\x02\x03\x04\x05\x06\x07\x08\x00\x00\x00\x00\x00\x00\x00\x01",
					"\x01\x02\x03\x04\x05\x06\x07\x08\x00\x00\x00\x00\x00\x00\x00\x02",
					"\x01\x02\x03\x04\x05\x06\x07\x08\x00\x00\x00\x00\x00\x00\x00\x03",
				},
				0,
			},
		},
	}

	for _, test := range tests {
		test := test

		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			ndpDisp := ndpDispatcher{
				// We do not expect more than a single RDNSS
				// event at any time for this test.
				rdnssC: make(chan ndpRDNSSEvent, 1),
			}
			e := channel.New(0, 1280, linkAddr1)
			s := stack.New(stack.Options{
				NetworkProtocols: []stack.NetworkProtocol{ipv6.NewProtocol()},
				NDPConfigs: stack.NDPConfigurations{
					HandleRAs: true,
				},
				NDPDisp: &ndpDisp,
			})
			if err := s.CreateNIC(1, e); err != nil {
				t.Fatalf("CreateNIC(1) = %s", err)
			}

			e.InjectInbound(header.IPv6ProtocolNumber, raBufWithOpts(llAddr1, 0, header.NDPOptionsSerializer{test.opt}))

			if test.expected != nil {
				select {
				case e := <-ndpDisp.rdnssC:
					if e.nicID != 1 {
						t.Errorf("got rdnss nicID = %d, want = 1", e.nicID)
					}
					if diff := cmp.Diff(e.rdnss.addrs, test.expected.addrs); diff != "" {
						t.Errorf("rdnss addrs mismatch (-want +got):\n%s", diff)
					}
					if e.rdnss.lifetime != test.expected.lifetime {
						t.Errorf("got rdnss lifetime = %s, want = %s", e.rdnss.lifetime, test.expected.lifetime)
					}
				default:
					t.Fatal("expected an RDNSS option event")
				}
			}

			// Should have no more RDNSS options.
			select {
			case e := <-ndpDisp.rdnssC:
				t.Fatalf("unexpectedly got a new RDNSS option event: %+v", e)
			default:
			}
		})
	}
}

// TestCleanupHostOnlyStateOnBecomingRouter tests that all discovered routers
// and prefixes, and non-linklocal auto-generated addresses are invalidated when
// a NIC becomes a router.
func TestCleanupHostOnlyStateOnBecomingRouter(t *testing.T) {
	t.Parallel()

	const (
		lifetimeSeconds = 5
		maxEvents       = 4
		nicID1          = 1
		nicID2          = 2
	)

	prefix1, subnet1, e1Addr1 := prefixSubnetAddr(0, linkAddr1)
	prefix2, subnet2, e1Addr2 := prefixSubnetAddr(1, linkAddr1)
	e2Addr1 := addrForSubnet(subnet1, linkAddr2)
	e2Addr2 := addrForSubnet(subnet2, linkAddr2)
	llAddrWithPrefix1 := tcpip.AddressWithPrefix{
		Address:   llAddr1,
		PrefixLen: 64,
	}
	llAddrWithPrefix2 := tcpip.AddressWithPrefix{
		Address:   llAddr2,
		PrefixLen: 64,
	}

	ndpDisp := ndpDispatcher{
		routerC:        make(chan ndpRouterEvent, maxEvents),
		rememberRouter: true,
		prefixC:        make(chan ndpPrefixEvent, maxEvents),
		rememberPrefix: true,
		autoGenAddrC:   make(chan ndpAutoGenAddrEvent, maxEvents),
	}
	s := stack.New(stack.Options{
		NetworkProtocols:     []stack.NetworkProtocol{ipv6.NewProtocol()},
		AutoGenIPv6LinkLocal: true,
		NDPConfigs: stack.NDPConfigurations{
			HandleRAs:              true,
			DiscoverDefaultRouters: true,
			DiscoverOnLinkPrefixes: true,
			AutoGenGlobalAddresses: true,
		},
		NDPDisp: &ndpDisp,
	})

	expectRouterEvent := func() (bool, ndpRouterEvent) {
		select {
		case e := <-ndpDisp.routerC:
			return true, e
		default:
		}

		return false, ndpRouterEvent{}
	}

	expectPrefixEvent := func() (bool, ndpPrefixEvent) {
		select {
		case e := <-ndpDisp.prefixC:
			return true, e
		default:
		}

		return false, ndpPrefixEvent{}
	}

	expectAutoGenAddrEvent := func() (bool, ndpAutoGenAddrEvent) {
		select {
		case e := <-ndpDisp.autoGenAddrC:
			return true, e
		default:
		}

		return false, ndpAutoGenAddrEvent{}
	}

	e1 := channel.New(0, 1280, linkAddr1)
	if err := s.CreateNIC(nicID1, e1); err != nil {
		t.Fatalf("CreateNIC(%d, _) = %s", nicID1, err)
	}
	// We have other tests that make sure we receive the *correct* events
	// on normal discovery of routers/prefixes, and auto-generated
	// addresses. Here we just make sure we get an event and let other tests
	// handle the correctness check.
	expectAutoGenAddrEvent()

	e2 := channel.New(0, 1280, linkAddr2)
	if err := s.CreateNIC(nicID2, e2); err != nil {
		t.Fatalf("CreateNIC(%d, _) = %s", nicID2, err)
	}
	expectAutoGenAddrEvent()

	// Receive RAs on NIC(1) and NIC(2) from default routers (llAddr3 and
	// llAddr4) w/ PI (for prefix1 in RA from llAddr3 and prefix2 in RA from
	// llAddr4) to discover multiple routers and prefixes, and auto-gen
	// multiple addresses.

	e1.InjectInbound(header.IPv6ProtocolNumber, raBufWithPI(llAddr3, lifetimeSeconds, prefix1, true, true, lifetimeSeconds, lifetimeSeconds))
	if ok, _ := expectRouterEvent(); !ok {
		t.Errorf("expected router event for %s on NIC(%d)", llAddr3, nicID1)
	}
	if ok, _ := expectPrefixEvent(); !ok {
		t.Errorf("expected prefix event for %s on NIC(%d)", prefix1, nicID1)
	}
	if ok, _ := expectAutoGenAddrEvent(); !ok {
		t.Errorf("expected auto-gen addr event for %s on NIC(%d)", e1Addr1, nicID1)
	}

	e1.InjectInbound(header.IPv6ProtocolNumber, raBufWithPI(llAddr4, lifetimeSeconds, prefix2, true, true, lifetimeSeconds, lifetimeSeconds))
	if ok, _ := expectRouterEvent(); !ok {
		t.Errorf("expected router event for %s on NIC(%d)", llAddr4, nicID1)
	}
	if ok, _ := expectPrefixEvent(); !ok {
		t.Errorf("expected prefix event for %s on NIC(%d)", prefix2, nicID1)
	}
	if ok, _ := expectAutoGenAddrEvent(); !ok {
		t.Errorf("expected auto-gen addr event for %s on NIC(%d)", e1Addr2, nicID1)
	}

	e2.InjectInbound(header.IPv6ProtocolNumber, raBufWithPI(llAddr3, lifetimeSeconds, prefix1, true, true, lifetimeSeconds, lifetimeSeconds))
	if ok, _ := expectRouterEvent(); !ok {
		t.Errorf("expected router event for %s on NIC(%d)", llAddr3, nicID2)
	}
	if ok, _ := expectPrefixEvent(); !ok {
		t.Errorf("expected prefix event for %s on NIC(%d)", prefix1, nicID2)
	}
	if ok, _ := expectAutoGenAddrEvent(); !ok {
		t.Errorf("expected auto-gen addr event for %s on NIC(%d)", e1Addr2, nicID2)
	}

	e2.InjectInbound(header.IPv6ProtocolNumber, raBufWithPI(llAddr4, lifetimeSeconds, prefix2, true, true, lifetimeSeconds, lifetimeSeconds))
	if ok, _ := expectRouterEvent(); !ok {
		t.Errorf("expected router event for %s on NIC(%d)", llAddr4, nicID2)
	}
	if ok, _ := expectPrefixEvent(); !ok {
		t.Errorf("expected prefix event for %s on NIC(%d)", prefix2, nicID2)
	}
	if ok, _ := expectAutoGenAddrEvent(); !ok {
		t.Errorf("expected auto-gen addr event for %s on NIC(%d)", e2Addr2, nicID2)
	}

	// We should have the auto-generated addresses added.
	nicinfo := s.NICInfo()
	nic1Addrs := nicinfo[nicID1].ProtocolAddresses
	nic2Addrs := nicinfo[nicID2].ProtocolAddresses
	if !containsV6Addr(nic1Addrs, llAddrWithPrefix1) {
		t.Errorf("missing %s from the list of addresses for NIC(%d): %+v", llAddrWithPrefix1, nicID1, nic1Addrs)
	}
	if !containsV6Addr(nic1Addrs, e1Addr1) {
		t.Errorf("missing %s from the list of addresses for NIC(%d): %+v", e1Addr1, nicID1, nic1Addrs)
	}
	if !containsV6Addr(nic1Addrs, e1Addr2) {
		t.Errorf("missing %s from the list of addresses for NIC(%d): %+v", e1Addr2, nicID1, nic1Addrs)
	}
	if !containsV6Addr(nic2Addrs, llAddrWithPrefix2) {
		t.Errorf("missing %s from the list of addresses for NIC(%d): %+v", llAddrWithPrefix2, nicID2, nic2Addrs)
	}
	if !containsV6Addr(nic2Addrs, e2Addr1) {
		t.Errorf("missing %s from the list of addresses for NIC(%d): %+v", e2Addr1, nicID2, nic2Addrs)
	}
	if !containsV6Addr(nic2Addrs, e2Addr2) {
		t.Errorf("missing %s from the list of addresses for NIC(%d): %+v", e2Addr2, nicID2, nic2Addrs)
	}

	// We can't proceed any further if we already failed the test (missing
	// some discovery/auto-generated address events or addresses).
	if t.Failed() {
		t.FailNow()
	}

	s.SetForwarding(true)

	// Collect invalidation events after becoming a router
	gotRouterEvents := make(map[ndpRouterEvent]int)
	for i := 0; i < maxEvents; i++ {
		ok, e := expectRouterEvent()
		if !ok {
			t.Errorf("expected %d router events after becoming a router; got = %d", maxEvents, i)
			break
		}
		gotRouterEvents[e]++
	}
	gotPrefixEvents := make(map[ndpPrefixEvent]int)
	for i := 0; i < maxEvents; i++ {
		ok, e := expectPrefixEvent()
		if !ok {
			t.Errorf("expected %d prefix events after becoming a router; got = %d", maxEvents, i)
			break
		}
		gotPrefixEvents[e]++
	}
	gotAutoGenAddrEvents := make(map[ndpAutoGenAddrEvent]int)
	for i := 0; i < maxEvents; i++ {
		ok, e := expectAutoGenAddrEvent()
		if !ok {
			t.Errorf("expected %d auto-generated address events after becoming a router; got = %d", maxEvents, i)
			break
		}
		gotAutoGenAddrEvents[e]++
	}

	// No need to proceed any further if we already failed the test (missing
	// some invalidation events).
	if t.Failed() {
		t.FailNow()
	}

	expectedRouterEvents := map[ndpRouterEvent]int{
		{nicID: nicID1, addr: llAddr3, discovered: false}: 1,
		{nicID: nicID1, addr: llAddr4, discovered: false}: 1,
		{nicID: nicID2, addr: llAddr3, discovered: false}: 1,
		{nicID: nicID2, addr: llAddr4, discovered: false}: 1,
	}
	if diff := cmp.Diff(expectedRouterEvents, gotRouterEvents); diff != "" {
		t.Errorf("router events mismatch (-want +got):\n%s", diff)
	}
	expectedPrefixEvents := map[ndpPrefixEvent]int{
		{nicID: nicID1, prefix: subnet1, discovered: false}: 1,
		{nicID: nicID1, prefix: subnet2, discovered: false}: 1,
		{nicID: nicID2, prefix: subnet1, discovered: false}: 1,
		{nicID: nicID2, prefix: subnet2, discovered: false}: 1,
	}
	if diff := cmp.Diff(expectedPrefixEvents, gotPrefixEvents); diff != "" {
		t.Errorf("prefix events mismatch (-want +got):\n%s", diff)
	}
	expectedAutoGenAddrEvents := map[ndpAutoGenAddrEvent]int{
		{nicID: nicID1, addr: e1Addr1, eventType: invalidatedAddr}: 1,
		{nicID: nicID1, addr: e1Addr2, eventType: invalidatedAddr}: 1,
		{nicID: nicID2, addr: e2Addr1, eventType: invalidatedAddr}: 1,
		{nicID: nicID2, addr: e2Addr2, eventType: invalidatedAddr}: 1,
	}
	if diff := cmp.Diff(expectedAutoGenAddrEvents, gotAutoGenAddrEvents); diff != "" {
		t.Errorf("auto-generated address events mismatch (-want +got):\n%s", diff)
	}

	// Make sure the auto-generated addresses got removed.
	nicinfo = s.NICInfo()
	nic1Addrs = nicinfo[nicID1].ProtocolAddresses
	nic2Addrs = nicinfo[nicID2].ProtocolAddresses
	if !containsV6Addr(nic1Addrs, llAddrWithPrefix1) {
		t.Errorf("missing %s from the list of addresses for NIC(%d): %+v", llAddrWithPrefix1, nicID1, nic1Addrs)
	}
	if containsV6Addr(nic1Addrs, e1Addr1) {
		t.Errorf("still have %s in the list of addresses for NIC(%d): %+v", e1Addr1, nicID1, nic1Addrs)
	}
	if containsV6Addr(nic1Addrs, e1Addr2) {
		t.Errorf("still have %s in the list of addresses for NIC(%d): %+v", e1Addr2, nicID1, nic1Addrs)
	}
	if !containsV6Addr(nic2Addrs, llAddrWithPrefix2) {
		t.Errorf("missing %s from the list of addresses for NIC(%d): %+v", llAddrWithPrefix2, nicID2, nic2Addrs)
	}
	if containsV6Addr(nic2Addrs, e2Addr1) {
		t.Errorf("still have %s in the list of addresses for NIC(%d): %+v", e2Addr1, nicID2, nic2Addrs)
	}
	if containsV6Addr(nic2Addrs, e2Addr2) {
		t.Errorf("still have %s in the list of addresses for NIC(%d): %+v", e2Addr2, nicID2, nic2Addrs)
	}

	// Should not get any more events (invalidation timers should have been
	// cancelled when we transitioned into a router).
	time.Sleep(lifetimeSeconds*time.Second + defaultTimeout)
	select {
	case <-ndpDisp.routerC:
		t.Error("unexpected router event")
	default:
	}
	select {
	case <-ndpDisp.prefixC:
		t.Error("unexpected prefix event")
	default:
	}
	select {
	case <-ndpDisp.autoGenAddrC:
		t.Error("unexpected auto-generated address event")
	default:
	}
}

// TestDHCPv6ConfigurationFromNDPDA tests that the NDPDispatcher is properly
// informed when new information about what configurations are available via
// DHCPv6 is learned.
func TestDHCPv6ConfigurationFromNDPDA(t *testing.T) {
	const nicID = 1

	ndpDisp := ndpDispatcher{
		dhcpv6ConfigurationC: make(chan ndpDHCPv6Event, 1),
		rememberRouter:       true,
	}
	e := channel.New(0, 1280, linkAddr1)
	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocol{ipv6.NewProtocol()},
		NDPConfigs: stack.NDPConfigurations{
			HandleRAs: true,
		},
		NDPDisp: &ndpDisp,
	})

	if err := s.CreateNIC(nicID, e); err != nil {
		t.Fatalf("CreateNIC(%d, _) = %s", nicID, err)
	}

	expectDHCPv6Event := func(configuration stack.DHCPv6ConfigurationFromNDPRA) {
		t.Helper()
		select {
		case e := <-ndpDisp.dhcpv6ConfigurationC:
			if diff := cmp.Diff(ndpDHCPv6Event{nicID: nicID, configuration: configuration}, e, cmp.AllowUnexported(e)); diff != "" {
				t.Errorf("dhcpv6 event mismatch (-want +got):\n%s", diff)
			}
		default:
			t.Fatal("expected DHCPv6 configuration event")
		}
	}

	expectNoDHCPv6Event := func() {
		t.Helper()
		select {
		case <-ndpDisp.dhcpv6ConfigurationC:
			t.Fatal("unexpected DHCPv6 configuration event")
		default:
		}
	}

	// The initial DHCPv6 configuration should be stack.DHCPv6NoConfiguration.
	e.InjectInbound(header.IPv6ProtocolNumber, raBufWithDHCPv6(llAddr2, false, false))
	expectNoDHCPv6Event()

	// Receive an RA that updates the DHCPv6 configuration to Other
	// Configurations.
	e.InjectInbound(header.IPv6ProtocolNumber, raBufWithDHCPv6(llAddr2, false, true))
	expectDHCPv6Event(stack.DHCPv6OtherConfigurations)
	// Receiving the same update again should not result in an event to the
	// NDPDispatcher.
	e.InjectInbound(header.IPv6ProtocolNumber, raBufWithDHCPv6(llAddr2, false, true))
	expectNoDHCPv6Event()

	// Receive an RA that updates the DHCPv6 configuration to Managed Address.
	e.InjectInbound(header.IPv6ProtocolNumber, raBufWithDHCPv6(llAddr2, true, false))
	expectDHCPv6Event(stack.DHCPv6ManagedAddress)
	e.InjectInbound(header.IPv6ProtocolNumber, raBufWithDHCPv6(llAddr2, true, false))
	expectNoDHCPv6Event()

	// Receive an RA that updates the DHCPv6 configuration to none.
	e.InjectInbound(header.IPv6ProtocolNumber, raBufWithDHCPv6(llAddr2, false, false))
	expectDHCPv6Event(stack.DHCPv6NoConfiguration)
	e.InjectInbound(header.IPv6ProtocolNumber, raBufWithDHCPv6(llAddr2, false, false))
	expectNoDHCPv6Event()

	// Receive an RA that updates the DHCPv6 configuration to Managed Address.
	//
	// Note, when the M flag is set, the O flag is redundant.
	e.InjectInbound(header.IPv6ProtocolNumber, raBufWithDHCPv6(llAddr2, true, true))
	expectDHCPv6Event(stack.DHCPv6ManagedAddress)
	e.InjectInbound(header.IPv6ProtocolNumber, raBufWithDHCPv6(llAddr2, true, true))
	expectNoDHCPv6Event()
	// Even though the DHCPv6 flags are different, the effective configuration is
	// the same so we should not receive a new event.
	e.InjectInbound(header.IPv6ProtocolNumber, raBufWithDHCPv6(llAddr2, true, false))
	expectNoDHCPv6Event()
	e.InjectInbound(header.IPv6ProtocolNumber, raBufWithDHCPv6(llAddr2, true, true))
	expectNoDHCPv6Event()

	// Receive an RA that updates the DHCPv6 configuration to Other
	// Configurations.
	e.InjectInbound(header.IPv6ProtocolNumber, raBufWithDHCPv6(llAddr2, false, true))
	expectDHCPv6Event(stack.DHCPv6OtherConfigurations)
	e.InjectInbound(header.IPv6ProtocolNumber, raBufWithDHCPv6(llAddr2, false, true))
	expectNoDHCPv6Event()
}

// TestRouterSolicitation tests the initial Router Solicitations that are sent
// when a NIC newly becomes enabled.
func TestRouterSolicitation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name                        string
		maxRtrSolicit               uint8
		rtrSolicitInt               time.Duration
		effectiveRtrSolicitInt      time.Duration
		maxRtrSolicitDelay          time.Duration
		effectiveMaxRtrSolicitDelay time.Duration
	}{
		{
			name:                        "Single RS with delay",
			maxRtrSolicit:               1,
			rtrSolicitInt:               time.Second,
			effectiveRtrSolicitInt:      time.Second,
			maxRtrSolicitDelay:          time.Second,
			effectiveMaxRtrSolicitDelay: time.Second,
		},
		{
			name:                        "Two RS with delay",
			maxRtrSolicit:               2,
			rtrSolicitInt:               time.Second,
			effectiveRtrSolicitInt:      time.Second,
			maxRtrSolicitDelay:          500 * time.Millisecond,
			effectiveMaxRtrSolicitDelay: 500 * time.Millisecond,
		},
		{
			name:                        "Single RS without delay",
			maxRtrSolicit:               1,
			rtrSolicitInt:               time.Second,
			effectiveRtrSolicitInt:      time.Second,
			maxRtrSolicitDelay:          0,
			effectiveMaxRtrSolicitDelay: 0,
		},
		{
			name:                        "Two RS without delay and invalid zero interval",
			maxRtrSolicit:               2,
			rtrSolicitInt:               0,
			effectiveRtrSolicitInt:      4 * time.Second,
			maxRtrSolicitDelay:          0,
			effectiveMaxRtrSolicitDelay: 0,
		},
		{
			name:                        "Three RS without delay",
			maxRtrSolicit:               3,
			rtrSolicitInt:               500 * time.Millisecond,
			effectiveRtrSolicitInt:      500 * time.Millisecond,
			maxRtrSolicitDelay:          0,
			effectiveMaxRtrSolicitDelay: 0,
		},
		{
			name:                        "Two RS with invalid negative delay",
			maxRtrSolicit:               2,
			rtrSolicitInt:               time.Second,
			effectiveRtrSolicitInt:      time.Second,
			maxRtrSolicitDelay:          -3 * time.Second,
			effectiveMaxRtrSolicitDelay: time.Second,
		},
	}

	// This Run will not return until the parallel tests finish.
	//
	// We need this because we need to do some teardown work after the
	// parallel tests complete.
	//
	// See https://godoc.org/testing#hdr-Subtests_and_Sub_benchmarks for
	// more details.
	t.Run("group", func(t *testing.T) {
		for _, test := range tests {
			test := test

			t.Run(test.name, func(t *testing.T) {
				t.Parallel()
				e := channel.New(int(test.maxRtrSolicit), 1280, linkAddr1)
				e.LinkEPCapabilities |= stack.CapabilityResolutionRequired
				waitForPkt := func(timeout time.Duration) {
					t.Helper()
					ctx, _ := context.WithTimeout(context.Background(), timeout)
					p, ok := e.ReadContext(ctx)
					if !ok {
						t.Fatal("timed out waiting for packet")
						return
					}

					if p.Proto != header.IPv6ProtocolNumber {
						t.Fatalf("got Proto = %d, want = %d", p.Proto, header.IPv6ProtocolNumber)
					}

					// Make sure the right remote link address is used.
					if want := header.EthernetAddressFromMulticastIPv6Address(header.IPv6AllRoutersMulticastAddress); p.Route.RemoteLinkAddress != want {
						t.Errorf("got remote link address = %s, want = %s", p.Route.RemoteLinkAddress, want)
					}

					checker.IPv6(t,
						p.Pkt.Header.View(),
						checker.SrcAddr(header.IPv6Any),
						checker.DstAddr(header.IPv6AllRoutersMulticastAddress),
						checker.TTL(header.NDPHopLimit),
						checker.NDPRS(),
					)
				}
				waitForNothing := func(timeout time.Duration) {
					t.Helper()
					ctx, _ := context.WithTimeout(context.Background(), timeout)
					if _, ok := e.ReadContext(ctx); ok {
						t.Fatal("unexpectedly got a packet")
					}
				}
				s := stack.New(stack.Options{
					NetworkProtocols: []stack.NetworkProtocol{ipv6.NewProtocol()},
					NDPConfigs: stack.NDPConfigurations{
						MaxRtrSolicitations:     test.maxRtrSolicit,
						RtrSolicitationInterval: test.rtrSolicitInt,
						MaxRtrSolicitationDelay: test.maxRtrSolicitDelay,
					},
				})
				if err := s.CreateNIC(1, e); err != nil {
					t.Fatalf("CreateNIC(1) = %s", err)
				}

				// Make sure each RS got sent at the right
				// times.
				remaining := test.maxRtrSolicit
				if remaining > 0 {
					waitForPkt(test.effectiveMaxRtrSolicitDelay + defaultAsyncEventTimeout)
					remaining--
				}
				for ; remaining > 0; remaining-- {
					waitForNothing(test.effectiveRtrSolicitInt - defaultTimeout)
					waitForPkt(defaultAsyncEventTimeout)
				}

				// Make sure no more RS.
				if test.effectiveRtrSolicitInt > test.effectiveMaxRtrSolicitDelay {
					waitForNothing(test.effectiveRtrSolicitInt + defaultTimeout)
				} else {
					waitForNothing(test.effectiveMaxRtrSolicitDelay + defaultTimeout)
				}

				// Make sure the counter got properly
				// incremented.
				if got, want := s.Stats().ICMP.V6PacketsSent.RouterSolicit.Value(), uint64(test.maxRtrSolicit); got != want {
					t.Fatalf("got sent RouterSolicit = %d, want = %d", got, want)
				}
			})
		}
	})
}

// TestStopStartSolicitingRouters tests that when forwarding is enabled or
// disabled, router solicitations are stopped or started, respecitively.
func TestStopStartSolicitingRouters(t *testing.T) {
	t.Parallel()

	const interval = 500 * time.Millisecond
	const delay = time.Second
	const maxRtrSolicitations = 3
	e := channel.New(maxRtrSolicitations, 1280, linkAddr1)
	waitForPkt := func(timeout time.Duration) {
		t.Helper()
		ctx, _ := context.WithTimeout(context.Background(), timeout)
		p, ok := e.ReadContext(ctx)
		if !ok {
			t.Fatal("timed out waiting for packet")
			return
		}

		if p.Proto != header.IPv6ProtocolNumber {
			t.Fatalf("got Proto = %d, want = %d", p.Proto, header.IPv6ProtocolNumber)
		}
		checker.IPv6(t, p.Pkt.Header.View(),
			checker.SrcAddr(header.IPv6Any),
			checker.DstAddr(header.IPv6AllRoutersMulticastAddress),
			checker.TTL(header.NDPHopLimit),
			checker.NDPRS())
	}
	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocol{ipv6.NewProtocol()},
		NDPConfigs: stack.NDPConfigurations{
			MaxRtrSolicitations:     maxRtrSolicitations,
			RtrSolicitationInterval: interval,
			MaxRtrSolicitationDelay: delay,
		},
	})
	if err := s.CreateNIC(1, e); err != nil {
		t.Fatalf("CreateNIC(1) = %s", err)
	}

	// Enable forwarding which should stop router solicitations.
	s.SetForwarding(true)
	ctx, _ := context.WithTimeout(context.Background(), delay+defaultTimeout)
	if _, ok := e.ReadContext(ctx); ok {
		// A single RS may have been sent before forwarding was enabled.
		ctx, _ = context.WithTimeout(context.Background(), interval+defaultTimeout)
		if _, ok = e.ReadContext(ctx); ok {
			t.Fatal("Should not have sent more than one RS message")
		}
	}

	// Enabling forwarding again should do nothing.
	s.SetForwarding(true)
	ctx, _ = context.WithTimeout(context.Background(), delay+defaultTimeout)
	if _, ok := e.ReadContext(ctx); ok {
		t.Fatal("unexpectedly got a packet after becoming a router")
	}

	// Disable forwarding which should start router solicitations.
	s.SetForwarding(false)
	waitForPkt(delay + defaultAsyncEventTimeout)
	waitForPkt(interval + defaultAsyncEventTimeout)
	waitForPkt(interval + defaultAsyncEventTimeout)
	ctx, _ = context.WithTimeout(context.Background(), interval+defaultTimeout)
	if _, ok := e.ReadContext(ctx); ok {
		t.Fatal("unexpectedly got an extra packet after sending out the expected RSs")
	}

	// Disabling forwarding again should do nothing.
	s.SetForwarding(false)
	ctx, _ = context.WithTimeout(context.Background(), delay+defaultTimeout)
	if _, ok := e.ReadContext(ctx); ok {
		t.Fatal("unexpectedly got a packet after becoming a router")
	}
}
