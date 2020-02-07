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

package stack

import (
	"log"
	"math/rand"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

const (
	// defaultDupAddrDetectTransmits is the default number of NDP Neighbor
	// Solicitation messages to send when doing Duplicate Address Detection
	// for a tentative address.
	//
	// Default = 1 (from RFC 4862 section 5.1)
	defaultDupAddrDetectTransmits = 1

	// defaultRetransmitTimer is the default amount of time to wait between
	// sending NDP Neighbor solicitation messages.
	//
	// Default = 1s (from RFC 4861 section 10).
	defaultRetransmitTimer = time.Second

	// defaultMaxRtrSolicitations is the default number of Router
	// Solicitation messages to send when a NIC becomes enabled.
	//
	// Default = 3 (from RFC 4861 section 10).
	defaultMaxRtrSolicitations = 3

	// defaultRtrSolicitationInterval is the default amount of time between
	// sending Router Solicitation messages.
	//
	// Default = 4s (from 4861 section 10).
	defaultRtrSolicitationInterval = 4 * time.Second

	// defaultMaxRtrSolicitationDelay is the default maximum amount of time
	// to wait before sending the first Router Solicitation message.
	//
	// Default = 1s (from 4861 section 10).
	defaultMaxRtrSolicitationDelay = time.Second

	// defaultHandleRAs is the default configuration for whether or not to
	// handle incoming Router Advertisements as a host.
	defaultHandleRAs = true

	// defaultDiscoverDefaultRouters is the default configuration for
	// whether or not to discover default routers from incoming Router
	// Advertisements, as a host.
	defaultDiscoverDefaultRouters = true

	// defaultDiscoverOnLinkPrefixes is the default configuration for
	// whether or not to discover on-link prefixes from incoming Router
	// Advertisements' Prefix Information option, as a host.
	defaultDiscoverOnLinkPrefixes = true

	// defaultAutoGenGlobalAddresses is the default configuration for
	// whether or not to generate global IPv6 addresses in response to
	// receiving a new Prefix Information option with its Autonomous
	// Address AutoConfiguration flag set, as a host.
	//
	// Default = true.
	defaultAutoGenGlobalAddresses = true

	// minimumRetransmitTimer is the minimum amount of time to wait between
	// sending NDP Neighbor solicitation messages. Note, RFC 4861 does
	// not impose a minimum Retransmit Timer, but we do here to make sure
	// the messages are not sent all at once. We also come to this value
	// because in the RetransmitTimer field of a Router Advertisement, a
	// value of 0 means unspecified, so the smallest valid value is 1.
	// Note, the unit of the RetransmitTimer field in the Router
	// Advertisement is milliseconds.
	minimumRetransmitTimer = time.Millisecond

	// minimumRtrSolicitationInterval is the minimum amount of time to wait
	// between sending Router Solicitation messages. This limit is imposed
	// to make sure that Router Solicitation messages are not sent all at
	// once, defeating the purpose of sending the initial few messages.
	minimumRtrSolicitationInterval = 500 * time.Millisecond

	// minimumMaxRtrSolicitationDelay is the minimum amount of time to wait
	// before sending the first Router Solicitation message. It is 0 because
	// we cannot have a negative delay.
	minimumMaxRtrSolicitationDelay = 0

	// MaxDiscoveredDefaultRouters is the maximum number of discovered
	// default routers. The stack should stop discovering new routers after
	// discovering MaxDiscoveredDefaultRouters routers.
	//
	// This value MUST be at minimum 2 as per RFC 4861 section 6.3.4, and
	// SHOULD be more.
	MaxDiscoveredDefaultRouters = 10

	// MaxDiscoveredOnLinkPrefixes is the maximum number of discovered
	// on-link prefixes. The stack should stop discovering new on-link
	// prefixes after discovering MaxDiscoveredOnLinkPrefixes on-link
	// prefixes.
	MaxDiscoveredOnLinkPrefixes = 10

	// validPrefixLenForAutoGen is the expected prefix length that an
	// address can be generated for. Must be 64 bits as the interface
	// identifier (IID) is 64 bits and an IPv6 address is 128 bits, so
	// 128 - 64 = 64.
	validPrefixLenForAutoGen = 64
)

var (
	// MinPrefixInformationValidLifetimeForUpdate is the minimum Valid
	// Lifetime to update the valid lifetime of a generated address by
	// SLAAC.
	//
	// This is exported as a variable (instead of a constant) so tests
	// can update it to a smaller value.
	//
	// Min = 2hrs.
	MinPrefixInformationValidLifetimeForUpdate = 2 * time.Hour
)

// DHCPv6ConfigurationFromNDPRA is a configuration available via DHCPv6 that an
// NDP Router Advertisement informed the Stack about.
type DHCPv6ConfigurationFromNDPRA int

const (
	// DHCPv6NoConfiguration indicates that no configurations are available via
	// DHCPv6.
	DHCPv6NoConfiguration DHCPv6ConfigurationFromNDPRA = iota

	// DHCPv6ManagedAddress indicates that addresses are available via DHCPv6.
	//
	// DHCPv6ManagedAddress also implies DHCPv6OtherConfigurations because DHCPv6
	// will return all available configuration information.
	DHCPv6ManagedAddress

	// DHCPv6OtherConfigurations indicates that other configuration information is
	// available via DHCPv6.
	//
	// Other configurations are configurations other than addresses. Examples of
	// other configurations are recursive DNS server list, DNS search lists and
	// default gateway.
	DHCPv6OtherConfigurations
)

// NDPDispatcher is the interface integrators of netstack must implement to
// receive and handle NDP related events.
type NDPDispatcher interface {
	// OnDuplicateAddressDetectionStatus will be called when the DAD process
	// for an address (addr) on a NIC (with ID nicID) completes. resolved
	// will be set to true if DAD completed successfully (no duplicate addr
	// detected); false otherwise (addr was detected to be a duplicate on
	// the link the NIC is a part of, or it was stopped for some other
	// reason, such as the address being removed). If an error occured
	// during DAD, err will be set and resolved must be ignored.
	//
	// This function is not permitted to block indefinitely. This function
	// is also not permitted to call into the stack.
	OnDuplicateAddressDetectionStatus(nicID tcpip.NICID, addr tcpip.Address, resolved bool, err *tcpip.Error)

	// OnDefaultRouterDiscovered will be called when a new default router is
	// discovered. Implementations must return true if the newly discovered
	// router should be remembered.
	//
	// This function is not permitted to block indefinitely. This function
	// is also not permitted to call into the stack.
	OnDefaultRouterDiscovered(nicID tcpip.NICID, addr tcpip.Address) bool

	// OnDefaultRouterInvalidated will be called when a discovered default
	// router that was remembered is invalidated.
	//
	// This function is not permitted to block indefinitely. This function
	// is also not permitted to call into the stack.
	OnDefaultRouterInvalidated(nicID tcpip.NICID, addr tcpip.Address)

	// OnOnLinkPrefixDiscovered will be called when a new on-link prefix is
	// discovered. Implementations must return true if the newly discovered
	// on-link prefix should be remembered.
	//
	// This function is not permitted to block indefinitely. This function
	// is also not permitted to call into the stack.
	OnOnLinkPrefixDiscovered(nicID tcpip.NICID, prefix tcpip.Subnet) bool

	// OnOnLinkPrefixInvalidated will be called when a discovered on-link
	// prefix that was remembered is invalidated.
	//
	// This function is not permitted to block indefinitely. This function
	// is also not permitted to call into the stack.
	OnOnLinkPrefixInvalidated(nicID tcpip.NICID, prefix tcpip.Subnet)

	// OnAutoGenAddress will be called when a new prefix with its
	// autonomous address-configuration flag set has been received and SLAAC
	// has been performed. Implementations may prevent the stack from
	// assigning the address to the NIC by returning false.
	//
	// This function is not permitted to block indefinitely. It must not
	// call functions on the stack itself.
	OnAutoGenAddress(tcpip.NICID, tcpip.AddressWithPrefix) bool

	// OnAutoGenAddressDeprecated will be called when an auto-generated
	// address (as part of SLAAC) has been deprecated, but is still
	// considered valid. Note, if an address is invalidated at the same
	// time it is deprecated, the deprecation event MAY be omitted.
	//
	// This function is not permitted to block indefinitely. It must not
	// call functions on the stack itself.
	OnAutoGenAddressDeprecated(tcpip.NICID, tcpip.AddressWithPrefix)

	// OnAutoGenAddressInvalidated will be called when an auto-generated
	// address (as part of SLAAC) has been invalidated.
	//
	// This function is not permitted to block indefinitely. It must not
	// call functions on the stack itself.
	OnAutoGenAddressInvalidated(tcpip.NICID, tcpip.AddressWithPrefix)

	// OnRecursiveDNSServerOption will be called when an NDP option with
	// recursive DNS servers has been received. Note, addrs may contain
	// link-local addresses.
	//
	// It is up to the caller to use the DNS Servers only for their valid
	// lifetime. OnRecursiveDNSServerOption may be called for new or
	// already known DNS servers. If called with known DNS servers, their
	// valid lifetimes must be refreshed to lifetime (it may be increased,
	// decreased, or completely invalidated when lifetime = 0).
	//
	// This function is not permitted to block indefinitely. It must not
	// call functions on the stack itself.
	OnRecursiveDNSServerOption(nicID tcpip.NICID, addrs []tcpip.Address, lifetime time.Duration)

	// OnDHCPv6Configuration will be called with an updated configuration that is
	// available via DHCPv6 for a specified NIC.
	//
	// NDPDispatcher assumes that the initial configuration available by DHCPv6 is
	// DHCPv6NoConfiguration.
	//
	// This function is not permitted to block indefinitely. It must not
	// call functions on the stack itself.
	OnDHCPv6Configuration(tcpip.NICID, DHCPv6ConfigurationFromNDPRA)
}

// NDPConfigurations is the NDP configurations for the netstack.
type NDPConfigurations struct {
	// The number of Neighbor Solicitation messages to send when doing
	// Duplicate Address Detection for a tentative address.
	//
	// Note, a value of zero effectively disables DAD.
	DupAddrDetectTransmits uint8

	// The amount of time to wait between sending Neighbor solicitation
	// messages.
	//
	// Must be greater than or equal to 1ms.
	RetransmitTimer time.Duration

	// The number of Router Solicitation messages to send when the NIC
	// becomes enabled.
	MaxRtrSolicitations uint8

	// The amount of time between transmitting Router Solicitation messages.
	//
	// Must be greater than or equal to 0.5s.
	RtrSolicitationInterval time.Duration

	// The maximum amount of time before transmitting the first Router
	// Solicitation message.
	//
	// Must be greater than or equal to 0s.
	MaxRtrSolicitationDelay time.Duration

	// HandleRAs determines whether or not Router Advertisements will be
	// processed.
	HandleRAs bool

	// DiscoverDefaultRouters determines whether or not default routers will
	// be discovered from Router Advertisements. This configuration is
	// ignored if HandleRAs is false.
	DiscoverDefaultRouters bool

	// DiscoverOnLinkPrefixes determines whether or not on-link prefixes
	// will be discovered from Router Advertisements' Prefix Information
	// option. This configuration is ignored if HandleRAs is false.
	DiscoverOnLinkPrefixes bool

	// AutoGenGlobalAddresses determines whether or not global IPv6
	// addresses will be generated for a NIC in response to receiving a new
	// Prefix Information option with its Autonomous Address
	// AutoConfiguration flag set, as a host, as per RFC 4862 (SLAAC).
	//
	// Note, if an address was already generated for some unique prefix, as
	// part of SLAAC, this option does not affect whether or not the
	// lifetime(s) of the generated address changes; this option only
	// affects the generation of new addresses as part of SLAAC.
	AutoGenGlobalAddresses bool
}

// DefaultNDPConfigurations returns an NDPConfigurations populated with
// default values.
func DefaultNDPConfigurations() NDPConfigurations {
	return NDPConfigurations{
		DupAddrDetectTransmits:  defaultDupAddrDetectTransmits,
		RetransmitTimer:         defaultRetransmitTimer,
		MaxRtrSolicitations:     defaultMaxRtrSolicitations,
		RtrSolicitationInterval: defaultRtrSolicitationInterval,
		MaxRtrSolicitationDelay: defaultMaxRtrSolicitationDelay,
		HandleRAs:               defaultHandleRAs,
		DiscoverDefaultRouters:  defaultDiscoverDefaultRouters,
		DiscoverOnLinkPrefixes:  defaultDiscoverOnLinkPrefixes,
		AutoGenGlobalAddresses:  defaultAutoGenGlobalAddresses,
	}
}

// validate modifies an NDPConfigurations with valid values. If invalid values
// are present in c, the corresponding default values will be used instead.
//
// If RetransmitTimer is less than minimumRetransmitTimer, then a value of
// defaultRetransmitTimer will be used.
//
// If RtrSolicitationInterval is less than minimumRtrSolicitationInterval, then
// a value of defaultRtrSolicitationInterval will be used.
//
// If MaxRtrSolicitationDelay is less than minimumMaxRtrSolicitationDelay, then
// a value of defaultMaxRtrSolicitationDelay will be used.
func (c *NDPConfigurations) validate() {
	if c.RetransmitTimer < minimumRetransmitTimer {
		c.RetransmitTimer = defaultRetransmitTimer
	}

	if c.RtrSolicitationInterval < minimumRtrSolicitationInterval {
		c.RtrSolicitationInterval = defaultRtrSolicitationInterval
	}

	if c.MaxRtrSolicitationDelay < minimumMaxRtrSolicitationDelay {
		c.MaxRtrSolicitationDelay = defaultMaxRtrSolicitationDelay
	}
}

// ndpState is the per-interface NDP state.
type ndpState struct {
	// The NIC this ndpState is for.
	nic *NIC

	// configs is the per-interface NDP configurations.
	configs NDPConfigurations

	// The DAD state to send the next NS message, or resolve the address.
	dad map[tcpip.Address]dadState

	// The default routers discovered through Router Advertisements.
	defaultRouters map[tcpip.Address]defaultRouterState

	// The on-link prefixes discovered through Router Advertisements' Prefix
	// Information option.
	onLinkPrefixes map[tcpip.Subnet]onLinkPrefixState

	// The timer used to send the next router solicitation message.
	// If routers are being solicited, rtrSolicitTimer MUST NOT be nil.
	rtrSolicitTimer *time.Timer

	// The addresses generated by SLAAC.
	autoGenAddresses map[tcpip.Address]autoGenAddressState

	// The last learned DHCPv6 configuration from an NDP RA.
	dhcpv6Configuration DHCPv6ConfigurationFromNDPRA
}

// dadState holds the Duplicate Address Detection timer and channel to signal
// to the DAD goroutine that DAD should stop.
type dadState struct {
	// The DAD timer to send the next NS message, or resolve the address.
	timer *time.Timer

	// Used to let the DAD timer know that it has been stopped.
	//
	// Must only be read from or written to while protected by the lock of
	// the NIC this dadState is associated with.
	done *bool
}

// defaultRouterState holds data associated with a default router discovered by
// a Router Advertisement (RA).
type defaultRouterState struct {
	invalidationTimer tcpip.CancellableTimer
}

// onLinkPrefixState holds data associated with an on-link prefix discovered by
// a Router Advertisement's Prefix Information option (PI) when the NDP
// configurations was configured to do so.
type onLinkPrefixState struct {
	invalidationTimer tcpip.CancellableTimer
}

// autoGenAddressState holds data associated with an address generated via
// SLAAC.
type autoGenAddressState struct {
	// A reference to the referencedNetworkEndpoint that this autoGenAddressState
	// is holding state for.
	ref *referencedNetworkEndpoint

	deprecationTimer  tcpip.CancellableTimer
	invalidationTimer tcpip.CancellableTimer

	// Nonzero only when the address is not valid forever.
	validUntil time.Time
}

// startDuplicateAddressDetection performs Duplicate Address Detection.
//
// This function must only be called by IPv6 addresses that are currently
// tentative.
//
// The NIC that ndp belongs to MUST be locked.
func (ndp *ndpState) startDuplicateAddressDetection(addr tcpip.Address, ref *referencedNetworkEndpoint) *tcpip.Error {
	// addr must be a valid unicast IPv6 address.
	if !header.IsV6UnicastAddress(addr) {
		return tcpip.ErrAddressFamilyNotSupported
	}

	if ref.getKind() != permanentTentative {
		// The endpoint should be marked as tentative since we are starting DAD.
		log.Fatalf("ndpdad: addr %s is not tentative on NIC(%d)", addr, ndp.nic.ID())
	}

	// Should not attempt to perform DAD on an address that is currently in the
	// DAD process.
	if _, ok := ndp.dad[addr]; ok {
		// Should never happen because we should only ever call this function for
		// newly created addresses. If we attemped to "add" an address that already
		// existed, we would get an error since we attempted to add a duplicate
		// address, or its reference count would have been increased without doing
		// the work that would have been done for an address that was brand new.
		// See NIC.addAddressLocked.
		log.Fatalf("ndpdad: already performing DAD for addr %s on NIC(%d)", addr, ndp.nic.ID())
	}

	remaining := ndp.configs.DupAddrDetectTransmits
	if remaining == 0 {
		ref.setKind(permanent)

		// Consider DAD to have resolved even if no DAD messages were actually
		// transmitted.
		if ndpDisp := ndp.nic.stack.ndpDisp; ndpDisp != nil {
			ndpDisp.OnDuplicateAddressDetectionStatus(ndp.nic.ID(), addr, true, nil)
		}

		return nil
	}

	var done bool
	var timer *time.Timer
	// We initially start a timer to fire immediately because some of the DAD work
	// cannot be done while holding the NIC's lock. This is effectively the same
	// as starting a goroutine but we use a timer that fires immediately so we can
	// reset it for the next DAD iteration.
	timer = time.AfterFunc(0, func() {
		ndp.nic.mu.RLock()
		if done {
			// If we reach this point, it means that the DAD timer fired after
			// another goroutine already obtained the NIC lock and stopped DAD
			// before this function obtained the NIC lock. Simply return here and do
			// nothing further.
			ndp.nic.mu.RUnlock()
			return
		}

		if ref.getKind() != permanentTentative {
			// The endpoint should still be marked as tentative since we are still
			// performing DAD on it.
			log.Fatalf("ndpdad: addr %s is no longer tentative on NIC(%d)", addr, ndp.nic.ID())
		}

		dadDone := remaining == 0
		ndp.nic.mu.RUnlock()

		var err *tcpip.Error
		if !dadDone {
			err = ndp.sendDADPacket(addr)
		}

		ndp.nic.mu.Lock()
		if done {
			// If we reach this point, it means that DAD was stopped after we released
			// the NIC's read lock and before we obtained the write lock.
			ndp.nic.mu.Unlock()
			return
		}

		if dadDone {
			// DAD has resolved.
			ref.setKind(permanent)
		} else if err == nil {
			// DAD is not done and we had no errors when sending the last NDP NS,
			// schedule the next DAD timer.
			remaining--
			timer.Reset(ndp.nic.stack.ndpConfigs.RetransmitTimer)

			ndp.nic.mu.Unlock()
			return
		}

		// At this point we know that either DAD is done or we hit an error sending
		// the last NDP NS. Either way, clean up addr's DAD state and let the
		// integrator know DAD has completed.
		delete(ndp.dad, addr)
		ndp.nic.mu.Unlock()

		if err != nil {
			log.Printf("ndpdad: error occured during DAD iteration for addr (%s) on NIC(%d); err = %s", addr, ndp.nic.ID(), err)
		}

		if ndpDisp := ndp.nic.stack.ndpDisp; ndpDisp != nil {
			ndpDisp.OnDuplicateAddressDetectionStatus(ndp.nic.ID(), addr, dadDone, err)
		}
	})

	ndp.dad[addr] = dadState{
		timer: timer,
		done:  &done,
	}

	return nil
}

// sendDADPacket sends a NS message to see if any nodes on ndp's NIC's link owns
// addr.
//
// addr must be a tentative IPv6 address on ndp's NIC.
func (ndp *ndpState) sendDADPacket(addr tcpip.Address) *tcpip.Error {
	snmc := header.SolicitedNodeAddr(addr)

	// Use the unspecified address as the source address when performing DAD.
	ref := ndp.nic.getRefOrCreateTemp(header.IPv6ProtocolNumber, header.IPv6Any, NeverPrimaryEndpoint, forceSpoofing)
	r := makeRoute(header.IPv6ProtocolNumber, header.IPv6Any, snmc, ndp.nic.linkEP.LinkAddress(), ref, false, false)
	defer r.Release()

	// Route should resolve immediately since snmc is a multicast address so a
	// remote link address can be calculated without a resolution process.
	if c, err := r.Resolve(nil); err != nil {
		log.Fatalf("ndp: error when resolving route to send NDP NS for DAD (%s -> %s on NIC(%d)): %s", header.IPv6Any, snmc, ndp.nic.ID(), err)
	} else if c != nil {
		log.Fatalf("ndp: route resolution not immediate for route to send NDP NS for DAD (%s -> %s on NIC(%d))", header.IPv6Any, snmc, ndp.nic.ID())
	}

	hdr := buffer.NewPrependable(int(r.MaxHeaderLength()) + header.ICMPv6NeighborSolicitMinimumSize)
	pkt := header.ICMPv6(hdr.Prepend(header.ICMPv6NeighborSolicitMinimumSize))
	pkt.SetType(header.ICMPv6NeighborSolicit)
	ns := header.NDPNeighborSolicit(pkt.NDPPayload())
	ns.SetTargetAddress(addr)
	pkt.SetChecksum(header.ICMPv6Checksum(pkt, r.LocalAddress, r.RemoteAddress, buffer.VectorisedView{}))

	sent := r.Stats().ICMP.V6PacketsSent
	if err := r.WritePacket(nil,
		NetworkHeaderParams{
			Protocol: header.ICMPv6ProtocolNumber,
			TTL:      header.NDPHopLimit,
			TOS:      DefaultTOS,
		}, tcpip.PacketBuffer{Header: hdr},
	); err != nil {
		sent.Dropped.Increment()
		return err
	}
	sent.NeighborSolicit.Increment()

	return nil
}

// stopDuplicateAddressDetection ends a running Duplicate Address Detection
// process. Note, this may leave the DAD process for a tentative address in
// such a state forever, unless some other external event resolves the DAD
// process (receiving an NA from the true owner of addr, or an NS for addr
// (implying another node is attempting to use addr)). It is up to the caller
// of this function to handle such a scenario. Normally, addr will be removed
// from n right after this function returns or the address successfully
// resolved.
//
// The NIC that ndp belongs to MUST be locked.
func (ndp *ndpState) stopDuplicateAddressDetection(addr tcpip.Address) {
	dad, ok := ndp.dad[addr]
	if !ok {
		// Not currently performing DAD on addr, just return.
		return
	}

	if dad.timer != nil {
		dad.timer.Stop()
		dad.timer = nil

		*dad.done = true
		dad.done = nil
	}

	delete(ndp.dad, addr)

	// Let the integrator know DAD did not resolve.
	if ndpDisp := ndp.nic.stack.ndpDisp; ndpDisp != nil {
		ndpDisp.OnDuplicateAddressDetectionStatus(ndp.nic.ID(), addr, false, nil)
	}
}

// handleRA handles a Router Advertisement message that arrived on the NIC
// this ndp is for. Does nothing if the NIC is configured to not handle RAs.
//
// The NIC that ndp belongs to MUST be locked.
func (ndp *ndpState) handleRA(ip tcpip.Address, ra header.NDPRouterAdvert) {
	// Is the NIC configured to handle RAs at all?
	//
	// Currently, the stack does not determine router interface status on a
	// per-interface basis; it is a stack-wide configuration, so we check
	// stack's forwarding flag to determine if the NIC is a routing
	// interface.
	if !ndp.configs.HandleRAs || ndp.nic.stack.forwarding {
		return
	}

	// Only worry about the DHCPv6 configuration if we have an NDPDispatcher as we
	// only inform the dispatcher on configuration changes. We do nothing else
	// with the information.
	if ndpDisp := ndp.nic.stack.ndpDisp; ndpDisp != nil {
		var configuration DHCPv6ConfigurationFromNDPRA
		switch {
		case ra.ManagedAddrConfFlag():
			configuration = DHCPv6ManagedAddress

		case ra.OtherConfFlag():
			configuration = DHCPv6OtherConfigurations

		default:
			configuration = DHCPv6NoConfiguration
		}

		if ndp.dhcpv6Configuration != configuration {
			ndp.dhcpv6Configuration = configuration
			ndpDisp.OnDHCPv6Configuration(ndp.nic.ID(), configuration)
		}
	}

	// Is the NIC configured to discover default routers?
	if ndp.configs.DiscoverDefaultRouters {
		rtr, ok := ndp.defaultRouters[ip]
		rl := ra.RouterLifetime()
		switch {
		case !ok && rl != 0:
			// This is a new default router we are discovering.
			//
			// Only remember it if we currently know about less than
			// MaxDiscoveredDefaultRouters routers.
			if len(ndp.defaultRouters) < MaxDiscoveredDefaultRouters {
				ndp.rememberDefaultRouter(ip, rl)
			}

		case ok && rl != 0:
			// This is an already discovered default router. Update
			// the invalidation timer.
			rtr.invalidationTimer.StopLocked()
			rtr.invalidationTimer.Reset(rl)
			ndp.defaultRouters[ip] = rtr

		case ok && rl == 0:
			// We know about the router but it is no longer to be
			// used as a default router so invalidate it.
			ndp.invalidateDefaultRouter(ip)
		}
	}

	// TODO(b/141556115): Do (RetransTimer, ReachableTime)) Parameter
	//                    Discovery.

	// We know the options is valid as far as wire format is concerned since
	// we got the Router Advertisement, as documented by this fn. Given this
	// we do not check the iterator for errors on calls to Next.
	it, _ := ra.Options().Iter(false)
	for opt, done, _ := it.Next(); !done; opt, done, _ = it.Next() {
		switch opt := opt.(type) {
		case header.NDPRecursiveDNSServer:
			if ndp.nic.stack.ndpDisp == nil {
				continue
			}

			ndp.nic.stack.ndpDisp.OnRecursiveDNSServerOption(ndp.nic.ID(), opt.Addresses(), opt.Lifetime())

		case header.NDPPrefixInformation:
			prefix := opt.Subnet()

			// Is the prefix a link-local?
			if header.IsV6LinkLocalAddress(prefix.ID()) {
				// ...Yes, skip as per RFC 4861 section 6.3.4,
				// and RFC 4862 section 5.5.3.b (for SLAAC).
				continue
			}

			// Is the Prefix Length 0?
			if prefix.Prefix() == 0 {
				// ...Yes, skip as this is an invalid prefix
				// as all IPv6 addresses cannot be on-link.
				continue
			}

			if opt.OnLinkFlag() {
				ndp.handleOnLinkPrefixInformation(opt)
			}

			if opt.AutonomousAddressConfigurationFlag() {
				ndp.handleAutonomousPrefixInformation(opt)
			}
		}

		// TODO(b/141556115): Do (MTU) Parameter Discovery.
	}
}

// invalidateDefaultRouter invalidates a discovered default router.
//
// The NIC that ndp belongs to MUST be locked.
func (ndp *ndpState) invalidateDefaultRouter(ip tcpip.Address) {
	rtr, ok := ndp.defaultRouters[ip]

	// Is the router still discovered?
	if !ok {
		// ...Nope, do nothing further.
		return
	}

	rtr.invalidationTimer.StopLocked()

	delete(ndp.defaultRouters, ip)

	// Let the integrator know a discovered default router is invalidated.
	if ndpDisp := ndp.nic.stack.ndpDisp; ndpDisp != nil {
		ndpDisp.OnDefaultRouterInvalidated(ndp.nic.ID(), ip)
	}
}

// rememberDefaultRouter remembers a newly discovered default router with IPv6
// link-local address ip with lifetime rl.
//
// The router identified by ip MUST NOT already be known by the NIC.
//
// The NIC that ndp belongs to MUST be locked.
func (ndp *ndpState) rememberDefaultRouter(ip tcpip.Address, rl time.Duration) {
	ndpDisp := ndp.nic.stack.ndpDisp
	if ndpDisp == nil {
		return
	}

	// Inform the integrator when we discovered a default router.
	if !ndpDisp.OnDefaultRouterDiscovered(ndp.nic.ID(), ip) {
		// Informed by the integrator to not remember the router, do
		// nothing further.
		return
	}

	state := defaultRouterState{
		invalidationTimer: tcpip.MakeCancellableTimer(&ndp.nic.mu, func() {
			ndp.invalidateDefaultRouter(ip)
		}),
	}

	state.invalidationTimer.Reset(rl)

	ndp.defaultRouters[ip] = state
}

// rememberOnLinkPrefix remembers a newly discovered on-link prefix with IPv6
// address with prefix prefix with lifetime l.
//
// The prefix identified by prefix MUST NOT already be known.
//
// The NIC that ndp belongs to MUST be locked.
func (ndp *ndpState) rememberOnLinkPrefix(prefix tcpip.Subnet, l time.Duration) {
	ndpDisp := ndp.nic.stack.ndpDisp
	if ndpDisp == nil {
		return
	}

	// Inform the integrator when we discovered an on-link prefix.
	if !ndpDisp.OnOnLinkPrefixDiscovered(ndp.nic.ID(), prefix) {
		// Informed by the integrator to not remember the prefix, do
		// nothing further.
		return
	}

	state := onLinkPrefixState{
		invalidationTimer: tcpip.MakeCancellableTimer(&ndp.nic.mu, func() {
			ndp.invalidateOnLinkPrefix(prefix)
		}),
	}

	if l < header.NDPInfiniteLifetime {
		state.invalidationTimer.Reset(l)
	}

	ndp.onLinkPrefixes[prefix] = state
}

// invalidateOnLinkPrefix invalidates a discovered on-link prefix.
//
// The NIC that ndp belongs to MUST be locked.
func (ndp *ndpState) invalidateOnLinkPrefix(prefix tcpip.Subnet) {
	s, ok := ndp.onLinkPrefixes[prefix]

	// Is the on-link prefix still discovered?
	if !ok {
		// ...Nope, do nothing further.
		return
	}

	s.invalidationTimer.StopLocked()

	delete(ndp.onLinkPrefixes, prefix)

	// Let the integrator know a discovered on-link prefix is invalidated.
	if ndpDisp := ndp.nic.stack.ndpDisp; ndpDisp != nil {
		ndpDisp.OnOnLinkPrefixInvalidated(ndp.nic.ID(), prefix)
	}
}

// handleOnLinkPrefixInformation handles a Prefix Information option with
// its on-link flag set, as per RFC 4861 section 6.3.4.
//
// handleOnLinkPrefixInformation assumes that the prefix this pi is for is
// not the link-local prefix and the on-link flag is set.
//
// The NIC that ndp belongs to MUST be locked.
func (ndp *ndpState) handleOnLinkPrefixInformation(pi header.NDPPrefixInformation) {
	prefix := pi.Subnet()
	prefixState, ok := ndp.onLinkPrefixes[prefix]
	vl := pi.ValidLifetime()

	if !ok && vl == 0 {
		// Don't know about this prefix but it has a zero valid
		// lifetime, so just ignore.
		return
	}

	if !ok && vl != 0 {
		// This is a new on-link prefix we are discovering
		//
		// Only remember it if we currently know about less than
		// MaxDiscoveredOnLinkPrefixes on-link prefixes.
		if ndp.configs.DiscoverOnLinkPrefixes && len(ndp.onLinkPrefixes) < MaxDiscoveredOnLinkPrefixes {
			ndp.rememberOnLinkPrefix(prefix, vl)
		}
		return
	}

	if ok && vl == 0 {
		// We know about the on-link prefix, but it is
		// no longer to be considered on-link, so
		// invalidate it.
		ndp.invalidateOnLinkPrefix(prefix)
		return
	}

	// This is an already discovered on-link prefix with a
	// new non-zero valid lifetime.
	//
	// Update the invalidation timer.

	prefixState.invalidationTimer.StopLocked()

	if vl < header.NDPInfiniteLifetime {
		// Prefix is valid for a finite lifetime, reset the timer to expire after
		// the new valid lifetime.
		prefixState.invalidationTimer.Reset(vl)
	}

	ndp.onLinkPrefixes[prefix] = prefixState
}

// handleAutonomousPrefixInformation handles a Prefix Information option with
// its autonomous flag set, as per RFC 4862 section 5.5.3.
//
// handleAutonomousPrefixInformation assumes that the prefix this pi is for is
// not the link-local prefix and the autonomous flag is set.
//
// The NIC that ndp belongs to MUST be locked.
func (ndp *ndpState) handleAutonomousPrefixInformation(pi header.NDPPrefixInformation) {
	vl := pi.ValidLifetime()
	pl := pi.PreferredLifetime()

	// If the preferred lifetime is greater than the valid lifetime,
	// silently ignore the Prefix Information option, as per RFC 4862
	// section 5.5.3.c.
	if pl > vl {
		return
	}

	prefix := pi.Subnet()

	// Check if we already have an auto-generated address for prefix.
	for addr, addrState := range ndp.autoGenAddresses {
		refAddrWithPrefix := tcpip.AddressWithPrefix{Address: addr, PrefixLen: addrState.ref.ep.PrefixLen()}
		if refAddrWithPrefix.Subnet() != prefix {
			continue
		}

		// At this point, we know we are refreshing a SLAAC generated IPv6 address
		// with the prefix prefix. Do the work as outlined by RFC 4862 section
		// 5.5.3.e.
		ndp.refreshAutoGenAddressLifetimes(addr, pl, vl)
		return
	}

	// We do not already have an address with the prefix prefix. Do the
	// work as outlined by RFC 4862 section 5.5.3.d if n is configured
	// to auto-generate global addresses by SLAAC.
	if !ndp.configs.AutoGenGlobalAddresses {
		return
	}

	ndp.doSLAAC(prefix, pl, vl)
}

// doSLAAC generates a new SLAAC address with the provided lifetimes
// for prefix.
//
// pl is the new preferred lifetime. vl is the new valid lifetime.
func (ndp *ndpState) doSLAAC(prefix tcpip.Subnet, pl, vl time.Duration) {
	// If we do not already have an address for this prefix and the valid
	// lifetime is 0, no need to do anything further, as per RFC 4862
	// section 5.5.3.d.
	if vl == 0 {
		return
	}

	// Make sure the prefix is valid (as far as its length is concerned) to
	// generate a valid IPv6 address from an interface identifier (IID), as
	// per RFC 4862 sectiion 5.5.3.d.
	if prefix.Prefix() != validPrefixLenForAutoGen {
		return
	}

	addrBytes := []byte(prefix.ID())
	if oIID := ndp.nic.stack.opaqueIIDOpts; oIID.NICNameFromID != nil {
		addrBytes = header.AppendOpaqueInterfaceIdentifier(addrBytes[:header.IIDOffsetInIPv6Address], prefix, oIID.NICNameFromID(ndp.nic.ID(), ndp.nic.name), 0 /* dadCounter */, oIID.SecretKey)
	} else {
		// Only attempt to generate an interface-specific IID if we have a valid
		// link address.
		//
		// TODO(b/141011931): Validate a LinkEndpoint's link address (provided by
		// LinkEndpoint.LinkAddress) before reaching this point.
		linkAddr := ndp.nic.linkEP.LinkAddress()
		if !header.IsValidUnicastEthernetAddress(linkAddr) {
			return
		}

		// Generate an address within prefix from the modified EUI-64 of ndp's NIC's
		// Ethernet MAC address.
		header.EthernetAdddressToModifiedEUI64IntoBuf(linkAddr, addrBytes[header.IIDOffsetInIPv6Address:])
	}
	addr := tcpip.Address(addrBytes)
	addrWithPrefix := tcpip.AddressWithPrefix{
		Address:   addr,
		PrefixLen: validPrefixLenForAutoGen,
	}

	// If the nic already has this address, do nothing further.
	if ndp.nic.hasPermanentAddrLocked(addr) {
		return
	}

	// Inform the integrator that we have a new SLAAC address.
	ndpDisp := ndp.nic.stack.ndpDisp
	if ndpDisp == nil {
		return
	}
	if !ndpDisp.OnAutoGenAddress(ndp.nic.ID(), addrWithPrefix) {
		// Informed by the integrator not to add the address.
		return
	}

	protocolAddr := tcpip.ProtocolAddress{
		Protocol:          header.IPv6ProtocolNumber,
		AddressWithPrefix: addrWithPrefix,
	}
	// If the preferred lifetime is zero, then the address should be considered
	// deprecated.
	deprecated := pl == 0
	ref, err := ndp.nic.addAddressLocked(protocolAddr, FirstPrimaryEndpoint, permanent, slaac, deprecated)
	if err != nil {
		log.Fatalf("ndp: error when adding address %s: %s", protocolAddr, err)
	}

	state := autoGenAddressState{
		ref: ref,
		deprecationTimer: tcpip.MakeCancellableTimer(&ndp.nic.mu, func() {
			addrState, ok := ndp.autoGenAddresses[addr]
			if !ok {
				log.Fatalf("ndp: must have an autoGenAddressess entry for the SLAAC generated IPv6 address %s", addr)
			}
			addrState.ref.deprecated = true
			ndp.notifyAutoGenAddressDeprecated(addr)
		}),
		invalidationTimer: tcpip.MakeCancellableTimer(&ndp.nic.mu, func() {
			ndp.invalidateAutoGenAddress(addr)
		}),
	}

	// Setup the initial timers to deprecate and invalidate this newly generated
	// address.

	if !deprecated && pl < header.NDPInfiniteLifetime {
		state.deprecationTimer.Reset(pl)
	}

	if vl < header.NDPInfiniteLifetime {
		state.invalidationTimer.Reset(vl)
		state.validUntil = time.Now().Add(vl)
	}

	ndp.autoGenAddresses[addr] = state
}

// refreshAutoGenAddressLifetimes refreshes the lifetime of a SLAAC generated
// address addr.
//
// pl is the new preferred lifetime. vl is the new valid lifetime.
func (ndp *ndpState) refreshAutoGenAddressLifetimes(addr tcpip.Address, pl, vl time.Duration) {
	addrState, ok := ndp.autoGenAddresses[addr]
	if !ok {
		log.Fatalf("ndp: SLAAC state not found to refresh lifetimes for %s", addr)
	}
	defer func() { ndp.autoGenAddresses[addr] = addrState }()

	// If the preferred lifetime is zero, then the address should be considered
	// deprecated.
	deprecated := pl == 0
	wasDeprecated := addrState.ref.deprecated
	addrState.ref.deprecated = deprecated

	// Only send the deprecation event if the deprecated status for addr just
	// changed from non-deprecated to deprecated.
	if !wasDeprecated && deprecated {
		ndp.notifyAutoGenAddressDeprecated(addr)
	}

	// If addr was preferred for some finite lifetime before, stop the deprecation
	// timer so it can be reset.
	addrState.deprecationTimer.StopLocked()

	// Reset the deprecation timer if addr has a finite preferred lifetime.
	if !deprecated && pl < header.NDPInfiniteLifetime {
		addrState.deprecationTimer.Reset(pl)
	}

	// As per RFC 4862 section 5.5.3.e, the valid lifetime of the address
	//
	//
	// 1) If the received Valid Lifetime is greater than 2 hours or greater than
	//    RemainingLifetime, set the valid lifetime of the address to the
	//    advertised Valid Lifetime.
	//
	// 2) If RemainingLifetime is less than or equal to 2 hours, ignore the
	//    advertised Valid Lifetime.
	//
	// 3) Otherwise, reset the valid lifetime of the address to 2 hours.

	// Handle the infinite valid lifetime separately as we do not keep a timer in
	// this case.
	if vl >= header.NDPInfiniteLifetime {
		addrState.invalidationTimer.StopLocked()
		addrState.validUntil = time.Time{}
		return
	}

	var effectiveVl time.Duration
	var rl time.Duration

	// If the address was originally set to be valid forever, assume the remaining
	// time to be the maximum possible value.
	if addrState.validUntil == (time.Time{}) {
		rl = header.NDPInfiniteLifetime
	} else {
		rl = time.Until(addrState.validUntil)
	}

	if vl > MinPrefixInformationValidLifetimeForUpdate || vl > rl {
		effectiveVl = vl
	} else if rl <= MinPrefixInformationValidLifetimeForUpdate {
		return
	} else {
		effectiveVl = MinPrefixInformationValidLifetimeForUpdate
	}

	addrState.invalidationTimer.StopLocked()
	addrState.invalidationTimer.Reset(effectiveVl)
	addrState.validUntil = time.Now().Add(effectiveVl)
}

// notifyAutoGenAddressDeprecated notifies the stack's NDP dispatcher that addr
// has been deprecated.
func (ndp *ndpState) notifyAutoGenAddressDeprecated(addr tcpip.Address) {
	if ndpDisp := ndp.nic.stack.ndpDisp; ndpDisp != nil {
		ndpDisp.OnAutoGenAddressDeprecated(ndp.nic.ID(), tcpip.AddressWithPrefix{
			Address:   addr,
			PrefixLen: validPrefixLenForAutoGen,
		})
	}
}

// invalidateAutoGenAddress invalidates an auto-generated address.
//
// The NIC that ndp belongs to MUST be locked.
func (ndp *ndpState) invalidateAutoGenAddress(addr tcpip.Address) {
	if !ndp.cleanupAutoGenAddrResourcesAndNotify(addr) {
		return
	}

	ndp.nic.removePermanentAddressLocked(addr)
}

// cleanupAutoGenAddrResourcesAndNotify cleans up an invalidated auto-generated
// address's resources from ndp. If the stack has an NDP dispatcher, it will
// be notified that addr has been invalidated.
//
// Returns true if ndp had resources for addr to cleanup.
//
// The NIC that ndp belongs to MUST be locked.
func (ndp *ndpState) cleanupAutoGenAddrResourcesAndNotify(addr tcpip.Address) bool {
	state, ok := ndp.autoGenAddresses[addr]
	if !ok {
		return false
	}

	state.deprecationTimer.StopLocked()
	state.invalidationTimer.StopLocked()
	delete(ndp.autoGenAddresses, addr)

	if ndpDisp := ndp.nic.stack.ndpDisp; ndpDisp != nil {
		ndpDisp.OnAutoGenAddressInvalidated(ndp.nic.ID(), tcpip.AddressWithPrefix{
			Address:   addr,
			PrefixLen: validPrefixLenForAutoGen,
		})
	}

	return true
}

// cleanupHostOnlyState cleans up any state that is only useful for hosts.
//
// cleanupHostOnlyState MUST be called when ndp's NIC is transitioning from a
// host to a router. This function will invalidate all discovered on-link
// prefixes, discovered routers, and auto-generated addresses as routers do not
// normally process Router Advertisements to discover default routers and
// on-link prefixes, and auto-generate addresses via SLAAC.
//
// The NIC that ndp belongs to MUST be locked.
func (ndp *ndpState) cleanupHostOnlyState() {
	linkLocalSubnet := header.IPv6LinkLocalPrefix.Subnet()
	linkLocalAddrs := 0
	for addr := range ndp.autoGenAddresses {
		// RFC 4862 section 5 states that routers are also expected to generate a
		// link-local address so we do not invalidate them.
		if linkLocalSubnet.Contains(addr) {
			linkLocalAddrs++
			continue
		}

		ndp.invalidateAutoGenAddress(addr)
	}

	if got := len(ndp.autoGenAddresses); got != linkLocalAddrs {
		log.Fatalf("ndp: still have non-linklocal auto-generated addresses after cleaning up; found = %d prefixes, of which %d are link-local", got, linkLocalAddrs)
	}

	for prefix := range ndp.onLinkPrefixes {
		ndp.invalidateOnLinkPrefix(prefix)
	}

	if got := len(ndp.onLinkPrefixes); got != 0 {
		log.Fatalf("ndp: still have discovered on-link prefixes after cleaning up; found = %d", got)
	}

	for router := range ndp.defaultRouters {
		ndp.invalidateDefaultRouter(router)
	}

	if got := len(ndp.defaultRouters); got != 0 {
		log.Fatalf("ndp: still have discovered default routers after cleaning up; found = %d", got)
	}
}

// startSolicitingRouters starts soliciting routers, as per RFC 4861 section
// 6.3.7. If routers are already being solicited, this function does nothing.
//
// The NIC ndp belongs to MUST be locked.
func (ndp *ndpState) startSolicitingRouters() {
	if ndp.rtrSolicitTimer != nil {
		// We are already soliciting routers.
		return
	}

	remaining := ndp.configs.MaxRtrSolicitations
	if remaining == 0 {
		return
	}

	// Calculate the random delay before sending our first RS, as per RFC
	// 4861 section 6.3.7.
	var delay time.Duration
	if ndp.configs.MaxRtrSolicitationDelay > 0 {
		delay = time.Duration(rand.Int63n(int64(ndp.configs.MaxRtrSolicitationDelay)))
	}

	ndp.rtrSolicitTimer = time.AfterFunc(delay, func() {
		// Send an RS message with the unspecified source address.
		ref := ndp.nic.getRefOrCreateTemp(header.IPv6ProtocolNumber, header.IPv6Any, NeverPrimaryEndpoint, forceSpoofing)
		r := makeRoute(header.IPv6ProtocolNumber, header.IPv6Any, header.IPv6AllRoutersMulticastAddress, ndp.nic.linkEP.LinkAddress(), ref, false, false)
		defer r.Release()

		// Route should resolve immediately since
		// header.IPv6AllRoutersMulticastAddress is a multicast address so a
		// remote link address can be calculated without a resolution process.
		if c, err := r.Resolve(nil); err != nil {
			log.Fatalf("ndp: error when resolving route to send NDP RS (%s -> %s on NIC(%d)): %s", header.IPv6Any, header.IPv6AllRoutersMulticastAddress, ndp.nic.ID(), err)
		} else if c != nil {
			log.Fatalf("ndp: route resolution not immediate for route to send NDP RS (%s -> %s on NIC(%d))", header.IPv6Any, header.IPv6AllRoutersMulticastAddress, ndp.nic.ID())
		}

		payloadSize := header.ICMPv6HeaderSize + header.NDPRSMinimumSize
		hdr := buffer.NewPrependable(header.IPv6MinimumSize + payloadSize)
		pkt := header.ICMPv6(hdr.Prepend(payloadSize))
		pkt.SetType(header.ICMPv6RouterSolicit)
		pkt.SetChecksum(header.ICMPv6Checksum(pkt, r.LocalAddress, r.RemoteAddress, buffer.VectorisedView{}))

		sent := r.Stats().ICMP.V6PacketsSent
		if err := r.WritePacket(nil,
			NetworkHeaderParams{
				Protocol: header.ICMPv6ProtocolNumber,
				TTL:      header.NDPHopLimit,
				TOS:      DefaultTOS,
			}, tcpip.PacketBuffer{Header: hdr},
		); err != nil {
			sent.Dropped.Increment()
			log.Printf("startSolicitingRouters: error writing NDP router solicit message on NIC(%d); err = %s", ndp.nic.ID(), err)
			// Don't send any more messages if we had an error.
			remaining = 0
		} else {
			sent.RouterSolicit.Increment()
			remaining--
		}

		ndp.nic.mu.Lock()
		defer ndp.nic.mu.Unlock()
		if remaining == 0 {
			ndp.rtrSolicitTimer = nil
		} else if ndp.rtrSolicitTimer != nil {
			// Note, we need to explicitly check to make sure that
			// the timer field is not nil because if it was nil but
			// we still reached this point, then we know the NIC
			// was requested to stop soliciting routers so we don't
			// need to send the next Router Solicitation message.
			ndp.rtrSolicitTimer.Reset(ndp.configs.RtrSolicitationInterval)
		}
	})

}

// stopSolicitingRouters stops soliciting routers. If routers are not currently
// being solicited, this function does nothing.
//
// The NIC ndp belongs to MUST be locked.
func (ndp *ndpState) stopSolicitingRouters() {
	if ndp.rtrSolicitTimer == nil {
		// Nothing to do.
		return
	}

	ndp.rtrSolicitTimer.Stop()
	ndp.rtrSolicitTimer = nil
}
