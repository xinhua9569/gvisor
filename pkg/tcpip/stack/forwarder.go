// Copyright 2020 The gVisor Authors.
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

	"gvisor.dev/gvisor/pkg/ilist"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/tcpip"
)

const (
	// maxPendingResolutions is the maximum number of pending link-address
	// resolutions.
	maxPendingResolutions          = 64
	maxPendingPacketsPerResolution = 256
)

type pendingPacket struct {
	ilist.Entry
	nic   *NIC
	route *Route
	proto tcpip.NetworkProtocolNumber
	pkt   tcpip.PacketBuffer
}

type packetList struct {
	ilist.List
	count int
}

func (l *packetList) PopFront() *pendingPacket {
	if l.List.Empty() {
		return nil
	}
	e := l.List.Front()
	p := e.(*pendingPacket)
	l.List.Remove(e)
	l.count--
	return p
}

func (l *packetList) PushBack(p *pendingPacket) {
	l.List.PushBack(p)
	l.count++
}

func (l *packetList) Len() int {
	return l.count
}

type forwardQueue struct {
	sync.Mutex

	// The packets to send once the resolver completes.
	packets map[<-chan struct{}]*packetList

	// FIFO of channels used to cancel the oldest goroutine waiting for
	// link-address resolution.
	cancelChans cancelChanList
}

func newForwardQueue() forwardQueue {
	return forwardQueue{packets: make(map[<-chan struct{}]*packetList)}
}

func (f *forwardQueue) enqueue(ch <-chan struct{}, n *NIC, r *Route, protocol tcpip.NetworkProtocolNumber, pkt tcpip.PacketBuffer) {
	shouldWait := false

	f.Lock()
	packets, ok := f.packets[ch]
	if !ok {
		f.packets[ch] = &packetList{}
		packets = f.packets[ch]
		shouldWait = true
	}
	for packets.Len() == maxPendingPacketsPerResolution {
		p := packets.PopFront()
		p.nic.stack.stats.IP.OutgoingPacketErrors.Increment()
		p.route.Release()
	}
	if packets.Len() >= maxPendingPacketsPerResolution {
		log.Fatalf("max pending packets for resolution reached; got %d packets, max = %d", packets.Len(), maxPendingPacketsPerResolution)
	}
	packets.PushBack(&pendingPacket{
		nic:   n,
		route: r,
		proto: protocol,
		pkt:   pkt,
	})
	f.Unlock()

	if !shouldWait {
		return
	}

	// Wait for the link-address resolution to complete.
	// Start a goroutine with a forwarding-cancel channel so that we can
	// limit the maximum number of goroutines running concurrently.
	cancel := f.newCancelChannel()
	go func() {
		cancelled := false
		select {
		case <-ch:
		case <-cancel:
			cancelled = true
		}

		f.Lock()
		packets := f.packets[ch]
		delete(f.packets, ch)
		f.Unlock()

		for p := packets.PopFront(); p != nil; p = packets.PopFront() {
			if cancelled {
				p.nic.stack.stats.IP.OutgoingPacketErrors.Increment()
			} else if _, err := p.route.Resolve(nil); err != nil {
				p.nic.stack.stats.IP.OutgoingPacketErrors.Increment()
			} else {
				p.nic.writeForwardingPacket(p.route, p.proto, p.pkt)
			}
			p.route.Release()
		}
	}()
}

type cancelChan struct {
	ilist.Entry
	ch chan struct{}
}

type cancelChanList struct {
	ilist.List
	count int
}

func (l *cancelChanList) PopFront() *cancelChan {
	if l.List.Empty() {
		return nil
	}
	e := l.List.Front()
	c := e.(*cancelChan)
	l.List.Remove(e)
	l.count--
	return c
}

func (l *cancelChanList) PushBack(c *cancelChan) {
	l.List.PushBack(c)
	l.count++
}

func (l *cancelChanList) Len() int {
	return l.count
}

// newCancelChannel creates a channel that can cancel a pending forwarding
// activity. The oldest channel is closed if the number of open channels would
// exceed maxPendingResolutions.
func (f *forwardQueue) newCancelChannel() chan struct{} {
	f.Lock()
	defer f.Unlock()

	if f.cancelChans.Len() == maxPendingResolutions {
		c := f.cancelChans.PopFront()
		close(c.ch)
	}
	if f.cancelChans.Len() >= maxPendingResolutions {
		log.Fatalf("max pending resolutions reached; got %d active resolutions, max = %d", f.cancelChans.Len(), maxPendingResolutions)
	}

	c := &cancelChan{ch: make(chan struct{})}
	f.cancelChans.PushBack(c)
	return c.ch
}
