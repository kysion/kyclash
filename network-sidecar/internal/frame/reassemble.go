package frame

import (
	"time"
)

const defaultMaxAssemblies = 16

type assembly struct {
	count     uint16
	parts     [][]byte
	received  uint16
	total     int
	expiresAt time.Time
}

type Reassembler struct {
	assemblies map[uint64]*assembly
	completed  map[uint64]time.Time
	ttl        time.Duration
	max        int
	now        func() time.Time
}

func NewReassembler(ttl time.Duration) *Reassembler {
	return &Reassembler{
		assemblies: make(map[uint64]*assembly),
		completed:  make(map[uint64]time.Time),
		ttl:        ttl,
		max:        defaultMaxAssemblies,
		now:        time.Now,
	}
}

func (reassembler *Reassembler) Accept(frame Frame) ([]byte, bool, error) {
	if err := frame.Validate(); err != nil {
		return nil, false, err
	}
	if frame.Fragment == nil {
		return frame.Payload, true, nil
	}
	if reassembler.ttl <= 0 {
		return nil, false, ErrInvalidFragment
	}
	now := reassembler.now()
	reassembler.expire(now)
	fragment := frame.Fragment
	if _, exists := reassembler.completed[fragment.MessageID]; exists {
		return nil, false, ErrDuplicateFragment
	}
	current, exists := reassembler.assemblies[fragment.MessageID]
	if !exists {
		if len(reassembler.assemblies) >= reassembler.max {
			return nil, false, ErrAssemblyLimit
		}
		current = &assembly{
			count:     fragment.Count,
			parts:     make([][]byte, fragment.Count),
			expiresAt: now.Add(reassembler.ttl),
		}
		reassembler.assemblies[fragment.MessageID] = current
	}
	if current.count != fragment.Count {
		return nil, false, ErrInvalidFragment
	}
	if current.parts[fragment.Index] != nil {
		return nil, false, ErrDuplicateFragment
	}
	if current.total+len(frame.Payload) > MaxPayloadSize {
		delete(reassembler.assemblies, fragment.MessageID)
		return nil, false, ErrPayloadTooLarge
	}
	current.parts[fragment.Index] = append([]byte(nil), frame.Payload...)
	current.received++
	current.total += len(frame.Payload)
	if current.received != current.count {
		return nil, false, nil
	}
	packet := make([]byte, 0, current.total)
	for _, part := range current.parts {
		packet = append(packet, part...)
	}
	delete(reassembler.assemblies, fragment.MessageID)
	reassembler.completed[fragment.MessageID] = now.Add(reassembler.ttl)
	return packet, true, nil
}

func (reassembler *Reassembler) expire(now time.Time) {
	for messageID, current := range reassembler.assemblies {
		if !now.Before(current.expiresAt) {
			delete(reassembler.assemblies, messageID)
		}
	}
	for messageID, expiresAt := range reassembler.completed {
		if !now.Before(expiresAt) {
			delete(reassembler.completed, messageID)
		}
	}
}

func (reassembler *Reassembler) Reset() {
	clear(reassembler.assemblies)
	clear(reassembler.completed)
}
