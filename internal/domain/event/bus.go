package event

import (
	"sync"
)

type EventType string

const (
	EventStateChanged   EventType = "state_changed"
	EventNetworkChanged EventType = "network_changed"
	EventConfigChanged  EventType = "config_changed"
	EventAuthSuccess    EventType = "auth_success"
	EventAuthFailed     EventType = "auth_failed"
)

type Event struct {
	Type    EventType
	Payload any
}

type Listener func(e Event)

// Bus implements a thread-safe publish-subscribe event bus.
type Bus struct {
	mu        sync.RWMutex
	listeners map[EventType][]Listener
}

func NewBus() *Bus {
	return &Bus{
		listeners: make(map[EventType][]Listener),
	}
}

func (b *Bus) Subscribe(t EventType, l Listener) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.listeners[t] = append(b.listeners[t], l)
}

func (b *Bus) Publish(e Event) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	for _, l := range b.listeners[e.Type] {
		go l(e)
	}
}
