package controlapi

import (
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

type LogField struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type LogEvent struct {
	Time    time.Time    `json:"time"`
	Level   logrus.Level `json:"-"`
	Type    string       `json:"type"`
	Payload string       `json:"payload"`
	Fields  []LogField   `json:"fields"`
}

type logSubscription struct {
	minLevel logrus.Level
	ch       chan LogEvent
}

type LogBroker struct {
	mu     sync.RWMutex
	nextID int
	subs   map[int]logSubscription
}

func NewLogBroker() *LogBroker {
	return &LogBroker{
		subs: make(map[int]logSubscription),
	}
}

func (b *LogBroker) Hook() logrus.Hook {
	return logBrokerHook{broker: b}
}

func (b *LogBroker) Subscribe(minLevel logrus.Level) (<-chan LogEvent, func()) {
	ch := make(chan LogEvent, 256)

	b.mu.Lock()
	id := b.nextID
	b.nextID++
	b.subs[id] = logSubscription{
		minLevel: minLevel,
		ch:       ch,
	}
	b.mu.Unlock()

	unsubscribe := func() {
		b.mu.Lock()
		sub, ok := b.subs[id]
		if ok {
			delete(b.subs, id)
		}
		b.mu.Unlock()
		if ok {
			close(sub.ch)
		}
	}
	return ch, unsubscribe
}

func (b *LogBroker) publish(event LogEvent) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	for _, sub := range b.subs {
		if event.Level > sub.minLevel {
			continue
		}
		select {
		case sub.ch <- event:
		default:
		}
	}
}

type logBrokerHook struct {
	broker *LogBroker
}

func (h logBrokerHook) Levels() []logrus.Level {
	return logrus.AllLevels
}

func (h logBrokerHook) Fire(entry *logrus.Entry) error {
	if h.broker == nil || entry == nil {
		return nil
	}

	fields := make([]LogField, 0, len(entry.Data))
	for key, value := range entry.Data {
		fields = append(fields, LogField{
			Key:   key,
			Value: toString(value),
		})
	}
	sort.Slice(fields, func(i, j int) bool {
		return fields[i].Key < fields[j].Key
	})

	h.broker.publish(LogEvent{
		Time:    entry.Time,
		Level:   entry.Level,
		Type:    entry.Level.String(),
		Payload: entry.Message,
		Fields:  fields,
	})
	return nil
}

func toString(v any) string {
	return fmt.Sprint(v)
}
