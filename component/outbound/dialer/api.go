package dialer

import "time"

type HealthSnapshot struct {
	Alive              bool
	LastLatency        time.Duration
	LastLatencyOK      bool
	Average10Latency   time.Duration
	Average10LatencyOK bool
	MovingAverage      time.Duration
	MovingAverageOK    bool
}

func (d *Dialer) SnapshotHealth(typ *NetworkType) HealthSnapshot {
	collection := d.mustGetCollection(typ)
	snapshot := HealthSnapshot{
		Alive: collection.Alive.Load(),
	}
	snapshot.LastLatency, snapshot.LastLatencyOK = collection.Latencies10.LastLatency()
	snapshot.Average10Latency, snapshot.Average10LatencyOK = collection.Latencies10.AvgLatency()

	d.collectionFineMu.RLock()
	snapshot.MovingAverage = collection.MovingAverage
	snapshot.MovingAverageOK = snapshot.MovingAverage > 0
	d.collectionFineMu.RUnlock()
	return snapshot
}
