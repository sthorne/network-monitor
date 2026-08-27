package dnsmon

import (
	"net/netip"
	"time"

	"github.com/sthorne/network-monitor/internal/capture"
)

// Side is which half of the recursive resolver a transaction belongs to.
type Side uint8

const (
	// SideClient is the left side: a client querying the resolver.
	SideClient Side = iota
	// SideUpstream is the right side: the resolver querying an upstream or
	// authoritative server.
	SideUpstream
	sideCount
)

func (s Side) String() string {
	if s == SideUpstream {
		return "upstream"
	}
	return "client"
}

// TxnState is the lifecycle of one query/response transaction.
type TxnState uint8

const (
	TxnPending TxnState = iota
	TxnAnswered
	TxnTimeout
)

func (s TxnState) String() string {
	switch s {
	case TxnAnswered:
		return "answered"
	case TxnTimeout:
		return "timeout"
	}
	return "pending"
}

// Row is a value-type projection of one DNS transaction for the UI. It shares
// no memory with live tracker state.
type Row struct {
	Side  Side
	Proto capture.Proto

	// Querier → Server is the query direction: on the client side the querier
	// is the client and the server the resolver; on the upstream side the
	// querier is the resolver and the server the upstream/auth.
	Querier     netip.Addr
	QuerierPort uint16
	Server      netip.Addr
	ServerPort  uint16

	QID   uint16
	QName string
	QType uint16

	State   TxnState
	RCode   uint8
	Answers uint16
	TC      bool
	Retries uint32

	QueryTS, RespTS time.Time
}

// Latency is query→response time; zero unless answered.
func (r *Row) Latency() time.Duration {
	if r.State != TxnAnswered {
		return 0
	}
	return r.RespTS.Sub(r.QueryTS)
}

// SideStats aggregates one side's transactions at snapshot time.
type SideStats struct {
	Queries, Answered, Pending, Timeout uint64
	Retries                             uint64
	RCodes                              map[uint8]uint64
}

// Snapshot is the tracker state copy handed to the UI on each tick. Rows are
// in query-arrival order (oldest first).
type Snapshot struct {
	Now       time.Time
	Rows      []Row
	Resolvers []netip.Addr
	Sides     [sideCount]SideStats

	TotalMsgs  uint64 // parsed DNS messages
	TotalBytes uint64
	Malformed  uint64 // port-53 packets that failed to parse
	Orphans    uint64 // responses with no matching pending query
	Evicted    uint64 // transactions dropped by the ring cap
	EOF        bool
}
