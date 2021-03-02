package block

import (
	"context"
	"fmt"
	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/request"
	"github.com/miekg/dns"
)

type Blocker struct {
	Next  plugin.Handler
	Rules map[string]Rule
	Zones plugin.Zones
}

func (b Blocker) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	state := request.Request{W: w, Req: r}
	qname := state.QName()
	zone := b.Zones.Matches(qname)
	if zone == "" {
		return plugin.NextOrFailure(b.Name(), b.Next, ctx, w, r)
	}
	resp := new(dns.Msg)
	resp.SetReply(r)
	resp.Answer = []dns.RR{}

	err := w.WriteMsg(resp)
	return dns.RcodeSuccess, err
}

func (b Blocker) Name() string {
	return "block"
}

type Rule struct {
	RecordTypes []RecordType
}

type RecordType string

const (
	All   RecordType = "*"
	NS    RecordType = "NS"
	A     RecordType = "A"
	AAAA  RecordType = "AAAA"
	SRV   RecordType = "SRV"
	TXT   RecordType = "TXT"
	CNAME RecordType = "CNAME"
	MX    RecordType = "MX"
	PTR   RecordType = "PTR"
	SOA   RecordType = "SOA"
	CAA   RecordType = "CAA"
)

func RecordTypefromString(s string) (RecordType, error) {
	switch s {
	case "*":
		return All, nil
	case "NS":
		return NS, nil
	case "A":
		return A, nil
	case "AAAA":
		return AAAA, nil
	case "SRV":
		return SRV, nil
	case "TXT":
		return TXT, nil
	case "CNAME":
		return CNAME, nil
	case "MX":
		return MX, nil
	case "PTR":
		return PTR, nil
	case "SOA":
		return SOA, nil
	case "CAA":
		return CAA, nil
	default:
		return "", plugin.Error("block", fmt.Errorf("Unrecogniced RecordType: %s", s))
	}
}
