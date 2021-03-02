package block

import (
	"context"
	"fmt"
	"github.com/coredns/coredns/plugin"
	clog "github.com/coredns/coredns/plugin/pkg/log"
	"github.com/coredns/coredns/request"
	"github.com/miekg/dns"
)

var log = clog.NewWithPlugin("block")

type Blocker struct {
	Next  plugin.Handler
	Rules map[string]Rule
}

type Rule struct {
	RecordTypes []uint16
}

func (b Blocker) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	state := request.Request{W: w, Req: r}
	qname := state.QName()
	zone := b.match(qname)
	if !b.matchQuestion(r, zone) {
		return plugin.NextOrFailure(b.Name(), b.Next, ctx, w, r)
	}
	resp := new(dns.Msg)
	resp.SetReply(r)
	resp.Answer = []dns.RR{}

	err := w.WriteMsg(resp)
	return dns.RcodeSuccess, err
}

func (b Blocker) match(name string) string {
	for zone := range b.Rules {
		log.Debugf("Check if %s matches %s", zone, name)
		if zone == name {
			log.Debugf("%s did match %s", zone, name)
			return zone
		}
	}
	return ""
}

func (b Blocker) matchQuestion(r *dns.Msg, zone string) bool {
	if zone == "" {
		return false
	}
	log.Debugf("Searching Rule for %s", zone)
	for _, question := range r.Question {
		log.Debugf("Compare Type %v with Rule %v", question.Qtype, b.Rules[zone].RecordTypes)
		if typeInSlice(question.Qtype, b.Rules[zone].RecordTypes) {
			return true
		}
	}
	return false
}

func (b Blocker) Name() string {
	return "block"
}

const (
	All   = dns.TypeANY
	NS    = dns.TypeNS
	A     = dns.TypeA
	AAAA  = dns.TypeAAAA
	SRV   = dns.TypeSRV
	TXT   = dns.TypeTXT
	CNAME = dns.TypeCNAME
	MX    = dns.TypeMX
	PTR   = dns.TypePTR
	SOA   = dns.TypeSOA
	CAA   = dns.TypeCAA
)

func RecordTypefromString(s string) (uint16, error) {
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
		return 0, plugin.Error("block", fmt.Errorf("Unrecogniced RecordType: %s", s))
	}
}

func typeInSlice(a uint16, list []uint16) bool {
	for _, b := range list {
		fmt.Println(a, b)
		if b == a {
			return true
		}
	}
	return false
}
