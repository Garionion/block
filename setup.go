package block

import (
	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
)

// init registers this plugin.
func init() { plugin.Register("block", setup) }

// setup is the function that gets called when the config parser see the token "example". Setup is responsible
// for parsing any extra options the example plugin may have. The first token this function sees is "example".
func setup(c *caddy.Controller) error {
	rules, err := blockParser(c)
	if err != nil {
		return plugin.Error("block", err)
	}

	// Add the Plugin to CoreDNS, so Servers can use it in their plugin chain.
	dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
		return Blocker{Next: next, Rules: rules}
	})

	// All OK, return a nil error.
	return nil
}

func blockParser(c *caddy.Controller) (map[string]Rule, error) {
	rules := make(map[string]Rule)
	zones := plugin.Zones{}
	for c.Next() {
		for c.NextBlock() {
			recordType, err := RecordTypefromString(c.Val())
			if err != nil {
				return nil, err
			}
			domainNames := c.RemainingArgs()
			for _, domainName := range domainNames {
				domainName = plugin.Name(domainName).Normalize()
				if _, ok := rules[domainName]; !ok {
					rules[domainName] = Rule{RecordTypes: []uint16{recordType}}
				} else {
					rule := rules[domainName]
					recordTypes := append(rules[domainName].RecordTypes, recordType)
					rule.RecordTypes = recordTypes
					rules[domainName] = rule
					zones = append(zones, domainName)
				}
			}

		}
	}
	return rules, nil
}
