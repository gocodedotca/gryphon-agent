package clientagent

import (
	"time"

	"github.com/gocodedotca/gryphon-agent/pkg/agent"
	"github.com/gocodedotca/gryphon-agent/pkg/netcheck"
)

// Where this agent's checks may dial.
//
// The agent exists to reach what the Gryphon server cannot: a service bound to
// loopback, an address on a private network, a name only the internal resolver
// knows. That is the whole of its job, and it is also the whole of its remit --
// so by default it dials addresses inside its own network and refuses the rest.
//
// The refusal is made here rather than on the server because here is where it
// holds. A server-side rule is a convenience for the person filling in the
// form; it is bypassed by a server that has been compromised, by anybody
// holding a copy of the access key, and by a request that never went through a
// form at all. The dialer's Control hook is the only place that judges the
// address actually being connected to.
//
// It is the address and never the name. An internal name resolving to a private
// address is the ordinary case for this agent, so a name cannot be judged at
// all -- and a name under an account holder's control resolves to whatever they
// like, differently on each lookup.

// reach is the rule this configuration amounts to.
func (c Config) reach() netcheck.Reach {
	if c.AllowPublicTargets {
		return netcheck.ReachAny
	}
	return netcheck.ReachPrivate
}

// refusedMessage is what a check reports when the agent will not dial the
// address it was given.
//
// It names the setting, because the person reading it off a dashboard in
// Gryphon cannot see this machine's environment and would otherwise have
// nothing to go on.
const refusedMessage = "the agent only reaches addresses inside its own network " +
	"(set GWC_ALLOW_PUBLIC_TARGETS on the agent to allow public ones)"

// refused is the answer to a check pointed somewhere the agent may not go.
//
// Unknown, never problem: the service is very likely fine and the check is the
// thing that is misconfigured. Reporting an outage here would page somebody
// about a typo.
func refused() result {
	return result{statusID: agent.StatusUnknown, msg: refusedMessage}
}

// dialTimeout bounds one connection attempt made through the reach's dialer.
// The check's own timeout still bounds the whole of it.
const dialTimeout = 10 * time.Second
