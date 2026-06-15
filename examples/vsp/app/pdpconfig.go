package app

import (
	vsppolicies "github.com/pmsbkhn/authorization-zta/examples/vsp/policies"
	"github.com/pmsbkhn/authorization-zta/internal/services"
)

// DemoPDPConfig returns a platform PDPConfig wired with the VSP reference domain
// policy layered over the embedded framework. The reference cmd/pdp and the
// end-to-end tests use it; it is the demo's stand-in for what a real adopter
// supplies (its own ExtraModules, or a compiled bundle in production).
func DemoPDPConfig(secret []byte) services.PDPConfig {
	return services.PDPConfig{
		TokenSecret:  secret,
		ExtraModules: vsppolicies.MustModules(),
		ExtraData:    vsppolicies.MustData(),
	}
}
