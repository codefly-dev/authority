package noproxygate

// The overlay cases the gate is tested on import these; naming them here keeps
// them in this module's requirements.
import (
	_ "github.com/codefly-dev/authority/libraries/authority-client/go/host"
	_ "google.golang.org/grpc"
	_ "google.golang.org/grpc/credentials/insecure"
)
