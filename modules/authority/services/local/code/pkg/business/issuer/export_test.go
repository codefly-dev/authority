package issuer

import "time"

// SetClock moves the clock admission leases are judged by, for a test.
func SetClock(i *Issuer, now func() time.Time) { i.now = now }

// SetTrustDomain sets the host's trust domain a registering hop must be in,
// for a test of a hop the anchor vouches for in another.
func SetTrustDomain(i *Issuer, domain string) { i.trustDomain = domain }
