package issuer

import "time"

// SetClock moves the clock admission leases are judged by, for a test.
func SetClock(i *Issuer, now func() time.Time) { i.now = now }
