package authority

// AllowAnyRoleNamesForTest lets c compose a new generation declaring roles
// other than exactly admin and user, for this package's fixtures that model
// the core's wider role model. Compiled into this package's tests only.
func AllowAnyRoleNamesForTest(c *Config) { c.anyRoleNames = true }
