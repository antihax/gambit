package drivers

import "github.com/antihax/pass/pkg/driver"

var drivers []DriverHandler

// DriverHandler matches a pattern to a driver
type DriverHandler struct {
	Pattern []byte
	Driver  driver.Driver
}

// AddDriver adds a driver to the internal list
func AddDriver(pattern []byte, driver driver.Driver) {
	drivers = append(drivers, DriverHandler{pattern, driver})
}

// GetDrivers returns the available driver list
func GetDrivers() []DriverHandler {
	return drivers
}
