package drivers

import "github.com/antihax/pass/pkg/driver"

var drivers []*DriverHandler

// DriverHandler matches a pattern to a driver
type DriverHandler struct {
	Pattern []byte
	Driver  driver.Driver
}

// AddDriver adds a driver to the internal list
func AddDriver(pattern []byte, handler driver.Driver) {
	d := &DriverHandler{pattern, handler}
	drivers = append(drivers, d)
}

// GetDrivers returns the available driver list
func GetDrivers() []*DriverHandler {
	return drivers
}
