package main

import (
	"log"

	"github.com/antihax/pass/pkg/conman"
)

func main() {
	conman, err := conman.NewConMan()
	if err != nil {
		log.Panic(err)
	}
	conman.StartConning()
}
