package main

import (
	"log"

	"github.com/antihax/gambit/internal/conman"
)

func main() {
	conman, err := conman.NewConMan()
	if err != nil {
		log.Fatal(err)
	}
	conman.StartConning()
}
