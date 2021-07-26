package main

import (
	"log"
	"net/http"

	"github.com/antihax/gambit/internal/contrive"
	_ "github.com/antihax/gambit/internal/contrive/views"
	"github.com/gorilla/context"
)

func main() {
	contrive, err := contrive.NewContrive()
	if err != nil {
		log.Fatal(err)
	}
	defer contrive.Close()

	rtr := contrive.NewRouter()
	log.Fatalln(http.ListenAndServe(":3000", context.ClearHandler(rtr)))
}
