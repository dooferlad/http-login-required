package main

import (
	"fmt"
	"os"

	"github.com/dooferlad/http-login-required/server"
)

func main() {
	if m, err := server.New(nil); err == nil {
		// Now you can add your own paths:
		// m.Mux.Path("some-path", aHandlerFunc)
		// m.SecureMux.Path("some-path", aHandlerFunc)
		m.Serve()

	} else {
		fmt.Fprint(os.Stderr, err)
		os.Exit(1)
	}
}
