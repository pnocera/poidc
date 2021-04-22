package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	oidc "github.com/pnocera/poidc/poidc"
)

type authenticationMiddleware struct {
	ClientID string
	Provider *oidc.Provider
}

func (amw *authenticationMiddleware) Middleware(next http.Handler) http.Handler {
	var verifier = amw.Provider.Verifier(&oidc.Config{ClientID: amw.ClientID})

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqToken := r.Header.Get("Authorization")
		fmt.Printf("%+v\n", reqToken)
		splitToken := strings.Split(reqToken, "Bearer")
		if len(splitToken) != 2 {
			http.Error(w, "Token doesn't seem right", http.StatusUnauthorized)
			return
		}

		reqToken = strings.TrimSpace(splitToken[1])

		idToken, err := verifier.Verify(r.Context(), reqToken)
		if err != nil {
			log.Println(err.Error())
			http.Error(w, "Unable to verify token", http.StatusUnauthorized)
			return
		}
		fmt.Printf("%+v\n", idToken)

		var claims struct {
			Emails []string `json:"emails"`
		}
		if err := idToken.Claims(&claims); err != nil {
			fmt.Println(err)
			http.Error(w, "Unable to retrieve claims", http.StatusUnauthorized)
			return
		}
		fmt.Printf("%+v\n", claims)

		// Call the next handler, which can be another middleware in the chain, or the final handler.
		next.ServeHTTP(w, r)
	})
}

func httpHomePage(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Hello Home Page!")
	fmt.Println("hit home page")
}

func main() {

	provider, err := oidc.NewProvider(context.Background(), "https://docrender.b2clogin.com/tfp/f6a1f0af-38f9-4352-9325-f21c825dcd53/b2c_1_signin/v2.0/") //REPLACE THIS WITH YOUR VALUE
	if err != nil {
		log.Fatal(err)
	}
	amw := authenticationMiddleware{
		Provider: provider,
		ClientID: "2c564ea4-1cd2-459c-b75b-eeeaa518c3ac",
	}

	r := mux.NewRouter()
	r.HandleFunc("/", httpHomePage)

	cors := handlers.CORS(
		handlers.AllowedHeaders([]string{"Authorization"}),
		handlers.AllowedMethods([]string{"GET"}),
		handlers.AllowedOrigins([]string{"http://localhost:4200"}),
	)

	// Apply the CORS middleware to our top-level router, with the defaults.
	log.Fatal(http.ListenAndServe(":8080", cors(amw.Middleware(r))))
}
