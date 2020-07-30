package server

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/gob"
	"encoding/json"
	"html/template"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"github.com/joho/godotenv"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

var log = logrus.WithFields(logrus.Fields{"pkg": "google_login_required"})

type CleanupFunc func()

// Server is an HTTP server with open and protected pages
type Server struct {
	sessionStore sessions.Store
	oathConfig   *oauth2.Config
	Mux          *mux.Router
	SecureMux    *mux.Router
	CleanupFuncs []CleanupFunc
}

// cleanup is used instead of using deferred functions because they aren't run
// when the process is interrupted, only on a clean shutdown.
func (s *Server) cleanup() {
	log.Info("In cleanup")
	for _, f := range s.CleanupFuncs {
		f()
	}
}

func (s *Server) loginRequired(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session, err := s.sessionStore.Get(r, "auth-session")
		if err != nil {
			logrus.Error("Unable to open session (1) ", err.Error())
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		if v, ok := session.Values["profile"]; !ok {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
		} else {
			if hd, ok := v.(map[string]interface{})["hd"]; ok && hd == "octoenergy.com" {
				next.ServeHTTP(w, r)
			} else {
				http.Redirect(w, r, "/login", http.StatusSeeOther)
			}
		}
	})
}

func (s *Server) callbackHandler(w http.ResponseWriter, r *http.Request) {
	state := r.URL.Query().Get("state")
	session, err := s.sessionStore.Get(r, "state")
	if err != nil {
		http.Error(w, "callbackHandler 1 "+err.Error(), http.StatusInternalServerError)
		return
	}

	if state != session.Values["state"] {
		http.Error(w, "Invalid state parameter", http.StatusInternalServerError)
		return
	}

	code := r.URL.Query().Get("code")

	token, err := s.oathConfig.Exchange(context.TODO(), code)
	if err != nil {
		http.Error(w, "callbackHandler 2 "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Getting now the userInfo
	client := s.oathConfig.Client(context.TODO(), token)
	resp, err := client.Get("https://www.googleapis.com/oauth2/v3/userinfo")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	defer resp.Body.Close()

	var profile map[string]interface{}
	if err = json.NewDecoder(resp.Body).Decode(&profile); err != nil {
		http.Error(w, "callbackHandler 3 "+err.Error(), http.StatusInternalServerError)
		return
	}

	session, err = s.sessionStore.Get(r, "auth-session")
	if err != nil {
		logrus.Warn("callbackHandler: Overwriting session due to ", err)
		session, err = s.sessionStore.New(r, "auth-session")
	}

	usersDomain := os.Getenv("RESTRICTED_TO_DOMAIN")
	if usersDomain != "" && profile["hd"] != usersDomain {
		http.Error(w, "This is restricted to Octopus Energy", http.StatusUnauthorized)
		return
	}

	session.Values["id_token"] = token.Extra("id_token")
	session.Values["access_token"] = token.AccessToken
	session.Values["profile"] = profile
	err = session.Save(r, w)
	if err != nil {
		http.Error(w, "callbackHandler 5 "+err.Error(), http.StatusInternalServerError)
		return
	}

	logrus.Infof("Logged in: %#v", profile)

	// Redirect to logged in page
	http.Redirect(w, r, "/", http.StatusSeeOther)

}

func (s *Server) loginHandler(w http.ResponseWriter, r *http.Request) {
	// Generate random state
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		http.Error(w, "Unable to get randomness", http.StatusInternalServerError)
	}
	state := base64.StdEncoding.EncodeToString(b)

	session, err := s.sessionStore.Get(r, "state")
	if err != nil {
		logrus.Warn("Overwriting session due to ", err)
		session, err = s.sessionStore.New(r, "state")
	}
	session.Values["state"] = state
	err = session.Save(r, w)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	url := s.oathConfig.AuthCodeURL(state)

	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func (s *Server) userHandler(w http.ResponseWriter, r *http.Request) {
	session, err := s.sessionStore.Get(r, "auth-session")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	tmpl := template.Must(template.ParseFiles("templates/user.html"))
	if err := tmpl.Execute(w, session.Values["profile"]); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func New(sessionStore sessions.Store) (*Server, error) {
	// Load .env if it exists
	if _, err := os.Stat(".env"); err == nil {
		if err := godotenv.Load(); err != nil {
			return nil, errors.Wrap(err, "loading .env")
		}
	}

	oathConfig := &oauth2.Config{
		ClientID:     os.Getenv("GOOGLE_OATH_CLIENT_ID"),
		ClientSecret: os.Getenv("GOOGLE_OATH_CLIENT_SECRET"),
		RedirectURL:  os.Getenv("ROOT_URL") + "/auth",
		Scopes: []string{
			"https://www.googleapis.com/auth/userinfo.email",
		},
		Endpoint: google.Endpoint,
	}

	s := Server{
		oathConfig: oathConfig,
	}

	if sessionStore == nil {
		if secret, err := base64.StdEncoding.DecodeString(os.Getenv("COOKIE_SECRET")); err != nil {
			return nil, errors.Wrap(err, "Unable to read COOKIE_SECRET from cookie store")
		} else {
			s.sessionStore = sessions.NewFilesystemStore("", secret)
		}
	} else {
		s.sessionStore = sessionStore
	}

	gob.Register(map[string]interface{}{})

	// Set up an on exit handler, which is useful for functions that won't get run by defer
	c := make(chan os.Signal)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-c
		s.cleanup()
		os.Exit(1)
	}()

	logrus.Info("Ready")

	m := mux.NewRouter()
	m.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir("./static"))))

	r := m.MatcherFunc(func(r *http.Request, rm *mux.RouteMatch) bool {
		if r.URL.Path == "/login" || r.URL.Path == "/auth" {
			return false
		}
		return true
	}).Subrouter()

	m.Path("/login").HandlerFunc(s.loginHandler)
	m.Path("/auth").HandlerFunc(s.callbackHandler)
	r.Path("/user").HandlerFunc(s.userHandler)

	r.Use(s.loginRequired)

	s.Mux = m
	s.SecureMux = r

	return &s, nil
}

// Serve runs the assembled web server
func (s *Server) Serve() {
	port := os.Getenv("HTTP_PORT")
	if port == "" {
		port = "7777"
	}
	if err := http.ListenAndServe(":"+port, handlers.RecoveryHandler()(s.Mux)); err != nil {
		logrus.Fatal(err)
	}
}
