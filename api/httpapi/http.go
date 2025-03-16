package httpapi

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/mycoria/mycoria/config"
	"github.com/mycoria/mycoria/m"
	"github.com/mycoria/mycoria/mgr"
	"github.com/mycoria/mycoria/state"
)

// API is an HTTP API manager.
type API struct {
	mgr      *mgr.Manager
	instance instance

	httpServer         *http.Server
	httpServerListener net.Listener

	handlers *http.ServeMux
}

// instance is an interface subset of inst.Ance.
type instance interface {
	Version() string
	Config() *config.Config
	Identity() *m.Address
	State() *state.State
}

// New returns a new HTTP API.
func New(instance instance, ln net.Listener) (*API, error) {
	// Create HTTP server.
	api := &API{
		mgr:                mgr.New("api"),
		instance:           instance,
		httpServerListener: ln,
		handlers:           http.NewServeMux(),
	}
	api.httpServer = &http.Server{
		Handler:      api,
		ReadTimeout:  time.Second,
		WriteTimeout: time.Second,
	}

	return api, nil
}

// Manager returns the module's manager.
func (api *API) Manager() *mgr.Manager {
	return api.mgr
}

// Start starts the API.
func (api *API) Start() error {
	api.mgr.Go("http server", api.httpServerWorker)

	return nil
}

// Stop stops the API.
func (api *API) Stop() error {
	if err := api.httpServer.Close(); err != nil {
		api.mgr.Error("failed to stop http server", "err", err)
	}
	return nil
}

// Handle registers the handler for the given pattern. If a handler already exists for pattern, Handle panics.
func (api *API) Handle(pattern string, handler http.Handler) {
	api.handlers.Handle(pattern, handler)
}

// HandleFunc registers the handler function for the given pattern.
func (api *API) HandleFunc(pattern string, handler func(http.ResponseWriter, *http.Request)) {
	api.handlers.HandleFunc(pattern, handler)
}

func (api *API) httpServerWorker(w *mgr.WorkerCtx) error {
	// Configure server.
	api.httpServer.ErrorLog = slog.NewLogLogger(w.Logger().Handler(), slog.LevelWarn)

	// Start serving.
	err := api.httpServer.Serve(api.httpServerListener)
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// ServeHTTP implements the HTTP server handler.
func (api *API) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	_ = api.mgr.Do("request", func(wkr *mgr.WorkerCtx) error {
		api.handleRequest(wkr, w, r)
		return nil
	})
}

func (api *API) handleRequest(wkr *mgr.WorkerCtx, w http.ResponseWriter, r *http.Request) {
	// Set retrievable request context.
	r = r.WithContext(wkr.AddToCtx(wkr.Ctx()))

	// Capture status code for logging.
	statusCodeWriter := NewStatusCodeWriter(w, r)

	// Log request.
	started := time.Now()
	logged := false
	defer func() {
		if !logged {
			logLevel := slog.LevelDebug
			switch {
			case statusCodeWriter.Status >= 500:
				logLevel = slog.LevelError
			case statusCodeWriter.Status >= 400 &&
				strings.HasSuffix(r.URL.Path, ".map"):
				logLevel = slog.LevelDebug
			case statusCodeWriter.Status >= 400:
				logLevel = slog.LevelWarn
			}
			wkr.Log(
				logLevel,
				"request",
				"method", r.Method,
				"status", statusCodeWriter.Status,
				"path", r.URL.Path,
				"remote", r.RemoteAddr,
				"time", time.Since(started),
			)
		}
	}()

	// Recover from panic.
	defer func() {
		panicVal := recover()
		if panicVal != nil {
			// Respond with error.
			http.Error(w,
				fmt.Sprintf("internal error: %s", panicVal),
				http.StatusInternalServerError,
			)

			// Log error.
			wkr.Error(
				"request failed",
				"method", r.Method,
				"path", r.URL.Path,
				"err", fmt.Sprintf("panic: %s", panicVal),
				"remote", r.RemoteAddr,
				"time", time.Since(started),
			)
			logged = true
		}
	}()

	// Add security headers.
	hdr := w.Header()
	hdr.Set("Referrer-Policy", "same-origin")
	hdr.Set("X-Content-Type-Options", "nosniff")
	hdr.Set("X-Frame-Options", "deny")
	hdr.Set("X-XSS-Protection", "1; mode=block")
	hdr.Set("X-DNS-Prefetch-Control", "off")

	// Add CSP Header.
	hdr.Set(
		"Content-Security-Policy",
		"default-src 'self'; "+
			"style-src 'self' 'unsafe-inline'; "+
			"img-src 'self' data: blob:",
	)

	// Check Cross-Origin Requests.
	origin := r.Header.Get("Origin")
	if origin != "" {
		// Check for omitted origin.
		if origin == "null" {
			http.Error(w, "Cross-Origin Request Denied: Origin Header Unset.", http.StatusForbidden)
			wkr.Warn(
				"request denied: origin header is omitted",
				"remote", r.RemoteAddr,
			)
			logged = true
			return
		}

		// Parse origin URL.
		originURL, err := url.Parse(origin)
		if err != nil {
			http.Error(w, "Cross-Origin Request Denied: Invalid Origin.", http.StatusForbidden)
			wkr.Warn(
				"request denied: failed to parse origin header",
				"err", err,
				"remote", r.RemoteAddr,
			)
			logged = true
			return
		}

		// Check if the Origin matches the Host.
		hostname := originURL.Hostname()
		switch {
		case originURL.Host == r.Host:
			// Origin (with port) matches Host.
		case hostname == r.Host:
			// Origin (without port) matches Host.
		case hostname == "localhost", hostname == "::1":
			// Localhost
		default:
			// Origin and Host do NOT match!
			http.Error(w, "Cross-Origin Request Denied.", http.StatusForbidden)
			wkr.Warn(
				"request denied: origin not allowed",
				"origin", origin,
				"host", r.Host,
				"remote", r.RemoteAddr,
			)
			logged = true
			return

			// Note: If the Host header has a port, and the Origin does not, requests
			// will also end up here, as we cannot properly check for equality.
		}

		// Add Cross-Site Headers now as we need them in any case now.
		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Set("Access-Control-Allow-Methods", "*")
		w.Header().Set("Access-Control-Allow-Headers", "*")
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.Header().Set("Access-Control-Expose-Headers", "*")
		w.Header().Set("Access-Control-Max-Age", "60")
		w.Header().Add("Vary", "Origin")

		// If there's a Access-Control-Request-Method header this is a preflight check.
		// In that case, we will just check if the preflighMethod is allowed and then return
		// success here.
		if r.Method == http.MethodOptions {
			if r.Header.Get("Access-Control-Request-Method") != "" {
				statusCodeWriter.WriteHeader(http.StatusOK)
				logged = true // Do not log preflight checks.
				return
			}
		}
	}

	// Handle with registered handler.
	api.handlers.ServeHTTP(statusCodeWriter, r)
}
