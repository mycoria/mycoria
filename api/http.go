package api

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/mycoria/mycoria/mgr"
)

func (api *API) netstackHTTPServer(w *mgr.WorkerCtx) error {
	// Configure server.
	baseCtx := w.AddToCtx(w.Ctx())
	api.httpServer.ErrorLog = slog.NewLogLogger(w.Logger().Handler(), slog.LevelInfo)
	api.httpServer.BaseContext = func(_ net.Listener) context.Context {
		return baseCtx
	}

	// Start serving.
	err := api.httpServer.Serve(api.httpServerListener)
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// ServeHTTP implements the HTTP server handler.
func (api *API) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	wkr := mgr.WorkerFromCtx(r.Context())
	if wkr == nil {
		slog.Error("misconfigured http server")
	}

	started := time.Now()
	defer func() {
		wkr.Debug(
			"request",
			"method", r.Method,
			"path", r.URL.Path,
			"time", time.Since(started),
		)
	}()

	http.Error(w, "Hello from Mycoria API!", http.StatusOK)
}
