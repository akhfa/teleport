/*
Copyright 2020 Gravitational, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Package app connections to applications over a reverse tunnel and forwards
// HTTP requests to them.
package app

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/gravitational/teleport"
	"github.com/gravitational/teleport/lib/auth"
	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/reversetunnel"
	"github.com/gravitational/teleport/lib/services"
	"github.com/gravitational/teleport/lib/utils"
	"github.com/gravitational/ttlmap"

	"github.com/gravitational/trace"

	"github.com/jonboulle/clockwork"
	"github.com/sirupsen/logrus"
)

// HandlerConfig is the configuration for an application handler.
type HandlerConfig struct {
	// Clock is used to control time in tests.
	Clock clockwork.Clock
	// AuthClient is a direct client to auth.
	AuthClient auth.ClientI
	// AccessPoint is caching client to auth.
	AccessPoint auth.AccessPoint
	// ProxyClient holds connections to leaf clusters.
	ProxyClient  reversetunnel.Server
	CipherSuites []uint16
}

// CheckAndSetDefaults validates configuration.
func (c *HandlerConfig) CheckAndSetDefaults() error {
	if c.Clock == nil {
		c.Clock = clockwork.NewRealClock()
	}

	if c.AuthClient == nil {
		return trace.BadParameter("auth client missing")
	}
	if c.AccessPoint == nil {
		return trace.BadParameter("access point missing")
	}
	if c.ProxyClient == nil {
		return trace.BadParameter("proxy client missing")
	}

	return nil
}

// Handler is an application handler.
type Handler struct {
	c *HandlerConfig

	log *logrus.Entry

	mu    sync.Mutex
	cache *ttlmap.TTLMap
}

// NewHandler returns a new application handler.
func NewHandler(c *HandlerConfig) (*Handler, error) {
	if err := c.CheckAndSetDefaults(); err != nil {
		return nil, trace.Wrap(err)
	}

	// Cache of request forwarders.
	cache, err := ttlmap.New(defaults.ClientCacheSize)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return &Handler{
		c: c,
		log: logrus.WithFields(logrus.Fields{
			trace.Component: teleport.ComponentAppProxy,
		}),
		cache: cache,
	}, nil

}

// ForwardToApp checks if the request is bound for the application handler.
// Used by "ServeHTTP" within the "web" package to make a decision if the
// request should be processed by the UI or forwarded to an application.
func (h *Handler) IsAuthenticatedApp(r *http.Request) bool {
	// The only unauthenticated endpoint supported is the special
	// "x-teleport-auth" endpoint. If the request is coming to this special
	// endpoint, it should be processed by application handlers.
	if r.URL.Path == "/x-teleport-auth" {
		return true
	}

	// Check if an application specific cookie exists. If it exists, forward the
	// request to an application handler otherwise allow the UI to handle it.
	_, err := r.Cookie(cookieName)
	if err != nil {
		return false
	}
	return true
}

// IsUnauthenticatedApp checks if the client is attempting to connect to a
// host that is different than the public address of the proxy. If it is, it
// redirects back to the application launcher in the Web UI.
func (h *Handler) IsUnauthenticatedApp(r *http.Request, publicAddr string) (string, bool) {
	requestedHost, err := utils.ParseAddr(r.Host)
	if err != nil {
		return "", false
	}

	// TODO(russjones): Benchmark time to loop over all applications and look
	// for a match.
	if utils.IsLocalhost(requestedHost.Host()) {
		return "", false
	}
	if net.ParseIP(requestedHost.Host()) != nil {
		return "", false
	}
	if r.Host == publicAddr {
		return "", false
	}

	host, _, _ := net.SplitHostPort(r.Host)

	//u, err := url.Parse(fmt.Sprintf("https://%v/web/launch/%v", publicAddr, r.Host))
	u, err := url.Parse(fmt.Sprintf("https://%v/web/launch/%v", publicAddr, host))
	if err != nil {
		h.log.Debugf("Failed to parse while handling unauthenticated request to %v: %v.", r.Host, err)
		return "", false
	}
	return u.String(), true
}

// ServeHTTP will forward the *http.Request to the application proxy service.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if err := h.serveHTTP(w, r); err != nil {
		h.log.Warnf("Failed to serve request: %v.", err)

		// Covert trace error type to HTTP and write response.
		code := trace.ErrorToCode(err)
		http.Error(w, http.StatusText(code), code)
	}
}

func (h *Handler) serveHTTP(w http.ResponseWriter, r *http.Request) error {
	// Only two special endpoints exist, one is used to pass authentication from
	// one origin to another and the other is to logout. All other requests
	// simply get forwarded.
	switch r.URL.Path {
	case "/x-teleport-auth":
		if err := h.handleFragment(w, r); err != nil {
			return trace.Wrap(err)
		}
	case "/x-teleport-logout":
		// Authenticate the session based off the session cookie.
		ws, err := h.authenticate(r.Context(), r)
		if err != nil {
			return trace.Wrap(err)
		}

		if err := h.handleLogout(w, r, ws); err != nil {
			return trace.Wrap(err)
		}
	default:
		// Authenticate the session based off the session cookie.
		ws, err := h.authenticate(r.Context(), r)
		if err != nil {
			return trace.Wrap(err)
		}

		// Fetch a cached request forwarder or create one if this is the first
		// request (or the process has been restarted).
		session, err := h.getSession(r.Context(), ws)
		if err != nil {
			return trace.Wrap(err)
		}

		// Forward the request to the Teleport application proxy service.
		session.fwd.ServeHTTP(w, r)
	}

	return nil
}

// authenticate will check if request carries a session cookie matching a
// session in the backend.
func (h *Handler) authenticate(ctx context.Context, r *http.Request) (services.WebSession, error) {
	// Extract the session cookie from the *http.Request.
	cookie, err := parseCookie(r)
	if err != nil {
		h.log.Warnf("Failed to parse session cookie: %v.", err)
		return nil, trace.AccessDenied("invalid session")
	}

	// Check that the session exists in the backend cache. This allows the user
	// to logout and invalidate their application session immediately. This
	// lookup should also be fast because it's in the local cache.
	session, err := h.c.AccessPoint.GetAppWebSession(ctx, services.GetAppWebSessionRequest{
		//Username:   cookie.Username,
		//ParentHash: cookie.ParentHash,
		SessionID: cookie.SessionID,
	})
	if err != nil {
		h.log.Warnf("Failed to fetch application session: %v.", err)
		return nil, trace.AccessDenied("invalid session")
	}

	return session, nil
}

// cacheGet will fetch the forwarder from the cache.
func (h *Handler) cacheGet(key string) (*session, error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if s, ok := h.cache.Get(key); ok {
		if sess, sok := s.(*session); sok {
			return sess, nil
		}
		return nil, trace.BadParameter("invalid type stored in cache: %T", s)
	}
	return nil, trace.NotFound("forwarder not found")
}

// cacheSet will add the forwarder to the cache.
func (h *Handler) cacheSet(key string, value *session, ttl time.Duration) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if err := h.cache.Set(key, value, ttl); err != nil {
		return trace.Wrap(err)
	}
	return nil
}
