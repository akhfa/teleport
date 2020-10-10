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

package app

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/gravitational/oxy/forward"
	"github.com/gravitational/teleport"
	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/reversetunnel"
	"github.com/gravitational/teleport/lib/services"
	"github.com/gravitational/teleport/lib/tlsca"
	"github.com/gravitational/teleport/lib/utils"
	"github.com/gravitational/trace"
	"github.com/sirupsen/logrus"
)

type session struct {
	fwd *forward.Forwarder
}

func (h *Handler) getSession(ctx context.Context, webSession services.WebSession) (*session, error) {
	// If a cached session exists, return it right away.
	session, err := h.cacheGet(webSession.GetName())
	if err == nil {
		return session, nil
	}

	// Create a new session with a forwarder in it.
	session, err = h.newSession(webSession)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// Put the session in the cache so the next request can use it.
	err = h.cacheSet(webSession.GetName(), session, session.Expiry().Sub(h.c.Clock.Now()))
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return session, nil
}

func (h *Handler) newSession(webSession services.WebSession) (*session, error) {
	// Extract the identity of the user.
	certificate, err := tlsca.ParseCertificatePEM(webSession.GetTLSCert())
	if err != nil {
		return nil, trace.Wrap(err)
	}
	identity, err := tlsca.FromSubject(certificate.Subject, certificate.NotAfter)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// Create a http.RoundTripper that uses the x509 identity of the user.
	transport, err := newTransport(identity, webSession)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// Create the forwarder.
	fwder, err := newForwarder(forwarderConfig{
		uri: fmt.Sprintf("https://%v.%v", session.GetServerID(), session.GetClusterName()),
		//uri:       "https://" + teleport.APIDomain,
		//uri:       "https://server04",
		sessionID: session.GetSessionID(),
		//tr:        h.tr,
		tr:  tr,
		log: h.log,
	})
	if err != nil {
		return nil, trace.Wrap(err)
	}
	fwd, err = forward.New(
		forward.RoundTripper(fwder),
		forward.Rewriter(fwder),
		forward.Logger(h.log))
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return &session{
		fwd: fwd,
	}, nil
}

// forwarderConfig is the configuration for a forwarder.
type forwarderConfig struct {
	uri       string
	sessionID string
	tr        http.RoundTripper
	log       *logrus.Entry
}

// Check will valid the configuration of a forwarder.
func (c forwarderConfig) Check() error {
	if c.uri == "" {
		return trace.BadParameter("uri missing")
	}
	if c.sessionID == "" {
		return trace.BadParameter("session ID missing")
	}
	if c.tr == nil {
		return trace.BadParameter("round tripper missing")
	}
	if c.log == nil {
		return trace.BadParameter("logger missing")
	}

	return nil
}

// forwarder will rewrite and forward the request to the target address.
type forwarder struct {
	c forwarderConfig

	uri *url.URL
}

// newForwarder returns a new forwarder.
func newForwarder(c forwarderConfig) (*forwarder, error) {
	if err := c.Check(); err != nil {
		return nil, trace.Wrap(err)
	}

	// Parse the target address once then inject it into all requests.
	uri, err := url.Parse(c.uri)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return &forwarder{
		c:   c,
		uri: uri,
	}, nil
}

func (f *forwarder) RoundTrip(r *http.Request) (*http.Response, error) {
	// Update the target address of the request so it's forwarded correctly.
	// Format is always serverID.clusterName.
	r.URL.Scheme = f.uri.Scheme
	r.URL.Host = f.uri.Host

	resp, err := f.c.tr.RoundTrip(r)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return resp, nil
}

func (f *forwarder) Rewrite(r *http.Request) {
	// Pass the application session ID to the application service in a header.
	// This will be removed by the application proxy service before forwarding
	// the request to the target application.
	r.Header.Set(teleport.AppSessionIDHeader, f.c.sessionID)

	// Remove the application specific session cookie from the header. This is
	// done by first wiping out the "Cookie" header then adding back all cookies
	// except the Teleport application specific session cookie. This appears to
	// be the best way to serialize cookies.
	cookies := r.Cookies()
	r.Header.Del("Cookie")
	for _, cookie := range cookies {
		if cookie.Name == cookieName {
			continue
		}
		r.AddCookie(cookie)
	}
}

// newTransport creates a http.RoundTripper that uses the reverse tunnel
// subsystem to build the connection. This allows re-use of the transports
// connection pooling logic instead of needing to write and maintain our own.
func newTransport(proxyClient reversetunnel.Server) (*http.Transport, error) {
	//ca, err := h.c.AuthClient.GetCertAuthority(services.CertAuthID{
	//	Type:       services.HostCA,
	//	DomainName: "example.com",
	//}, false)
	//if err != nil {
	//	return nil, trace.Wrap(err)
	//}
	//certPool, err := services.CertPool(ca)
	//if err != nil {
	//	return nil, trace.Wrap(err)
	//}
	//tlsConfig := utils.TLSConfig(h.c.CipherSuites)
	//tlsCert, err := tls.X509KeyPair(session.GetTLSCert(), session.GetPriv())
	//if err != nil {
	//	return nil, trace.Wrap(err, "failed to parse TLS cert and key")
	//}
	//tlsConfig.Certificates = []tls.Certificate{tlsCert}
	//tlsConfig.RootCAs = certPool
	//// TODO(russjones): This might be due to hostname mistmatch?
	////tlsConfig.InsecureSkipVerify = true
	////tlsConfig.ServerName = auth.EncodeClusterName("example.com")
	//cert := tlsConfig.Certificates[0]
	//tlsConfig.Certificates = nil
	//tlsConfig.GetClientCertificate = func(_ *tls.CertificateRequestInfo) (*tls.Certificate, error) {
	//	fmt.Printf("--> sending cert.\n")
	//	return &cert, nil
	//}
	//tlsConfig.ServerName = "server04"
	////tlsConfig.BuildNameToCertificate()
	//tr, _ := newTransport(h.c.ProxyClient)
	//tr.TLSClientConfig = tlsConfig

	// Clone the default transport to pick up sensible defaults.
	defaultTransport, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return nil, trace.BadParameter("invalid transport type %T", http.DefaultTransport)
	}
	tr := defaultTransport.Clone()

	// Increase the size of the transports connection pool. This substantially
	// improves the performance of Teleport under load as it reduces the number
	// of TLS handshakes performed.
	tr.MaxIdleConns = defaults.HTTPMaxIdleConns
	tr.MaxIdleConnsPerHost = defaults.HTTPMaxIdleConnsPerHost

	// Set IdleConnTimeout on the transport, this defines the maximum amount of
	// time before idle connections are closed. Leaving this unset will lead to
	// connections open forever and will cause memory leaks in a long running
	// process.
	tr.IdleConnTimeout = defaults.HTTPIdleTimeout

	// The address field is always formatted as serverUUID.clusterName allowing
	// the connection pool maintained by the transport to differentiate
	// connections to different application proxy hosts.
	tr.DialContext = func(ctx context.Context, network string, addr string) (net.Conn, error) {
		//serverID, clusterName, err := extract(addr)
		//if err != nil {
		//	return nil, trace.Wrap(err)
		//}
		//clusterClient, err := proxyClient.GetSite(clusterName)
		clusterClient, err := proxyClient.GetSite("example.com")
		//clusterClient, err := proxyClient.GetSite("remote.example.com")
		if err != nil {
			return nil, trace.Wrap(err)
		}

		conn, err := clusterClient.Dial(reversetunnel.DialParams{
			// The "From" and "To" addresses don't mean anything for tunnel dialing,
			// so they are simply filled out with dummy values.
			From: &utils.NetAddr{AddrNetwork: "tcp", Addr: "@proxy"},
			To:   &utils.NetAddr{AddrNetwork: "tcp", Addr: "@app"},
			//ServerID: fmt.Sprintf("%v.%v", serverID, clusterName),
			ServerID: "7540982c-06e0-4943-a3b2-7442c1509b37.example.com",
			//ServerID: "a9c770b9-3b7c-4cbf-99a4-ee1821bfaae0.remote.example.com",
			ConnType: services.AppTunnel,
		})
		if err != nil {
			return nil, trace.Wrap(err)
		}
		return conn, nil
	}

	return tr, nil
}

// extract takes an address in the form http://serverID.clusterName:80 and
// returns serverID and clusterName.
func extract(address string) (string, string, error) {
	// Strip port suffix.
	address = strings.TrimSuffix(address, ":80")
	address = strings.TrimSuffix(address, ":443")

	// Split into two parts: serverID and clusterName.
	index := strings.Index(address, ".")
	if index == -1 {
		return "", "", fmt.Errorf("")
	}

	return address[:index], address[index+1:], nil
}

/*
	//Works with local cluster.
	ca, err := h.c.AuthClient.GetCertAuthority(services.CertAuthID{
		Type:       services.HostCA,
		DomainName: "example.com",
	}, false)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	certPool, err := services.CertPool(ca)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	tlsConfig := utils.TLSConfig(h.c.CipherSuites)
	tlsCert, err := tls.X509KeyPair(session.GetTLSCert(), session.GetPriv())
	if err != nil {
		return nil, trace.Wrap(err, "failed to parse TLS cert and key")
	}
	tlsConfig.Certificates = []tls.Certificate{tlsCert}
	tlsConfig.RootCAs = certPool
	// TODO(russjones): This might be due to hostname mistmatch?
	//tlsConfig.InsecureSkipVerify = true
	//tlsConfig.ServerName = auth.EncodeClusterName("example.com")
	cert := tlsConfig.Certificates[0]
	tlsConfig.Certificates = nil
	tlsConfig.GetClientCertificate = func(_ *tls.CertificateRequestInfo) (*tls.Certificate, error) {
		fmt.Printf("--> sending cert.\n")
		return &cert, nil
	}
	tlsConfig.ServerName = "server04"
	//tlsConfig.BuildNameToCertificate()
	tr, _ := newTransport(h.c.ProxyClient)
	tr.TLSClientConfig = tlsConfig

	// works on remote.
	//ca, err := h.c.AuthClient.GetCertAuthority(services.CertAuthID{
	//	Type:       services.HostCA,
	//	DomainName: "remote.example.com",
	//}, false)
	//if err != nil {
	//	return nil, trace.Wrap(err)
	//}
	//certPool, err := services.CertPool(ca)
	//if err != nil {
	//	return nil, trace.Wrap(err)
	//}
	//tlsConfig := utils.TLSConfig(h.c.CipherSuites)
	//tlsCert, err := tls.X509KeyPair(session.GetTLSCert(), session.GetPriv())
	//if err != nil {
	//	return nil, trace.Wrap(err, "failed to parse TLS cert and key")
	//}
	//tlsConfig.Certificates = []tls.Certificate{tlsCert}
	//tlsConfig.RootCAs = certPool
	//// TODO(russjones): This might be due to hostname mistmatch?
	////tlsConfig.InsecureSkipVerify = true
	////tlsConfig.ServerName = auth.EncodeClusterName("example.com")
	////tlsConfig.ServerName = "a9c770b9-3b7c-4cbf-99a4-ee1821bfaae0.remote.example.com"
	//cert := tlsConfig.Certificates[0]
	//tlsConfig.Certificates = nil
	//tlsConfig.GetClientCertificate = func(_ *tls.CertificateRequestInfo) (*tls.Certificate, error) {
	//	fmt.Printf("--> sending cert.\n")
	//	return &cert, nil
	//}
	//tlsConfig.ServerName = "server06" // <<-- surprusing dialing has to happen by host here.
	////tlsConfig.BuildNameToCertificate()

	//tr, _ := newTransport(h.c.ProxyClient)
	//tr.TLSClientConfig = tlsConfig

	// Create the forwarder.
	fwder, err := newForwarder(forwarderConfig{
		uri: fmt.Sprintf("https://%v.%v", session.GetServerID(), session.GetClusterName()),
		//uri:       "https://" + teleport.APIDomain,
		//uri:       "https://server04",
		sessionID: session.GetSessionID(),
		//tr:        h.tr,
		tr:  tr,
		log: h.log,
	})
	if err != nil {
		return nil, trace.Wrap(err)
	}
	fwd, err = forward.New(
		forward.RoundTripper(fwder),
		forward.Rewriter(fwder),
		forward.Logger(h.log))
	if err != nil {
		return nil, trace.Wrap(err)
	}
*/
