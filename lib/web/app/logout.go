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
	"net/http"
	"time"

	"github.com/gravitational/teleport/lib/services"
	"github.com/gravitational/trace"
)

func (h *Handler) handleLogout(w http.ResponseWriter, r *http.Request, session services.WebSession) error {
	err := h.c.AuthClient.DeleteAppWebSession(context.Background(), services.DeleteAppWebSessionRequest{
		//Username:   session.GetUser(),
		//ParentHash: session.GetParentHash(),
		SessionID: session.GetName(),
	})
	if err != nil {
		return trace.Wrap(err)
	}

	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		HttpOnly: true,
		Secure:   true,
		Expires:  time.Unix(0, 0),
		SameSite: http.SameSiteLaxMode,
	})

	http.Error(w, "Logged out.", http.StatusOK)
	return nil
}
