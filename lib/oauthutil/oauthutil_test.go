package oauthutil

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"sync"
	"testing"

	"github.com/rclone/rclone/fs"
	"github.com/rclone/rclone/fs/config"
	"github.com/rclone/rclone/fs/config/configmap"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

// TestAuthServerHandleAuth checks that only a callback carrying the
// random state may complete the flow, since the callback is an
// unauthenticated request any web page in the user's browser can make.
func TestAuthServerHandleAuth(t *testing.T) {
	for _, test := range []struct {
		name       string
		query      string
		wantStatus int
		wantOK     bool
	}{
		{"CorrectState", "?code=CODE&state=correct-state", http.StatusOK, true},
		{"WrongState", "?code=CODE&state=wrong-state", http.StatusBadRequest, false},
		{"BlankState", "?code=CODE&state=", http.StatusBadRequest, false},
		{"MissingState", "?code=CODE", http.StatusBadRequest, false},
		{"MissingCode", "?state=correct-state", http.StatusBadRequest, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			s := newAuthServer(&Options{}, "", "correct-state", "")
			w := httptest.NewRecorder()
			s.handleAuth(w, httptest.NewRequest("GET", "/"+test.query, nil))
			assert.Equal(t, test.wantStatus, w.Code)
			result := <-s.result
			assert.Equal(t, test.wantOK, result.OK)
			if test.wantOK {
				assert.Equal(t, "CODE", result.Code)
				assert.Equal(t, "CODE", result.Form.Get("code"))
			} else {
				assert.Equal(t, "", result.Code)
			}
		})
	}
}

// pkceProvider is a fake OAuth2 provider which records and checks
// the PKCE parameters it is sent.
type pkceProvider struct {
	*httptest.Server
	requirePKCE bool // reject token requests without a valid code_verifier

	mu         sync.Mutex
	challenges []string          // code_challenge for each authorize request
	methods    []string          // code_challenge_method for each authorize request
	verifiers  []string          // code_verifier for each token request
	byCode     map[string]string // code => code_challenge
	nextCode   int
}

func newPKCEProvider(t *testing.T, requirePKCE bool) *pkceProvider {
	p := &pkceProvider{
		requirePKCE: requirePKCE,
		byCode:      map[string]string{},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/authorize", p.handleAuthorize)
	mux.HandleFunc("/token", p.handleToken)
	p.Server = httptest.NewServer(mux)
	t.Cleanup(p.Close)
	return p
}

// Simulates the user logging in then being redirected back to rclone
func (p *pkceProvider) handleAuthorize(w http.ResponseWriter, req *http.Request) {
	q := req.URL.Query()
	p.mu.Lock()
	p.nextCode++
	code := "code" + strconv.Itoa(p.nextCode)
	p.challenges = append(p.challenges, q.Get("code_challenge"))
	p.methods = append(p.methods, q.Get("code_challenge_method"))
	p.byCode[code] = q.Get("code_challenge")
	p.mu.Unlock()
	redirect, err := url.Parse(q.Get("redirect_uri"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	rq := redirect.Query()
	rq.Set("code", code)
	rq.Set("state", q.Get("state"))
	redirect.RawQuery = rq.Encode()
	http.Redirect(w, req, redirect.String(), http.StatusFound)
}

func (p *pkceProvider) handleToken(w http.ResponseWriter, req *http.Request) {
	if err := req.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	verifier := req.PostForm.Get("code_verifier")
	p.mu.Lock()
	p.verifiers = append(p.verifiers, verifier)
	challenge, ok := p.byCode[req.PostForm.Get("code")]
	p.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	if !ok || (p.requirePKCE && (challenge == "" || s256(verifier) != challenge)) {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant"})
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{
		"access_token":  "access-token",
		"refresh_token": "refresh-token",
		"token_type":    "Bearer",
		"expires_in":    3600,
	})
}

func (p *pkceProvider) oauthConfig() *Config {
	return &Config{
		ClientID:    "client-id",
		AuthURL:     p.URL + "/authorize",
		TokenURL:    p.URL + "/token",
		RedirectURL: RedirectURL,
	}
}

// s256 computes the PKCE S256 code challenge from RFC 7636
func s256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// Replace OpenURL with a fake browser which follows the login flow
func fakeBrowser(t *testing.T) {
	oldOpenURL := OpenURL
	t.Cleanup(func() { OpenURL = oldOpenURL })
	OpenURL = func(authURL string) error {
		resp, err := http.Get(authURL)
		if err != nil {
			return err
		}
		return resp.Body.Close()
	}
}

// Run the "*oauth-do" config state for a backend using opt
func runOAuthDo(ctx context.Context, m configmap.Mapper, opt *Options, code string) error {
	ri := &fs.RegInfo{
		Name: "pkcetest",
		Config: func(ctx context.Context, name string, m configmap.Mapper, in fs.ConfigIn) (*fs.ConfigOut, error) {
			return ConfigOut("", opt)
		},
	}
	_, err := ConfigOAuth(ctx, "pkcetest", m, ri, fs.ConfigIn{
		State:  fs.StatePush("", "*oauth-do", "", "", ""),
		Result: code,
	})
	return err
}

func TestGetAuthURLPKCE(t *testing.T) {
	oauthConfig := &Config{
		ClientID:    "client-id",
		AuthURL:     "https://example.com/authorize",
		TokenURL:    "https://example.com/token",
		RedirectURL: RedirectURL,
	}
	m := configmap.Simple{}

	// Without a verifier there should be no challenge
	authURL, _, err := getAuthURL("test", m, oauthConfig, &Options{}, "")
	require.NoError(t, err)
	u, err := url.Parse(authURL)
	require.NoError(t, err)
	assert.Empty(t, u.Query().Get("code_challenge"))
	assert.Empty(t, u.Query().Get("code_challenge_method"))

	// With a verifier there should be an S256 challenge and the
	// verifier itself must not be in the URL
	verifier := oauth2.GenerateVerifier()
	authURL, _, err = getAuthURL("test", m, oauthConfig, &Options{}, verifier)
	require.NoError(t, err)
	u, err = url.Parse(authURL)
	require.NoError(t, err)
	assert.Equal(t, s256(verifier), u.Query().Get("code_challenge"))
	assert.Equal(t, "S256", u.Query().Get("code_challenge_method"))
	assert.NotContains(t, authURL, verifier)
}

func TestConfigOAuthPKCE(t *testing.T) {
	ctx := context.Background()
	fakeBrowser(t)

	t.Run("PKCE", func(t *testing.T) {
		p := newPKCEProvider(t, true)
		m := configmap.Simple{}
		require.NoError(t, runOAuthDo(ctx, m, &Options{OAuth2Config: p.oauthConfig(), PKCE: true}, ""))

		require.Len(t, p.challenges, 1)
		require.Len(t, p.verifiers, 1)
		assert.Equal(t, "S256", p.methods[0])
		// RFC 7636 requires a verifier of 43-128 characters
		assert.GreaterOrEqual(t, len(p.verifiers[0]), 43)
		assert.LessOrEqual(t, len(p.verifiers[0]), 128)
		assert.Equal(t, p.challenges[0], s256(p.verifiers[0]))

		// Check the token was saved and the verifier was not
		tokenString, ok := m.Get(config.ConfigToken)
		require.True(t, ok)
		assert.Contains(t, tokenString, "access-token")
		for k, v := range m {
			assert.NotContains(t, v, p.verifiers[0], "verifier saved in config key %q", k)
		}
	})

	t.Run("FreshVerifierEachLogin", func(t *testing.T) {
		p := newPKCEProvider(t, true)
		opt := &Options{OAuth2Config: p.oauthConfig(), PKCE: true}
		require.NoError(t, runOAuthDo(ctx, configmap.Simple{}, opt, ""))
		require.NoError(t, runOAuthDo(ctx, configmap.Simple{}, opt, ""))
		require.Len(t, p.verifiers, 2)
		assert.NotEqual(t, p.verifiers[0], p.verifiers[1])
		assert.NotEqual(t, p.challenges[0], p.challenges[1])
	})

	t.Run("NoPKCEUnchanged", func(t *testing.T) {
		p := newPKCEProvider(t, false)
		m := configmap.Simple{}
		require.NoError(t, runOAuthDo(ctx, m, &Options{OAuth2Config: p.oauthConfig()}, ""))
		require.Len(t, p.challenges, 1)
		assert.Empty(t, p.challenges[0])
		assert.Empty(t, p.methods[0])
		assert.Empty(t, p.verifiers[0])
		_, ok := m.Get(config.ConfigToken)
		assert.True(t, ok)
	})

	t.Run("ProviderRequiresPKCE", func(t *testing.T) {
		// Check the fake provider really enforces PKCE so the
		// tests above are meaningful
		p := newPKCEProvider(t, true)
		err := runOAuthDo(ctx, configmap.Simple{}, &Options{OAuth2Config: p.oauthConfig()}, "")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid_grant")
	})

	t.Run("PastedCodeRejected", func(t *testing.T) {
		p := newPKCEProvider(t, true)
		err := runOAuthDo(ctx, configmap.Simple{}, &Options{OAuth2Config: p.oauthConfig(), PKCE: true}, "pasted-code")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "rclone authorize")
		assert.Empty(t, p.verifiers, "no token request should be made")
	})
}

// With PKCE the remote setup must use "rclone authorize" rather than
// asking for a pasted verification code, since the verifier can't be
// kept between config states.
func TestConfigOAuthRemotePKCE(t *testing.T) {
	ctx := context.Background()
	for _, pkce := range []bool{false, true} {
		opt := &Options{
			OAuth2Config: &Config{
				ClientID:    "client-id",
				AuthURL:     "https://example.com/authorize",
				TokenURL:    "https://example.com/token",
				RedirectURL: TitleBarRedirectURL,
			},
			PKCE: pkce,
		}
		ri := &fs.RegInfo{
			Name: "pkcetest",
			Config: func(ctx context.Context, name string, m configmap.Mapper, in fs.ConfigIn) (*fs.ConfigOut, error) {
				return ConfigOut("", opt)
			},
		}
		out, err := ConfigOAuth(ctx, "pkcetest", configmap.Simple{}, ri, fs.ConfigIn{
			State: fs.StatePush("", "*oauth-remote", "", "", ""),
		})
		require.NoError(t, err)
		require.NotNil(t, out.Option)
		if pkce {
			assert.Equal(t, "config_token", out.Option.Name)
			assert.Contains(t, out.Option.Help, "rclone authorize")
		} else {
			assert.Equal(t, "config_verification_code", out.Option.Name)
		}
	}
}
