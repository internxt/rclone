// Authentication handling for Internxt
package internxt

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
	internxtauth "github.com/internxt/rclone-adapter/auth"
	internxtconfig "github.com/internxt/rclone-adapter/config"
	"github.com/rclone/rclone/fs"
	"github.com/rclone/rclone/fs/config/configmap"
	"github.com/rclone/rclone/lib/oauthutil"
	"golang.org/x/oauth2"
)

const (
	driveWebURL      = "https://drive.internxt.com"
	defaultLocalPort = "53682"
	bindAddress      = "127.0.0.1:" + defaultLocalPort
	tokenExpiry2d    = 48 * time.Hour
)

// authResult holds the result from the SSO callback
type authResult struct {
	mnemonic string
	token    string
	bucket   string
	err      error
}

// authServer handles the local HTTP callback for SSO login
type authServer struct {
	listener net.Listener
	server   *http.Server
	result   chan authResult
}

// newAuthServer creates a new local auth callback server
func newAuthServer() (*authServer, error) {
	listener, err := net.Listen("tcp", bindAddress)
	if err != nil {
		return nil, fmt.Errorf("failed to start auth server on %s: %w", bindAddress, err)
	}

	s := &authServer{
		listener: listener,
		result:   make(chan authResult, 1),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleCallback)
	s.server = &http.Server{Handler: mux}

	return s, nil
}

// start begins serving requests in a goroutine
func (s *authServer) start() {
	go func() {
		err := s.server.Serve(s.listener)
		if err != nil && err != http.ErrServerClosed {
			s.result <- authResult{err: err}
		}
	}()
}

// stop gracefully shuts down the server
func (s *authServer) stop() {
	if s.server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = s.server.Shutdown(ctx)
	}
}

// handleCallback processes the SSO callback with mnemonic and token
func (s *authServer) handleCallback(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	mnemonicB64 := query.Get("mnemonic")
	tokenB64 := query.Get("newToken")

	if mnemonicB64 == "" || tokenB64 == "" {
		http.Error(w, "Missing mnemonic or token", http.StatusBadRequest)
		s.result <- authResult{err: errors.New("missing mnemonic or token in callback")}
		return
	}

	mnemonicBytes, err := base64.StdEncoding.DecodeString(mnemonicB64)
	if err != nil {
		http.Error(w, "Invalid mnemonic encoding", http.StatusBadRequest)
		s.result <- authResult{err: fmt.Errorf("failed to decode mnemonic: %w", err)}
		return
	}

	tokenBytes, err := base64.StdEncoding.DecodeString(tokenB64)
	if err != nil {
		http.Error(w, "Invalid token encoding", http.StatusBadRequest)
		s.result <- authResult{err: fmt.Errorf("failed to decode token: %w", err)}
		return
	}

	// Send success HTML response
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head>
	<p>placeholder</p>
</html>`)

	s.result <- authResult{
		mnemonic: string(mnemonicBytes),
		token:    string(tokenBytes),
	}
}

// doAuth performs the interactive SSO authentication
func doAuth(ctx context.Context) (token, mnemonic string, err error) {
	server, err := newAuthServer()
	if err != nil {
		return "", "", err
	}
	defer server.stop()

	server.start()

	callbackURL := "http://" + bindAddress + "/"
	callbackB64 := base64.StdEncoding.EncodeToString([]byte(callbackURL))
	authURL := fmt.Sprintf("%s/login?universalLink=true&redirectUri=%s", driveWebURL, callbackB64)

	fs.Logf(nil, "")
	fs.Logf(nil, "If your browser doesn't open automatically, visit this URL:")
	fs.Logf(nil, "%s", authURL)
	fs.Logf(nil, "")
	fs.Logf(nil, "Log in and authorize rclone for access")
	fs.Logf(nil, "Waiting for authentication...")

	if err = oauthutil.OpenURL(authURL); err != nil {
		fs.Errorf(nil, "Failed to open browser: %v", err)
		fs.Logf(nil, "Please manually open the URL above in your browser")
	}

	select {
	case result := <-server.result:
		if result.err != nil {
			return "", "", result.err
		}

		fs.Logf(nil, "SSO login successful, refreshing token to fetch user data...")

		cfg := internxtconfig.NewDefaultToken(result.token)
		resp, err := internxtauth.RefreshToken(ctx, cfg)
		if err != nil {
			return "", "", fmt.Errorf("failed to refresh token: %w", err)
		}

		if resp.NewToken == "" {
			return "", "", errors.New("refresh response missing newToken")
		}

		fs.Logf(nil, "Authentication successful!")
		return resp.NewToken, result.mnemonic, nil

	case <-time.After(5 * time.Minute):
		return "", "", errors.New("authentication timeout after 5 minutes")
	}
}


type userInfo struct {
	RootFolderID string
	Bucket       string
}

type userInfoConfig struct {
	Token string
}

// getUserInfo fetches user metadata from the JWT token and refresh endpoint
func getUserInfo(ctx context.Context, cfg *userInfoConfig) (*userInfo, error) {
	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	token, _, err := parser.ParseUnverified(cfg.Token, jwt.MapClaims{})
	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("invalid token claims")
	}

	info := &userInfo{}

	if payload, ok := claims["payload"].(map[string]any); ok {
		if uuid, ok := payload["uuid"].(string); ok {
			info.RootFolderID = uuid
		} else if rootFolderID, ok := payload["rootFolderId"].(string); ok {
			info.RootFolderID = rootFolderID
		}
	}

	if info.RootFolderID == "" {
		if uuid, ok := claims["uuid"].(string); ok {
			info.RootFolderID = uuid
		} else if sub, ok := claims["sub"].(string); ok {
			info.RootFolderID = sub
		}
	}

	if info.RootFolderID == "" {
		fs.Debugf(nil, "JWT token claims: %+v", claims)
		return nil, errors.New("could not find rootFolderId/uuid in JWT token")
	}

	refreshCfg := internxtconfig.NewDefaultToken(cfg.Token)
	resp, err := internxtauth.RefreshToken(ctx, refreshCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to get bucket: %w", err)
	}

	if resp.User.Bucket == "" {
		return nil, errors.New("refresh response missing user.bucket")
	}

	info.Bucket = resp.User.Bucket

	fs.Debugf(nil, "User info: rootFolderId=%s, bucket=%s", info.RootFolderID, info.Bucket)
	return info, nil
}

// parseJWTExpiry extracts the expiry time from a JWT token string
func parseJWTExpiry(tokenString string) (time.Time, error) {
	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	token, _, err := parser.ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		return time.Time{}, fmt.Errorf("failed to parse token: %w", err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return time.Time{}, errors.New("invalid token claims")
	}

	exp, ok := claims["exp"].(float64)
	if !ok {
		return time.Time{}, errors.New("token missing expiration")
	}

	return time.Unix(int64(exp), 0), nil
}

// jwtToOAuth2Token converts a JWT string to an oauth2.Token with expiry
func jwtToOAuth2Token(jwtString string) (*oauth2.Token, error) {
	expiry, err := parseJWTExpiry(jwtString)
	if err != nil {
		return nil, err
	}

	return &oauth2.Token{
		AccessToken: jwtString,
		TokenType:   "Bearer",
		Expiry:      expiry,
	}, nil
}

// refreshJWTToken refreshes the token using Internxt's refresh endpoint
func refreshJWTToken(ctx context.Context, name string, m configmap.Mapper) error {
	currentToken, err := oauthutil.GetToken(name, m)
	if err != nil {
		return fmt.Errorf("failed to get current token: %w", err)
	}

	mnemonic, _ := m.Get("mnemonic")

	cfg := internxtconfig.NewDefaultToken(currentToken.AccessToken)
	resp, err := internxtauth.RefreshToken(ctx, cfg)
	if err != nil {
		return fmt.Errorf("refresh request failed: %w", err)
	}

	if resp.NewToken == "" {
		return errors.New("refresh response missing newToken")
	}

	// Convert JWT to oauth2.Token format
	token, err := jwtToOAuth2Token(resp.NewToken)
	if err != nil {
		return fmt.Errorf("failed to parse refreshed token: %w", err)
	}

	err = oauthutil.PutToken(name, m, token, false)
	if err != nil {
		return fmt.Errorf("failed to save token: %w", err)
	}

	if resp.User.Bucket != "" {
		m.Set("bucket", resp.User.Bucket)
	}
	m.Set("mnemonic", mnemonic)

	fs.Debugf(name, "Token refreshed successfully, new expiry: %v", token.Expiry)
	return nil
}
