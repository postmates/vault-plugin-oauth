// vault-login-oauth is the program a user runs to log in to Vault with OAuth.
//
// It will:
//
// 1. Query Vault to determine what the authorization request URL should be,
//    according to the configuration there.
// 2. Start a webserver listening on 127.0.0.1.
// 3. Open a browser where the user will enter credentials.
// 4. Receive the authorization code when the user has finished entering
//    credentials via the HTTP server.
// 5. Forward this authorization code to Vault.
// 6. Save the token returned by Vault for subsequent use.

package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"time"

	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/command/token"
)

type oidcLogin struct {
	server       *http.Server
	listener     net.Listener
	vault        *api.Logical
	authReqURL   *url.URL
	redirectURL  string
	authDone     context.CancelFunc
	authErr      error
	authResponse *api.Secret
	callbackPath string

	// role and pluginPath are specified by the user as command-line options.
	role       string
	pluginPath string

	// stateNonce holds a random value we use to mitigate CSRF attacks.
	stateNonce string
}

const (
	callbackSuffix = "/cb"
	authReqSuffix  = "/auth-request"
	// how long we'll wait for the OAuth redirect after opening a browser
	oauthTimeout = 5 * time.Minute
)

func newLogin(pluginPath string, role string) *oidcLogin {
	login := &oidcLogin{
		server:     &http.Server{},
		role:       role,
		pluginPath: pluginPath,
		stateNonce: generateNonce(),

		// The callback URI must be unique for each authorization server. Since
		// each mount of the plugin corresponds to an authorization server,
		// incorporating the pluginPath accomplishes that.
		//
		// https://tools.ietf.org/html/rfc8252#section-8.10
		callbackPath: pluginPath + callbackSuffix,
	}

	http.HandleFunc(login.callbackPath, login.handleOAuthCallback)

	return login
}

func (login *oidcLogin) makeVaultClient() {
	vaultClient, err := api.NewClient(nil)
	if err != nil {
		fatal("Couldn't create Vault client:", err)
	}
	login.vault = vaultClient.Logical()
}

// startListening binds to some available port on 127.0.0.1. It then determines
// redirectURL.
func (login *oidcLogin) startListening() {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		fatal(err)
	}
	login.listener = listener
	login.redirectURL = fmt.Sprintf("http://%s%s", listener.Addr(), login.callbackPath)
}

// getAuthReqURL queries Vault for the authorization request URL, according to
// the OAuth provider configured on the Vault server. It adds the redirect_uri
// and state parameters, which aren't known by the Vault server.
func (login *oidcLogin) getAuthReqURL() {
	secret, err := login.vault.Read(login.pluginPath + authReqSuffix)
	if err != nil || secret == nil || secret.Data == nil {
		fatal("Failed to get authorization request URL:", err)
	}
	rawURL := secret.Data["url"].(string)
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		fatal("Failed parsing authorization request URL from Vault:", err)
	}

	query := parsedURL.Query()
	query.Set("redirect_uri", login.redirectURL)
	query.Set("state", login.stateNonce)
	parsedURL.RawQuery = query.Encode()
	login.authReqURL = parsedURL
}

// HTTP handler for the redirect_uri. Once the user has gone through the
// authentication flow at the identity provider they will be redirected here,
// at which point we obtain the authorization code if authentication was
// successful, or an error otherwise.
func (login *oidcLogin) handleOAuthCallback(writer http.ResponseWriter, req *http.Request) {
	writer.Header().Set("Content-Type", "text/plain; charset=utf-8")

	query := req.URL.Query()
	code := query.Get("code")
	state := query.Get("state")

	if state != login.stateNonce {
		// This indicates either a CSRF attack or a buggy authorization server.
		// We won't even dignify it with a response.
		//
		// https://tools.ietf.org/html/rfc6819#section-5.3.5
		// https://tools.ietf.org/html/rfc6749#section-10.12
		// https://tools.ietf.org/html/rfc6749#section-4.1.2
		fatal("DANGER: POSSIBLE CSRF ATTACK DETECTED.\nReceived state", state, "expected", login.stateNonce)
		return
	}

	secret, err := login.vault.Write(login.pluginPath+"/login", map[string]interface{}{
		"code":         code,
		"redirect_uri": login.redirectURL,
		"role":         login.role,
	})

	if err == nil {
		writer.WriteHeader(http.StatusOK)
		fmt.Fprint(writer, "authentication successful")
		login.authErr = nil
	} else {
		writer.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(writer, "authentication error: ", err)
		login.authErr = err
	}

	login.authResponse = secret
	login.authDone()
}

func (login *oidcLogin) runOAuthFlow() (*api.Secret, error) {
	ctx, cancel := context.WithTimeout(context.Background(), oauthTimeout)
	login.authDone = cancel

	// First we start the server.
	go func() {
		err := login.server.Serve(login.listener)
		if err != nil && err != http.ErrServerClosed {
			fatal("error running HTTP server:", err)
		}
	}()

	// Then we open a browser.
	openURL(login.authReqURL.String())

	// handleOAuthCallback will cancel the context when the callback has been
	// received, or the context will time out.
	<-ctx.Done()
	login.server.Shutdown(ctx)

	if ctx.Err() != context.Canceled {
		return nil, ctx.Err()
	}
	return login.authResponse, login.authErr
}

func main() {
	// We must define our own flagSet because
	// github.com/hashicorp/vault/command/token depends on "testing", which
	// will pollute the global flags :(
	flagSet := flag.NewFlagSet("vault-login-oauth", flag.ExitOnError)
	roleFlag := flagSet.String("role", "default", "Authenticate as this role")
	pathFlag := flagSet.String("path", "/auth/oauth", "Mount point of the OAuth plugin")

	flagSet.Parse(os.Args[1:])

	login := newLogin(*pathFlag, *roleFlag)
	login.makeVaultClient()
	login.startListening()
	login.getAuthReqURL()

	response, err := login.runOAuthFlow()
	if err == context.DeadlineExceeded {
		fatal("Timed out waiting for response")
	} else if err != nil {
		fatal(err)
	}

	if response == nil || response.Auth == nil {
		fatal("Response contained no authentication information")
	}

	clientToken := response.Auth.ClientToken
	if clientToken == "" {
		fatal("No token in response!")
	}
	tokenHelper := token.InternalTokenHelper{}
	err = tokenHelper.Store(clientToken)
	if err != nil {
		fatal("Failed to save token:", err)
	}
	os.Exit(0)
}

// fatal prints something to stderr and exits immediately.
func fatal(v ...interface{}) {
	fmt.Fprintln(os.Stderr, v...)
	os.Exit(1)
}

func openURL(url string) {
	var err error

	switch runtime.GOOS {
	case "linux":
		err = exec.Command("xdg-open", url).Start()
	case "windows":
		err = exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	case "darwin":
		err = exec.Command("open", url).Start()
	default:
		err = errors.New("unsupported platform")
	}
	if err != nil {
		fmt.Printf("Error automatically opening browser: %s\nManually open this URL to continue:\n%s\n", err, url)
	}
}

// Return a random, URL-safe string
func generateNonce() string {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		log.Fatal(err)
	}

	return base64.URLEncoding.EncodeToString(b)
}
