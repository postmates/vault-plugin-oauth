package oauthplugin

import (
	"testing"

	"github.com/hashicorp/vault/logical"
)

func TestAuthURL(t *testing.T) {
	fixture := newTestFixture(t)

	fixture.getAuthURL()
	if fixture.lastReqSucceeded() {
		fixture.Error("getting auth URL should fail if plugin isn't configured")
	}

	fixture.installTestProvider()
	authURL := fixture.getAuthURL()
	if !fixture.lastReqSucceeded() {
		fixture.Errorf("getting auth URL failed: %#v", fixture.lastResponseErr)
	}
	if authURL != testProviderAuthURL {
		fixture.Errorf("wrong auth URL: %#v\n", authURL)
	}
}

func (fixture *testFixture) getAuthURL() string {
	response := fixture.executeRequest(&logical.Request{
		Operation: logical.ReadOperation,
		Path:      "auth-request",
		Storage:   fixture.storage,
		Data:      map[string]interface{}{},
	})

	if response == nil {
		return ""
	}
	url, ok := response.Data["url"].(string)
	if !ok {
		return ""
	}
	return url
}
