package oauthplugin

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/hashicorp/vault/logical"
)

type testFixture struct {
	*testing.T
	backend         logical.Backend
	storage         logical.Storage
	lastRequest     *logical.Request
	lastResponse    *logical.Response
	lastResponseErr error
}

const (
	testProviderAuthURL = "http://example.com/auth"
	testEmail           = "john.doe@example.com"
	testSubject         = "subject123908713857189"
	testDomain          = "example.com"
	testGivenName       = "John Doe"
)

func newTestFixture(t *testing.T) *testFixture {
	fixture := &testFixture{T: t}
	fixture.buildStorage()
	fixture.buildBackend()
	return fixture
}

func (fixture *testFixture) buildStorage() {
	fixture.storage = &logical.InmemStorage{}
}

func (fixture *testFixture) buildBackend() {
	defaultLeaseTTLVal := time.Hour * 12
	maxLeaseTTLVal := time.Hour * 24

	config := &logical.BackendConfig{
		System: &logical.StaticSystemView{
			DefaultLeaseTTLVal: defaultLeaseTTLVal,
			MaxLeaseTTLVal:     maxLeaseTTLVal,
		},
		StorageView: fixture.storage,
	}
	backend, err := Factory(context.Background(), config)
	if err != nil {
		fixture.Fatalf("unable to create backend: %v", err)
	}

	fixture.backend = backend
}

func (fixture *testFixture) login(code string, role string) *logical.Response {
	return fixture.executeRequest(&logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "login",
		Storage:   fixture.storage,
		Data: map[string]interface{}{
			"code": code,
			"role": role,
		},
	})
}

func (fixture *testFixture) createDefaultRole() {
	fixture.executeRequest(&logical.Request{
		Operation: logical.CreateOperation,
		Path:      "role/default",
		Storage:   fixture.storage,
		Data: map[string]interface{}{
			"policies": "admin",
			"num_uses": 42,
			"ttl":      300,
			"max_ttl":  3600,
		},
	})

	if !fixture.lastReqSucceeded() {
		fixture.Fatal("failed to create default role", fixture.lastResponse, fixture.lastResponseErr)
	}
}

func (fixture *testFixture) readRole(name string) map[string]interface{} {
	response := fixture.executeRequest(&logical.Request{
		Operation: logical.ReadOperation,
		Path:      "role/" + name,
		Storage:   fixture.storage,
	})

	return response.Data
}

func (fixture *testFixture) updateRole(name string, data map[string]interface{}) *logical.Response {
	return fixture.executeRequest(&logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "role/" + name,
		Storage:   fixture.storage,
		Data:      data,
	})
}

func (fixture *testFixture) createRole(name string, data map[string]interface{}) *logical.Response {
	return fixture.executeRequest(&logical.Request{
		Operation: logical.CreateOperation,
		Path:      "role/" + name,
		Storage:   fixture.storage,
		Data:      data,
	})
}

func (fixture *testFixture) installTestProvider() {
	fixture.backend.(*oauthBackend).cachedIdProvider = &testIdProvider{validCode: "validtestcode"}

}

func (fixture *testFixture) executeRequest(request *logical.Request) *logical.Response {
	fixture.lastRequest = request
	fixture.lastResponse, fixture.lastResponseErr = fixture.backend.HandleRequest(context.Background(), fixture.lastRequest)
	return fixture.lastResponse
}

func (fixture *testFixture) updateConfig(data map[string]interface{}) *logical.Response {
	return fixture.executeRequest(&logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config",
		Storage:   fixture.storage,
		Data:      data,
	})
}

func (fixture *testFixture) readConfig() map[string]interface{} {
	response := fixture.executeRequest(&logical.Request{
		Operation: logical.ReadOperation,
		Path:      "config",
		Storage:   fixture.storage,
	})

	return response.Data
}

func (fixture *testFixture) lastReqSucceeded() bool {
	if fixture.lastResponseErr != nil {
		return false
	}

	if fixture.lastResponse == nil {
		return true
	}

	return !fixture.lastResponse.IsError()
}

func (fixture *testFixture) assertLastReqSucceeded(explanation string) {
	if !fixture.lastReqSucceeded() {
		fixture.Fatalf("%s\nerr:%#v response:%#v\n",
			explanation, fixture.lastResponseErr, fixture.lastResponse)
	}
}

func (fixture *testFixture) assertLastReqFailed(explanation string) {
	if fixture.lastReqSucceeded() {
		fixture.Fatalf("%s\nerr:%#v response:%#v\n",
			explanation, fixture.lastResponseErr, fixture.lastResponse)
	}
}

type testIdProvider struct {
	validCode string
}

func (idp *testIdProvider) ValidateCode(ctx context.Context, code string, redirect_uri string) (map[string]interface{}, error) {
	if code != idp.validCode {
		return nil, errors.New("invalid authentication code")
	}

	claims := map[string]interface{}{
		"sub":        testSubject,
		"email":      testEmail,
		"domain":     testDomain,
		"given_name": testGivenName,
	}
	return claims, nil
}

func (idp *testIdProvider) AuthURL(ctx context.Context) string {
	return testProviderAuthURL
}

func (idp *testIdProvider) Issuer() string {
	return "http://example.com"
}

func (idp *testIdProvider) ClientID() string {
	return testClientID
}

func (idp *testIdProvider) ClientSecret() string {
	return testClientSecret
}
