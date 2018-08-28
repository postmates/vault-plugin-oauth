package oauthplugin

import (
	"testing"
)

func TestReadAndWriteConfig(t *testing.T) {
	fixture := newTestFixture(t)

	dataIn := reasonableConfigData()
	fixture.updateConfig(dataIn)
	fixture.assertLastReqSucceeded("failed to write reasonable configuration")

	checkConfig := func() {
		dataOut := fixture.readConfig()
		fixture.assertLastReqSucceeded("failed to read configuration")

		same := func(field string) {
			if dataOut[field] != dataIn[field] {
				t.Errorf("incorrect %s: got %#v expected %#v\n", field, dataOut[field], dataIn[field])
			}
		}

		same("issuer")
		same("client_secret")
		same("client_id")
	}

	checkConfig()

	// build a new backend, simulating a restart of Vault

	fixture.Log("rebuilding backend")
	fixture.buildBackend()
	checkConfig()
}

// We can configure Google OIDC with a discovery endpoint, and all the other
// stuff gets filled in automagically.
func TestGoogleOIDCDiscovery(t *testing.T) {
	fixture := newTestFixture(t)

	fixture.updateConfig(map[string]interface{}{
		"issuer":        googleIssuer,
		"client_id":     testClientID,
		"client_secret": testClientSecret,
	})
	fixture.assertLastReqSucceeded("failed to write Google OIDC discovery configuration")

	data := fixture.readConfig()
	fixture.assertLastReqSucceeded("failed to read configuration")

	if data == nil {
		t.Fatal("nil response data\n")
	}
	if data["issuer"] != "https://accounts.google.com" {
		t.Errorf("incorrect issuer: %#v\n", data["issuer"])
	}
}

func TestRequiredConfigParams(t *testing.T) {
	fixture := newTestFixture(t)

	required := func(field string) {
		data := reasonableConfigData()
		delete(data, field)
		fixture.updateConfig(data)
		if fixture.lastReqSucceeded() {
			fixture.Errorf("config update should fail if %s missing", field)
		}
	}

	required("issuer")
	required("client_id")
	required("client_secret")
}

func reasonableConfigData() map[string]interface{} {
	return map[string]interface{}{
		"issuer":        googleIssuer,
		"client_id":     testClientID,
		"client_secret": testClientSecret,
	}
}

const (
	googleIssuer     = "https://accounts.google.com"
	testClientID     = "navygoldspitz@example.com"
	testClientSecret = "BEEFBEEFBEEFBEEFBEEF"
)
