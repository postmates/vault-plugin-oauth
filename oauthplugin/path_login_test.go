package oauthplugin

import (
	"reflect"
	"testing"
	"time"
)

func TestLogin(t *testing.T) {
	fixture := newTestFixture(t)
	fixture.createDefaultRole()

	fixture.login("validtestcode", "default")
	if fixture.lastReqSucceeded() {
		fixture.Error("login before plugin is configured should fail")
	}

	fixture.installTestProvider()

	fixture.login("boguscode", "default")
	if fixture.lastReqSucceeded() {
		fixture.Error("login with bogus code should fail")
	}

	fixture.login("validtestcode", "bogusrole")
	if fixture.lastReqSucceeded() {
		fixture.Error("login with nonexistant role should fail")
	}

	fixture.login("validtestcode", "")
	if fixture.lastReqSucceeded() {
		fixture.Error("login with empty role should fail")
	}

	// A successful login applies settings from the role to the returned token
	{
		fixture.login("validtestcode", "default")
		if !fixture.lastReqSucceeded() {
			fixture.Error("login with valid code should succeed")
		}
		auth := fixture.lastResponse.Auth
		if auth == nil {
			fixture.Error("response should have Auth set")
		} else {
			expectedPolicies := []string{"admin"}
			if !reflect.DeepEqual(auth.Policies, expectedPolicies) {
				fixture.Error("policies should be", expectedPolicies, "but are", auth.Policies)
			}

			if auth.NumUses != 42 {
				fixture.Error("NumUses should be 42, was", auth.NumUses)
			}

			if auth.LeaseOptions.TTL != 300*time.Second {
				fixture.Error("TTL should be 5m, was", auth.LeaseOptions.TTL)
			}

			if auth.LeaseOptions.MaxTTL != 3600*time.Second {
				fixture.Error("MaxTTL should be 1h, was", auth.LeaseOptions.MaxTTL)
			}

			if auth.DisplayName != testSubject {
				fixture.Error("DisplayName should be", testSubject, "got", auth.DisplayName)
			}

			if auth.Alias == nil {
				fixture.Error("response should have an Alias")
			} else {
				if auth.Alias.Name != testSubject {
					fixture.Error("Alias.Name should be", testSubject, "got", auth.Alias.Name)
				}
				if auth.Alias.Metadata == nil {
					fixture.Error("response should have alias metadata")
				} else {
					if auth.Alias.Metadata["given_name"] != testGivenName {
						fixture.Error("Alias given_name wrong:", auth.Alias.Metadata["given_name"])
					}
					if auth.Alias.Metadata["email"] != testEmail {
						fixture.Error("Alias email wrong:", auth.Alias.Metadata["email"])
					}
				}
			}
		}
	}

	// Login fails if user claim is missing
	{
		fixture.updateRole("default", map[string]interface{}{
			"user_claim": "nonexistant",
		})
		fixture.login("validtestcode", "default")
		if fixture.lastReqSucceeded() {
			fixture.Error("login should fail if user_claim is missing")
		}
		fixture.createDefaultRole()
	}

	// given_name and email are optional
	{
		fixture.updateRole("default", map[string]interface{}{
			"given_name_claim": "nonexistant",
			"email_claim":      "nonexistant",
		})
		fixture.login("validtestcode", "default")
		if !fixture.lastReqSucceeded() {
			fixture.Error("login should succeed even if given_name or email claims are missing")
		} else {
			metadata := fixture.lastResponse.Auth.Alias.Metadata
			if metadata["email"] != "" {
				fixture.Error("email metadata should be empty")
			}
			if metadata["given_name"] != "" {
				fixture.Error("given_name metadata should be empty")
			}
		}
		fixture.createDefaultRole()
	}

	// arbitrary claim bindings
	{
		// domain matches, everything is good
		fixture.updateRole("default", map[string]interface{}{
			"bound_claims": map[string]interface{}{"domain": "example.com"},
		})
		fixture.login("validtestcode", "default")
		if !fixture.lastReqSucceeded() {
			fixture.Error("login should succeed")
		}

		// domain doesn't match
		fixture.updateRole("default", map[string]interface{}{
			"bound_claims": map[string]interface{}{"domain": "other.example.com"},
		})
		fixture.login("validtestcode", "default")
		if fixture.lastReqSucceeded() {
			fixture.Error("login should fail: domain shouldn't match")
		}

		// bound claim not defined
		fixture.updateRole("default", map[string]interface{}{
			"bound_claims": map[string]interface{}{"nonexistant": "claim"},
		})
		fixture.login("validtestcode", "default")
		if fixture.lastReqSucceeded() {
			fixture.Error("login should fail: bound claim not defined")
		}

		fixture.createDefaultRole()
	}
}
