package oauthplugin

import (
	"reflect"
	"testing"
)

func TestCreateAndUpdateRole(t *testing.T) {
	fixture := newTestFixture(t)

	fixture.createRole("default", map[string]interface{}{
		"user_claim": "sub",
	})

	fixture.assertLastReqSucceeded("failed to create role")

	fixture.readRole("default")
	fixture.assertLastReqSucceeded("failed to read role")
	if fixture.lastResponse.Data["user_claim"] != "sub" {
		fixture.Fatal(fixture.lastResponse)
	}

	fixture.updateRole("default", map[string]interface{}{
		"policies": "admin,foo",
	})

	fixture.assertLastReqSucceeded("failed to update role")

	fixture.readRole("default")
	fixture.assertLastReqSucceeded("failed to read role the 2nd time")
	if fixture.lastResponse.Data["user_claim"] != "sub" {
		fixture.Fatal(fixture.lastResponse)
	}

	if fixture.lastResponse.Data["user_claim"] != "sub" {
		fixture.Fatal("user_claim should still be sub")
	}

	expectedPolicies := []string{"admin", "foo"}
	policies := fixture.lastResponse.Data["policies"].([]string)
	if !reflect.DeepEqual(policies, expectedPolicies) {
		fixture.Fatal("policies should be", expectedPolicies, "but are", policies)
	}
}
