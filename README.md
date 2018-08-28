# vault-plugin-oauth

This is a plugin for [Hashicorp Vault](https://www.github.com/hashicorp/vault).
It's been verified to work with these OIDC providers:

- [Dex](https://github.com/coreos/dex)
- [Google](https://google.com/)

It should also work against any other OIDC provider, such as:

- [Auth0](https://auth0.com/)
- [AWS Cognito](https://aws.amazon.com/cognito/)
- [Azure Active Directory](https://azure.microsoft.com/en-us/services/active-directory/)
- [Okta](https://www.okta.com/)

## Features

- With the included `vault-login-oauth` program installed by users, includes
  everything needed to authenticate without any copy-pasting or custom
  scripting. It's the author's hope this functionality can be included in the
  `vault` binary as a login method.
- Implements a
  [confidential OAuth client](https://tools.ietf.org/html/rfc6749#section-2.1)
  and the
  [authorization code grant](https://oauth.net/2/grant-types/authorization-code/).
  This is generally the most secure OAuth flow because the client secret
  ensures tokens are only given to the legitimate OAuth client (the Vault
  server). The client secret is securely stored by Vault and never shared with
  users.
- User credentials are never shared with anything besides the OAuth provider,
  through the user's browser. Credentials aren't shared with Vault.

## How to use

1. Run `vault-login-oauth`.
2. Complete the login form in your browser.
3. Profit.

It's also possible with some providers (those that support the magic
`urn:ietf:wg:oauth:2.0:oob` redirect URI: Google and Dex do, others might) to
log in without installing `vault-login-oauth`. For example this will work on
Mac OS:

1. `open $(vault read -field=url /auth/oauth/auth-request)`
2. Copy the authorization code after entering credentials.
3. `vault write /auth/oauth/login role=default code="$(pbpaste)"`
4. Put the resulting token in `~/.vault-token`.
5. Profit.

Linux users use `xdg-open` and `xsel --clipboard --output`.

## How to install

Pick some directory that will hold vault plugins. I'll use `/usr/lib/vault`.

Include `plugin_directory = "/usr/lib/vault"` in the Vault configuration file.
Start Vault with `vault server -config=...`.

Build the plugin:

    go build -o /usr/lib/vault/vault-plugin-oauth \
		/github.com/postmates/vault-plugin-oauth

Register the plugin:

    sha=$(shasum -a 256 ~/vaultplugins/vault-plugin-oauth | cut -f1 '-d ')
	vault write sys/plugins/catalog/vault-plugin-oauth \
		"sha_256=$sha" \
		command=vault-plugin-oauth

Enable the plugin (change the path if you like):

	vault auth enable -path=oauth -plugin-name=vault-plugin-oauth plugin

Configure the plugin. We use JSON input from stdin so other users on the system
can't run `ps` and see the client secret. The issuer is just the base
URL, without the `.well-known/...` suffix. For example, Google is
`https://accounts.google.com`.

	vault write auth/oauth/config - <<EOF
	{
		"issuer": ISSUER,
		"client_secret": OAUTH_CLIENT_SECRET,
		"client_id": OAUTH_CLIENT_ID
	}
	EOF

Configure a role. Roles contain options for the issued tokens, and can contain
additional assertions about the claims in the returned identity token. For
example, Google includes a `hd` claim if the user is part of a G Suite hosted
domain. OIDC also specifies an `email_verified` claim. We can restrict the role
only to the `example.com` hosted domain and users with verified email addresses
with a role such as:

	vault write auth/oauth/role/default - <<EOF
	{
		"bound_claims": {
			"hd": "postmates.com",
			"email_verified": true
		}
	}
	EOF

## How it works

![protococol flow diagram](doc/protocol.svg)

## To do

Some providers (for example GitHub) implement OAuth but not OIDC. Since OAuth
proper doesn't provide identity information, provider-specific support is
required. See [GitHub's user API](https://developer.github.com/v3/users/), for
example.

Some providers require an exact match on the redirect URI, which precludes
binding the `vault-login-oauth` program to port zero, as this results in an
unpredictable port number which will result in an invalid redirect URI. Ideally
providers could be configured to
[allow any port on 127.0.0.1](https://tools.ietf.org/html/rfc8252#section-7.3),
but as a workaround the plugin configuration could include a listen port number
which advises `vault-login-oauth` to listen on that port.

Some providers give a way to discover a user's group membership, but there is
currently no mechanism to use that information.

[CIDR bound tokens](https://www.vaultproject.io/docs/concepts/tokens.html#cidr-bound-tokens)
are not implemented.

Token renewal is not implemented.
