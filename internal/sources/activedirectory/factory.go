package activedirectory

import (
	"context"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/sources"
)

func init() {
	sources.RegisterFactory(SourceID, build, "url", "bind_dn", "bind_password", "token_env", "base_dn", "user_filter",
		"service_account_ous", "page_size", "timeout", "start_tls", "ca_cert", "tls_server_name")
}

// build validates sources.active_directory and constructs the plugin. It
// never dials: connection problems surface from Collect, config problems
// (missing url/bind_dn/password, plaintext ldap://, bad ca_cert) here.
func build(_ context.Context, env sources.Env) (core.SourcePlugin, error) {
	cfg, err := parseConfig(env.Config)
	if err != nil {
		return nil, err
	}
	return NewFromConfig(cfg), nil
}
