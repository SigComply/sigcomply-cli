// Package azcommon is the shared credential, subscription, and resource-graph
// foundation reused by every azure.* source plugin (WU-5.0). It lives under
// internal/sources/azure/internal so Go's internal-visibility rule restricts
// imports to packages rooted at internal/sources/azure/ — only Azure sources
// may use it, never aws/gcp.
//
// Auth model: a single DefaultAzureCredential drives all azure.* sources. In
// CI it resolves through the session `azure/login` leaves behind (OIDC /
// workload-identity federation — no long-lived secret); locally through
// `az login` or the AZURE_* environment credential. ARM-plane sources scope to
// a configured subscription_id; the Graph-plane source (azure.entra) uses the
// credential's home tenant. See docs/configuration.md §Azure.
package azcommon

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resourcegraph/armresourcegraph"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armsubscriptions/v2"

	"github.com/sigcomply/sigcomply-cli/internal/sources"
)

// OAuth ".default" scopes for the two planes azure.* sources reach. The
// ".default" suffix requests all statically-assigned app permissions for the
// resource; do not hardcode sovereign-cloud variants — set ClientOptions.Cloud
// instead so the audience flips automatically.
const (
	ScopeARM   = "https://management.azure.com/.default" // Azure Resource Manager
	ScopeGraph = "https://graph.microsoft.com/.default"  // Microsoft Graph
)

// Config is the parsed Azure source configuration shared by all azure.* plugins.
type Config struct {
	SubscriptionID string // ARM-plane scope; required for resource sources
	TenantID       string // optional; used by the Graph plane (azure.entra)
}

// ConfigKeys are the config keys ParseConfig reads. Declared beside the
// parser so the fourteen azure.* factories cannot drift from it.
var ConfigKeys = []string{"subscription_id", "tenant_id"}

// ParseConfig reads subscription_id / tenant_id from a source config map. When
// requireSubscription is true (every ARM-plane source) a missing/empty
// subscription_id is an error; Graph-only sources (azure.entra) pass false and
// rely on the credential's home tenant.
func ParseConfig(raw map[string]any, requireSubscription bool) (Config, error) {
	cfg := Config{
		SubscriptionID: strings.TrimSpace(sources.StringOpt(raw, "subscription_id")),
		TenantID:       strings.TrimSpace(sources.StringOpt(raw, "tenant_id")),
	}
	if requireSubscription && cfg.SubscriptionID == "" {
		return Config{}, fmt.Errorf("azure: subscription_id required")
	}
	return cfg, nil
}

// credentialTimeout bounds the single token request NewCredential makes.
// DefaultAzureCredential probes IMDS (~1s) and then shells out to az / azd /
// pwsh at 10s each, so an unauthenticated workstation can take ~30s to
// conclude it has nothing. That is a diagnosis, not a hang, and the cache
// below means we pay it at most once per scope — this bound exists only so a
// blackholed endpoint cannot stall the run forever, and is deliberately well
// above the chain's own worst case so the operator sees the real error rather
// than a timeout that hides it.
const credentialTimeout = 60 * time.Second

// newDefaultCredential is the seam over azidentity so tests can exercise
// NewCredential without a real identity chain. Mirrors newTokenSource in
// internal/sources/gcp/directory/auth.go.
var newDefaultCredential = func() (azcore.TokenCredential, error) {
	return azidentity.NewDefaultAzureCredential(nil)
}

// credCache memoizes one verified credential per scope.
//
// Every azure.* factory asks for a credential, so without this a run with 13
// ARM sources configured would build 13 independent DefaultAzureCredential
// chains and make 13 token requests — and on an unauthenticated runner would
// pay the ~30s probe 13 times before reporting the same failure once.
//
// Keyed by scope alone, because DefaultAzureCredential resolves ONE ambient
// identity per process: tenant_id is parsed but does not select an identity
// (see docs/architecture/12-multicloud-sources.md). If per-tenant credentials
// ever land, this key MUST grow a tenant component — the awscfg cache is
// keyed by the whole Options value for exactly that reason, and collapsing
// two identities into one cache entry is the failure that package exists to
// prevent.
var (
	credMu    sync.Mutex
	credCache = map[string]azcore.TokenCredential{}
)

// NewCredential builds a DefaultAzureCredential — the env / workload-identity /
// managed-identity / Azure-CLI chain — and proves it can mint a token for
// scope before returning it.
//
// The verification is the point. NewDefaultAzureCredential cannot fail in
// practice: every sub-credential whose constructor fails is still appended to
// the chain wrapped in an error reporter, so the chain is never empty and
// construction always succeeds. Without a token request, a source configured
// in `sources:` with no Azure identity anywhere in the environment would
// build cleanly and fail at its first Graph/ARM call — after the collector
// had retried a permanent failure through its whole backoff budget.
// `sources:` is the operator's declaration of scope, so an unusable
// credential is a configuration error, caught before collection starts.
//
// A failed verification is not cached: the cache write is reached only on
// success, so a credential that appears mid-run is picked up rather than
// shadowed.
func NewCredential(ctx context.Context, scope string) (azcore.TokenCredential, error) {
	credMu.Lock()
	defer credMu.Unlock()
	if cred, ok := credCache[scope]; ok {
		return cred, nil
	}
	cred, err := newDefaultCredential()
	if err != nil {
		return nil, fmt.Errorf("azure: building default credential: %w", err)
	}
	vctx, cancel := context.WithTimeout(ctx, credentialTimeout)
	defer cancel()
	if err := VerifyCredential(vctx, cred, scope); err != nil {
		return nil, fmt.Errorf("no usable Azure credentials: export AZURE_TENANT_ID, "+
			"AZURE_CLIENT_ID and AZURE_CLIENT_SECRET, use workload-identity "+
			"federation in CI, or run `az login` locally: %w", err)
	}
	credCache[scope] = cred
	return cred, nil
}

// ResetCredentialCache clears the memoized credentials. Test-only.
func ResetCredentialCache() {
	credMu.Lock()
	defer credMu.Unlock()
	credCache = map[string]azcore.TokenCredential{}
}

// VerifyCredential confirms the credential can mint a token for scope (ScopeARM
// or ScopeGraph). It makes one token request and no resource call — the
// cheapest credential smoke check.
func VerifyCredential(ctx context.Context, cred azcore.TokenCredential, scope string) error {
	if _, err := cred.GetToken(ctx, policy.TokenRequestOptions{Scopes: []string{scope}}); err != nil {
		return fmt.Errorf("azure: credential verification (%s): %w", scope, err)
	}
	return nil
}

// SubscriptionInfo is a cloud-neutral view of one Azure subscription.
type SubscriptionInfo struct {
	ID          string
	DisplayName string
	State       string
}

// subsLister is the slice of *armsubscriptions.Client that ListSubscriptions
// drives; tests inject a fake returning an in-memory pager.
type subsLister interface {
	NewListPager(*armsubscriptions.ClientListOptions) *runtime.Pager[armsubscriptions.ClientListResponse]
}

// ListSubscriptions enumerates every subscription the credential can reach. The
// Subscriptions client is tenant-scoped and takes no subscription argument, so
// this is how a plugin validates a configured subscription_id or discovers
// scope.
func ListSubscriptions(ctx context.Context, cred azcore.TokenCredential) ([]SubscriptionInfo, error) {
	client, err := armsubscriptions.NewClient(cred, nil)
	if err != nil {
		return nil, fmt.Errorf("azure: subscriptions client: %w", err)
	}
	return listSubscriptions(ctx, client)
}

func listSubscriptions(ctx context.Context, l subsLister) ([]SubscriptionInfo, error) {
	var out []SubscriptionInfo
	pager := l.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("azure: listing subscriptions: %w", err)
		}
		out = append(out, subscriptionInfos(page.Value)...)
	}
	return out, nil
}

func subscriptionInfos(subs []*armsubscriptions.Subscription) []SubscriptionInfo {
	out := make([]SubscriptionInfo, 0, len(subs))
	for _, s := range subs {
		if s == nil {
			continue
		}
		info := SubscriptionInfo{}
		if s.SubscriptionID != nil {
			info.ID = *s.SubscriptionID
		}
		if s.DisplayName != nil {
			info.DisplayName = *s.DisplayName
		}
		if s.State != nil {
			info.State = string(*s.State)
		}
		out = append(out, info)
	}
	return out
}

// resourceQuerier is the slice of *armresourcegraph.Client that the query
// helper drives; tests inject a fake.
type resourceQuerier interface {
	Resources(ctx context.Context, query armresourcegraph.QueryRequest, opts *armresourcegraph.ClientResourcesOptions) (armresourcegraph.ClientResourcesResponse, error)
}

// QueryResourceGraph runs a KQL query across the given subscriptions and pages
// through every result via SkipToken — the fast cross-resource-group primitive
// azure.* resource collectors use instead of fanning out per-RG ARM calls. Rows
// are returned as map[string]any (ResultFormatObjectArray).
func QueryResourceGraph(ctx context.Context, cred azcore.TokenCredential, kql string, subscriptionIDs []string) ([]map[string]any, error) {
	client, err := armresourcegraph.NewClient(cred, nil)
	if err != nil {
		return nil, fmt.Errorf("azure: resource graph client: %w", err)
	}
	return queryResourceGraph(ctx, client, kql, subscriptionIDs)
}

func queryResourceGraph(ctx context.Context, q resourceQuerier, kql string, subscriptionIDs []string) ([]map[string]any, error) {
	subs := make([]*string, 0, len(subscriptionIDs))
	for _, id := range subscriptionIDs {
		subs = append(subs, to.Ptr(id))
	}
	var (
		rows      []map[string]any
		skipToken *string
	)
	for {
		resp, err := q.Resources(ctx, armresourcegraph.QueryRequest{
			Query:         to.Ptr(kql),
			Subscriptions: subs,
			Options: &armresourcegraph.QueryRequestOptions{
				ResultFormat: to.Ptr(armresourcegraph.ResultFormatObjectArray),
				Top:          to.Ptr[int32](1000),
				SkipToken:    skipToken,
			},
		}, nil)
		if err != nil {
			return nil, fmt.Errorf("azure: resource graph query: %w", err)
		}
		rows = append(rows, rowsFromData(resp.Data)...)
		// Empty and nil SkipToken both mean "no more pages".
		if resp.SkipToken == nil || *resp.SkipToken == "" {
			break
		}
		skipToken = resp.SkipToken
	}
	return rows, nil
}

// rowsFromData coerces a Resource Graph ObjectArray result (an []any of
// map[string]any rows) into typed rows, skipping anything malformed.
func rowsFromData(data any) []map[string]any {
	batch, ok := data.([]any)
	if !ok {
		return nil
	}
	out := make([]map[string]any, 0, len(batch))
	for _, item := range batch {
		if m, ok := item.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out
}
