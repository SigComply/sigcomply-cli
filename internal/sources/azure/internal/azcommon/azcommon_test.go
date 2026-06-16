package azcommon

import (
	"context"
	"errors"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resourcegraph/armresourcegraph"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armsubscriptions"
)

// --- ParseConfig ---------------------------------------------------------

func TestParseConfig(t *testing.T) {
	tests := []struct {
		name       string
		raw        map[string]any
		requireSub bool
		wantSub    string
		wantTenant string
		wantErr    bool
	}{
		{
			name:       "arm source with subscription and tenant",
			raw:        map[string]any{"subscription_id": "sub-1", "tenant_id": "ten-1"},
			requireSub: true,
			wantSub:    "sub-1",
			wantTenant: "ten-1",
		},
		{
			name:       "arm source missing subscription errors",
			raw:        map[string]any{"tenant_id": "ten-1"},
			requireSub: true,
			wantErr:    true,
		},
		{
			name:       "graph source needs no subscription",
			raw:        map[string]any{"tenant_id": "ten-1"},
			requireSub: false,
			wantTenant: "ten-1",
		},
		{
			name:       "values are trimmed",
			raw:        map[string]any{"subscription_id": "  sub-2  ", "tenant_id": " ten-2 "},
			requireSub: true,
			wantSub:    "sub-2",
			wantTenant: "ten-2",
		},
		{
			name:       "empty subscription string still errors when required",
			raw:        map[string]any{"subscription_id": "   "},
			requireSub: true,
			wantErr:    true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := ParseConfig(tc.raw, tc.requireSub)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("ParseConfig() expected error, got cfg=%+v", cfg)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseConfig() unexpected error: %v", err)
			}
			if cfg.SubscriptionID != tc.wantSub {
				t.Errorf("SubscriptionID = %q; want %q", cfg.SubscriptionID, tc.wantSub)
			}
			if cfg.TenantID != tc.wantTenant {
				t.Errorf("TenantID = %q; want %q", cfg.TenantID, tc.wantTenant)
			}
		})
	}
}

// --- NewCredential -------------------------------------------------------

func TestNewCredential(t *testing.T) {
	// DefaultAzureCredential constructs its chain lazily — no creds needed to
	// build it; a missing identity only surfaces at GetToken time.
	cred, err := NewCredential()
	if err != nil {
		t.Fatalf("NewCredential() error: %v", err)
	}
	if cred == nil {
		t.Fatal("NewCredential() returned nil credential")
	}
}

// --- VerifyCredential ----------------------------------------------------

type fakeCred struct{ err error }

func (f fakeCred) GetToken(context.Context, policy.TokenRequestOptions) (azcore.AccessToken, error) {
	if f.err != nil {
		return azcore.AccessToken{}, f.err
	}
	return azcore.AccessToken{Token: "tok", ExpiresOn: time.Now().Add(time.Hour)}, nil
}

func TestVerifyCredential(t *testing.T) {
	if err := VerifyCredential(context.Background(), fakeCred{}, ScopeARM); err != nil {
		t.Errorf("VerifyCredential(ok) = %v; want nil", err)
	}
	wantErr := errors.New("no identity")
	if err := VerifyCredential(context.Background(), fakeCred{err: wantErr}, ScopeGraph); !errors.Is(err, wantErr) {
		t.Errorf("VerifyCredential(err) = %v; want wrap of %v", err, wantErr)
	}
}

// --- ListSubscriptions ---------------------------------------------------

type fakeSubs struct {
	pages [][]*armsubscriptions.Subscription
	err   error
}

func (f *fakeSubs) NewListPager(*armsubscriptions.ClientListOptions) *runtime.Pager[armsubscriptions.ClientListResponse] {
	idx := 0
	return runtime.NewPager(runtime.PagingHandler[armsubscriptions.ClientListResponse]{
		More: func(armsubscriptions.ClientListResponse) bool { return idx < len(f.pages) },
		Fetcher: func(context.Context, *armsubscriptions.ClientListResponse) (armsubscriptions.ClientListResponse, error) {
			if f.err != nil {
				return armsubscriptions.ClientListResponse{}, f.err
			}
			if idx >= len(f.pages) {
				return armsubscriptions.ClientListResponse{}, nil
			}
			page := f.pages[idx]
			idx++
			return armsubscriptions.ClientListResponse{
				SubscriptionListResult: armsubscriptions.SubscriptionListResult{Value: page},
			}, nil
		},
	})
}

func sub(id, name string, state armsubscriptions.SubscriptionState) *armsubscriptions.Subscription {
	return &armsubscriptions.Subscription{
		SubscriptionID: to.Ptr(id),
		DisplayName:    to.Ptr(name),
		State:          to.Ptr(state),
	}
}

func TestListSubscriptions_PagesAndMaps(t *testing.T) {
	f := &fakeSubs{pages: [][]*armsubscriptions.Subscription{
		{sub("s1", "prod", armsubscriptions.SubscriptionStateEnabled)},
		{sub("s2", "dev", armsubscriptions.SubscriptionStateDisabled), nil}, // nil entry is skipped
	}}
	got, err := listSubscriptions(context.Background(), f)
	if err != nil {
		t.Fatalf("listSubscriptions() error: %v", err)
	}
	want := []SubscriptionInfo{
		{ID: "s1", DisplayName: "prod", State: string(armsubscriptions.SubscriptionStateEnabled)},
		{ID: "s2", DisplayName: "dev", State: string(armsubscriptions.SubscriptionStateDisabled)},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("listSubscriptions() = %+v; want %+v", got, want)
	}
}

func TestListSubscriptions_Empty(t *testing.T) {
	got, err := listSubscriptions(context.Background(), &fakeSubs{})
	if err != nil {
		t.Fatalf("listSubscriptions() error: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("listSubscriptions(empty) = %+v; want none", got)
	}
}

func TestListSubscriptions_Error(t *testing.T) {
	want := errors.New("403")
	_, err := listSubscriptions(context.Background(), &fakeSubs{err: want})
	if !errors.Is(err, want) {
		t.Errorf("listSubscriptions() err = %v; want wrap of %v", err, want)
	}
}

func TestSubscriptionInfos_NilFields(t *testing.T) {
	got := subscriptionInfos([]*armsubscriptions.Subscription{
		{}, // all-nil pointers → zero-value info, not a panic
		nil,
	})
	want := []SubscriptionInfo{{}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("subscriptionInfos() = %+v; want %+v", got, want)
	}
}

// --- QueryResourceGraph --------------------------------------------------

type fakeRG struct {
	pages []armresourcegraph.ClientResourcesResponse
	err   error
	calls int
}

func (f *fakeRG) Resources(context.Context, armresourcegraph.QueryRequest, *armresourcegraph.ClientResourcesOptions) (armresourcegraph.ClientResourcesResponse, error) {
	if f.err != nil {
		return armresourcegraph.ClientResourcesResponse{}, f.err
	}
	resp := f.pages[f.calls]
	f.calls++
	return resp, nil
}

func rgPage(skip *string, rows ...map[string]any) armresourcegraph.ClientResourcesResponse {
	data := make([]any, len(rows))
	for i, r := range rows {
		data[i] = r
	}
	return armresourcegraph.ClientResourcesResponse{
		QueryResponse: armresourcegraph.QueryResponse{Data: data, SkipToken: skip},
	}
}

func TestQueryResourceGraph_PagesViaSkipToken(t *testing.T) {
	f := &fakeRG{pages: []armresourcegraph.ClientResourcesResponse{
		rgPage(to.Ptr("more"), map[string]any{"name": "vm1"}),
		rgPage(nil, map[string]any{"name": "vm2"}, map[string]any{"name": "vm3"}),
	}}
	got, err := queryResourceGraph(context.Background(), f, "Resources | project name", []string{"s1", "s2"})
	if err != nil {
		t.Fatalf("queryResourceGraph() error: %v", err)
	}
	want := []map[string]any{{"name": "vm1"}, {"name": "vm2"}, {"name": "vm3"}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("queryResourceGraph() = %+v; want %+v", got, want)
	}
	if f.calls != 2 {
		t.Errorf("Resources called %d times; want 2 (one per page)", f.calls)
	}
}

func TestQueryResourceGraph_EmptySkipTokenStops(t *testing.T) {
	// An empty-string SkipToken must terminate paging just like nil.
	f := &fakeRG{pages: []armresourcegraph.ClientResourcesResponse{
		rgPage(to.Ptr(""), map[string]any{"name": "only"}),
	}}
	got, err := queryResourceGraph(context.Background(), f, "Resources", nil)
	if err != nil {
		t.Fatalf("queryResourceGraph() error: %v", err)
	}
	if len(got) != 1 || f.calls != 1 {
		t.Errorf("got %+v calls=%d; want 1 row, 1 call", got, f.calls)
	}
}

func TestQueryResourceGraph_Error(t *testing.T) {
	want := errors.New("bad kql")
	_, err := queryResourceGraph(context.Background(), &fakeRG{err: want}, "x", nil)
	if !errors.Is(err, want) {
		t.Errorf("queryResourceGraph() err = %v; want wrap of %v", err, want)
	}
}

func TestRowsFromData(t *testing.T) {
	tests := []struct {
		name string
		data any
		want []map[string]any
	}{
		{name: "nil", data: nil, want: nil},
		{name: "not a slice (column/row table shape)", data: map[string]any{"rows": 1}, want: nil},
		{
			name: "object array with a malformed element skipped",
			data: []any{map[string]any{"a": 1}, "junk", map[string]any{"b": 2}},
			want: []map[string]any{{"a": 1}, {"b": 2}},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := rowsFromData(tc.data)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("rowsFromData() = %+v; want %+v", got, tc.want)
			}
		})
	}
}

// --- Live smoke test (skips without credentials) -------------------------

// TestLive_CredentialAndSubscriptions exercises the real DefaultAzureCredential
// chain end to end: mint an ARM token, then list subscriptions. It skips unless
// SIGCOMPLY_AZURE_LIVE is set (and a working credential is present), so CI and
// local runs without Azure creds stay green — the same "skip without creds"
// contract the cloud collectors follow.
func TestLive_CredentialAndSubscriptions(t *testing.T) {
	if os.Getenv("SIGCOMPLY_AZURE_LIVE") == "" {
		t.Skip("SIGCOMPLY_AZURE_LIVE not set; skipping live Azure credential smoke test")
	}
	ctx := context.Background()
	cred, err := NewCredential()
	if err != nil {
		t.Fatalf("NewCredential() error: %v", err)
	}
	if err := VerifyCredential(ctx, cred, ScopeARM); err != nil {
		t.Fatalf("VerifyCredential(ARM) error: %v", err)
	}
	subs, err := ListSubscriptions(ctx, cred)
	if err != nil {
		t.Fatalf("ListSubscriptions() error: %v", err)
	}
	t.Logf("reached %d subscription(s)", len(subs))
}
