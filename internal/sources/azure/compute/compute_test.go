package compute

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/cloud"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	armcompute "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v7"
	armnetwork "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v9"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/sources"
)

var fixedNow = time.Date(2026, 6, 17, 12, 0, 0, 0, time.UTC)

func mustUnmarshal(t *testing.T, raw json.RawMessage, dst any) {
	t.Helper()
	if err := json.Unmarshal(raw, dst); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
}

// fakeAPI records calls and returns staged VMs/NICs. NICs are keyed by name.
type fakeAPI struct {
	vms      []*armcompute.VirtualMachine
	nics     map[string]*armnetwork.Interface
	vmErr    error
	nicErr   error
	vmCalls  int
	nicCalls int
}

func (f *fakeAPI) ListVirtualMachines(context.Context) ([]*armcompute.VirtualMachine, error) {
	f.vmCalls++
	if f.vmErr != nil {
		return nil, f.vmErr
	}
	return f.vms, nil
}

func (f *fakeAPI) GetNetworkInterface(_ context.Context, _, name string) (*armnetwork.Interface, error) {
	f.nicCalls++
	if f.nicErr != nil {
		return nil, f.nicErr
	}
	return f.nics[name], nil
}

func req() core.SlotRequest {
	return core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}}
}

func vmID(name string) *string {
	return to.Ptr("/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/" + name)
}

func nicID(name string) *string {
	return to.Ptr("/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.Network/networkInterfaces/" + name)
}

func runningStatus() *armcompute.VirtualMachineInstanceView {
	return &armcompute.VirtualMachineInstanceView{
		Statuses: []*armcompute.InstanceViewStatus{
			{Code: to.Ptr("ProvisioningState/succeeded")},
			{Code: to.Ptr("PowerState/running")},
		},
	}
}

// nicWithPublicIP builds a NIC whose single IP config references a public IP.
func nicWithPublicIP() *armnetwork.Interface {
	return &armnetwork.Interface{Properties: &armnetwork.InterfacePropertiesFormat{
		IPConfigurations: []*armnetwork.InterfaceIPConfiguration{
			{Properties: &armnetwork.InterfaceIPConfigurationPropertiesFormat{
				PublicIPAddress: &armnetwork.PublicIPAddress{ID: to.Ptr("/subscriptions/sub-1/.../publicIPAddresses/pip")},
			}},
		},
	}}
}

// nicPrivateOnly builds a NIC with only a private IP (no public reference).
func nicPrivateOnly() *armnetwork.Interface {
	return &armnetwork.Interface{Properties: &armnetwork.InterfacePropertiesFormat{
		IPConfigurations: []*armnetwork.InterfaceIPConfiguration{
			{Properties: &armnetwork.InterfaceIPConfigurationPropertiesFormat{PrivateIPAddress: to.Ptr("10.0.0.4")}},
		},
	}}
}

func TestIDAndEmits(t *testing.T) {
	p := New(Options{})
	if got := p.ID(); got != "azure.compute" {
		t.Errorf("ID() = %q, want azure.compute", got)
	}
	got := p.Emits()
	if len(got) != 1 || got[0] != EvidenceTypeID {
		t.Errorf("Emits() = %v, want [compute_instance]", got)
	}
}

func TestCollect_RejectsNonEmittedType(t *testing.T) {
	p := New(Options{API: &fakeAPI{}})
	_, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{"object_storage_bucket"}})
	if err == nil || !strings.Contains(err.Error(), "compute_instance") {
		t.Fatalf("expected rejection error, got %v", err)
	}
}

func TestCollect_MapsSortsAndFullPayload(t *testing.T) {
	// Two VMs (out of order to prove sort): a public, running, CMEK Linux VM and
	// a stopped, private, platform-managed Windows VM with encryption-at-host.
	desID := "/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.Compute/diskEncryptionSets/des1"
	f := &fakeAPI{
		vms: []*armcompute.VirtualMachine{
			{
				ID:       vmID("z-web"),
				Name:     to.Ptr("z-web"),
				Location: to.Ptr("eastus"),
				Properties: &armcompute.VirtualMachineProperties{
					InstanceView:    runningStatus(),
					HardwareProfile: &armcompute.HardwareProfile{VMSize: to.Ptr(armcompute.VirtualMachineSizeTypesStandardD2SV3)},
					StorageProfile: &armcompute.StorageProfile{OSDisk: &armcompute.OSDisk{
						OSType:      to.Ptr(armcompute.OperatingSystemTypesLinux),
						ManagedDisk: &armcompute.ManagedDiskParameters{DiskEncryptionSet: &armcompute.DiskEncryptionSetParameters{ID: to.Ptr(desID)}},
					}},
					NetworkProfile: &armcompute.NetworkProfile{NetworkInterfaces: []*armcompute.NetworkInterfaceReference{
						{ID: nicID("web-nic")},
					}},
				},
			},
			{
				ID:       vmID("a-db"),
				Name:     to.Ptr("a-db"),
				Location: to.Ptr("eastus"),
				Properties: &armcompute.VirtualMachineProperties{
					InstanceView: &armcompute.VirtualMachineInstanceView{Statuses: []*armcompute.InstanceViewStatus{{Code: to.Ptr("PowerState/deallocated")}}},
					StorageProfile: &armcompute.StorageProfile{OSDisk: &armcompute.OSDisk{
						OSType:      to.Ptr(armcompute.OperatingSystemTypesWindows),
						ManagedDisk: &armcompute.ManagedDiskParameters{}, // platform-managed (no DES)
					}},
					SecurityProfile: &armcompute.SecurityProfile{EncryptionAtHost: to.Ptr(true)},
					NetworkProfile:  &armcompute.NetworkProfile{NetworkInterfaces: []*armcompute.NetworkInterfaceReference{{ID: nicID("db-nic")}}},
				},
			},
		},
		nics: map[string]*armnetwork.Interface{
			"web-nic": nicWithPublicIP(),
			"db-nic":  nicPrivateOnly(),
		},
	}
	p := New(Options{API: f, SubscriptionID: "sub-1", Now: func() time.Time { return fixedNow }})

	recs, err := p.Collect(context.Background(), req())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(recs) != 2 {
		t.Fatalf("got %d records, want 2", len(recs))
	}
	// Sorted by ID (ARM id): a-db before z-web.
	if recs[0].ID != *vmID("a-db") || recs[1].ID != *vmID("z-web") {
		t.Fatalf("sort order wrong: %s, %s", recs[0].ID, recs[1].ID)
	}
	for _, r := range recs {
		if r.Type != EvidenceTypeID || r.SourceID != SourceID || !r.CollectedAt.Equal(fixedNow) {
			t.Errorf("record %s: Type/SourceID/CollectedAt = %s/%s/%v", r.ID, r.Type, r.SourceID, r.CollectedAt)
		}
		if r.Scope == nil || r.Scope.Account != "sub-1" {
			t.Errorf("record %s: scope = %+v", r.ID, r.Scope)
		}
		if r.IdentityKey != "" {
			t.Errorf("record %s: unexpected IdentityKey %q", r.ID, r.IdentityKey)
		}
	}

	var db instancePayload
	mustUnmarshal(t, recs[0].Payload, &db)
	wantDB := instancePayload{
		ID:                  *vmID("a-db"),
		Name:                "a-db",
		Provider:            "azure",
		Region:              "eastus",
		IsRunning:           false,
		HasPublicIP:         false,
		RootVolumeEncrypted: true,
		PowerState:          "deallocated",
		OSType:              "Windows",
		CMEKEnabled:         false,
		EncryptionAtHost:    true,
		ResourceGroup:       "rg",
	}
	if !reflect.DeepEqual(db, wantDB) {
		t.Errorf("db payload mismatch:\n got  %+v\n want %+v", db, wantDB)
	}

	var web instancePayload
	mustUnmarshal(t, recs[1].Payload, &web)
	wantWeb := instancePayload{
		ID:                  *vmID("z-web"),
		Name:                "z-web",
		Provider:            "azure",
		Region:              "eastus",
		IsRunning:           true,
		HasPublicIP:         true,
		RootVolumeEncrypted: true,
		PowerState:          "running",
		VMSize:              "Standard_D2s_v3",
		OSType:              "Linux",
		CMEKEnabled:         true,
		EncryptionAtHost:    false,
		KMSKeyID:            desID,
		ResourceGroup:       "rg",
	}
	if !reflect.DeepEqual(web, wantWeb) {
		t.Errorf("web payload mismatch:\n got  %+v\n want %+v", web, wantWeb)
	}

	// monitoring_enabled must be omitted entirely (is_set-guarded policies scope
	// Azure out as a coverage gap).
	if strings.Contains(string(recs[0].Payload), "monitoring_enabled") {
		t.Errorf("monitoring_enabled should be omitted, payload = %s", recs[0].Payload)
	}
}

func TestCollect_MultipleNICs_AnyPublicWins(t *testing.T) {
	f := &fakeAPI{
		vms: []*armcompute.VirtualMachine{{
			ID:   vmID("vm"),
			Name: to.Ptr("vm"),
			Properties: &armcompute.VirtualMachineProperties{
				StorageProfile: &armcompute.StorageProfile{OSDisk: &armcompute.OSDisk{}},
				NetworkProfile: &armcompute.NetworkProfile{NetworkInterfaces: []*armcompute.NetworkInterfaceReference{
					{ID: nicID("private")},
					{ID: nicID("public")},
				}},
			},
		}},
		nics: map[string]*armnetwork.Interface{
			"private": nicPrivateOnly(),
			"public":  nicWithPublicIP(),
		},
	}
	recs, err := New(Options{API: f}).Collect(context.Background(), req())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	var got instancePayload
	mustUnmarshal(t, recs[0].Payload, &got)
	if !got.HasPublicIP {
		t.Errorf("a VM with any public-IP NIC should be has_public_ip=true, got %+v", got)
	}
}

func TestCollect_NoNetworkProfile_NoNICCalls(t *testing.T) {
	f := &fakeAPI{vms: []*armcompute.VirtualMachine{{
		ID:         vmID("vm"),
		Name:       to.Ptr("vm"),
		Properties: &armcompute.VirtualMachineProperties{StorageProfile: &armcompute.StorageProfile{OSDisk: &armcompute.OSDisk{}}},
	}}}
	recs, err := New(Options{API: f}).Collect(context.Background(), req())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	var got instancePayload
	mustUnmarshal(t, recs[0].Payload, &got)
	if got.HasPublicIP {
		t.Errorf("no network profile → has_public_ip should be false, got %+v", got)
	}
	if f.nicCalls != 0 {
		t.Errorf("no NIC calls expected, got %d", f.nicCalls)
	}
}

func TestCollect_NilEntriesSkipped(t *testing.T) {
	f := &fakeAPI{vms: []*armcompute.VirtualMachine{
		nil,
		{ID: vmID("ok"), Name: to.Ptr("ok"), Properties: &armcompute.VirtualMachineProperties{StorageProfile: &armcompute.StorageProfile{OSDisk: &armcompute.OSDisk{}}}},
	}}
	recs, err := New(Options{API: f}).Collect(context.Background(), req())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(recs) != 1 {
		t.Fatalf("expected 1 record (nil VM skipped), got %d", len(recs))
	}
}

func TestCollect_ErrorPropagation(t *testing.T) {
	t.Run("vm-list", func(t *testing.T) {
		_, err := New(Options{API: &fakeAPI{vmErr: errors.New("vm boom")}}).Collect(context.Background(), req())
		if err == nil || !strings.Contains(err.Error(), "vm boom") {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("nic-get", func(t *testing.T) {
		f := &fakeAPI{
			vms: []*armcompute.VirtualMachine{{ID: vmID("vm"), Name: to.Ptr("vm"), Properties: &armcompute.VirtualMachineProperties{
				NetworkProfile: &armcompute.NetworkProfile{NetworkInterfaces: []*armcompute.NetworkInterfaceReference{{ID: nicID("n")}}},
			}}},
			nicErr: errors.New("nic boom"),
		}
		_, err := New(Options{API: f}).Collect(context.Background(), req())
		if err == nil || !strings.Contains(err.Error(), "nic boom") {
			t.Fatalf("nic error should surface (not fabricate has_public_ip), got %v", err)
		}
	})
}

func TestCollect_BadNICResourceGroupID(t *testing.T) {
	f := &fakeAPI{vms: []*armcompute.VirtualMachine{{ID: vmID("vm"), Name: to.Ptr("vm"), Properties: &armcompute.VirtualMachineProperties{
		NetworkProfile: &armcompute.NetworkProfile{NetworkInterfaces: []*armcompute.NetworkInterfaceReference{{ID: to.Ptr("/subscriptions/s/providers/x")}}},
	}}}}
	_, err := New(Options{API: f}).Collect(context.Background(), req())
	if err == nil || !strings.Contains(err.Error(), "resourceGroups") {
		t.Fatalf("expected resource-group parse error, got %v", err)
	}
}

func TestCollect_KISSNoDRY_RefetchesEachCollect(t *testing.T) {
	f := &fakeAPI{
		vms: []*armcompute.VirtualMachine{{ID: vmID("vm"), Name: to.Ptr("vm"), Properties: &armcompute.VirtualMachineProperties{
			StorageProfile: &armcompute.StorageProfile{OSDisk: &armcompute.OSDisk{}},
			NetworkProfile: &armcompute.NetworkProfile{NetworkInterfaces: []*armcompute.NetworkInterfaceReference{{ID: nicID("n")}}},
		}}},
		nics: map[string]*armnetwork.Interface{"n": nicPrivateOnly()},
	}
	p := New(Options{API: f})
	for i := 0; i < 3; i++ {
		if _, err := p.Collect(context.Background(), req()); err != nil {
			t.Fatalf("Collect %d: %v", i, err)
		}
	}
	if f.vmCalls != 3 || f.nicCalls != 3 {
		t.Errorf("expected 3 vm + 3 nic calls, got %d + %d", f.vmCalls, f.nicCalls)
	}
}

func TestPowerState_Table(t *testing.T) {
	mk := func(codes ...string) *armcompute.VirtualMachine {
		sts := make([]*armcompute.InstanceViewStatus, 0, len(codes))
		for _, c := range codes {
			sts = append(sts, &armcompute.InstanceViewStatus{Code: to.Ptr(c)})
		}
		return &armcompute.VirtualMachine{Properties: &armcompute.VirtualMachineProperties{InstanceView: &armcompute.VirtualMachineInstanceView{Statuses: sts}}}
	}
	cases := []struct {
		name string
		vm   *armcompute.VirtualMachine
		want string
	}{
		{"running", mk("ProvisioningState/succeeded", "PowerState/running"), "running"},
		{"deallocated", mk("PowerState/deallocated"), "deallocated"},
		{"stopped", mk("PowerState/stopped"), "stopped"},
		{"no-power-status", mk("ProvisioningState/succeeded"), ""},
		{"no-instance-view", &armcompute.VirtualMachine{Properties: &armcompute.VirtualMachineProperties{}}, ""},
		{"nil-properties", &armcompute.VirtualMachine{}, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := powerState(c.vm); got != c.want {
				t.Errorf("powerState = %q, want %q", got, c.want)
			}
		})
	}
}

func TestNICHasPublicIP_NilSafe(t *testing.T) {
	if nicHasPublicIP(nil) || nicHasPublicIP(&armnetwork.Interface{}) {
		t.Error("nil-safe nicHasPublicIP should be false")
	}
	if nicHasPublicIP(nicPrivateOnly()) {
		t.Error("private-only NIC should be false")
	}
	if !nicHasPublicIP(nicWithPublicIP()) {
		t.Error("NIC with public IP reference should be true")
	}
}

func TestResourceGroupFromID_Table(t *testing.T) {
	cases := []struct {
		id      string
		want    string
		wantErr bool
	}{
		{"/subscriptions/s/resourceGroups/my-rg/providers/Microsoft.Compute/virtualMachines/vm", "my-rg", false},
		{"/subscriptions/s/resourcegroups/lower/providers/x", "lower", false},
		{"/subscriptions/s/providers/x", "", true},
	}
	for _, c := range cases {
		got, err := resourceGroupFromID(c.id)
		if (err != nil) != c.wantErr || got != c.want {
			t.Errorf("resourceGroupFromID(%q) = (%q,%v), want (%q,err=%v)", c.id, got, err, c.want, c.wantErr)
		}
	}
}

func TestNameFromID_Table(t *testing.T) {
	cases := []struct{ in, want string }{
		{"/subscriptions/s/resourceGroups/rg/providers/Microsoft.Network/networkInterfaces/nic1", "nic1"},
		{"bare", "bare"},
	}
	for _, c := range cases {
		if got := nameFromID(c.in); got != c.want {
			t.Errorf("nameFromID(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestBuild_RequiresSubscriptionID(t *testing.T) {
	_, err := sources.Build(context.Background(), SourceID, sources.Env{Config: map[string]any{}})
	if err == nil || !strings.Contains(err.Error(), "subscription_id") {
		t.Fatalf("expected subscription_id required error, got %v", err)
	}
}

// --- real adapter (httptest) ---

type fakeCred struct{}

func (fakeCred) GetToken(context.Context, policy.TokenRequestOptions) (azcore.AccessToken, error) {
	return azcore.AccessToken{Token: "fake", ExpiresOn: time.Now().Add(time.Hour)}, nil
}

func mustMarshal(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

func realComputePointedAt(t *testing.T, srv *httptest.Server) *realCompute {
	t.Helper()
	opts := &arm.ClientOptions{ClientOptions: azcore.ClientOptions{
		Cloud: cloud.Configuration{Services: map[cloud.ServiceName]cloud.ServiceConfiguration{
			cloud.ResourceManager: {Endpoint: srv.URL, Audience: "https://management.azure.com"},
		}},
		Transport: srv.Client(),
	}}
	rc, err := newRealCompute("sub-1", fakeCred{}, opts)
	if err != nil {
		t.Fatalf("newRealCompute: %v", err)
	}
	return rc
}

func TestRealCompute_ListAndGet_HappyPath(t *testing.T) {
	vmBody := mustMarshal(t, armcompute.VirtualMachineListResult{Value: []*armcompute.VirtualMachine{
		{Name: to.Ptr("vm1"), ID: vmID("vm1")},
	}})
	nicBody := mustMarshal(t, nicWithPublicIP())
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.Contains(r.URL.Path, "/virtualMachines"):
			_, _ = w.Write(vmBody) //nolint:errcheck // test handler
		case strings.Contains(r.URL.Path, "/networkInterfaces/"):
			_, _ = w.Write(nicBody) //nolint:errcheck // test handler
		default:
			t.Errorf("unexpected path: %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	rc := realComputePointedAt(t, srv)
	t.Run("vms", func(t *testing.T) {
		vms, err := rc.ListVirtualMachines(context.Background())
		if err != nil || len(vms) != 1 || deref(vms[0].Name) != "vm1" {
			t.Fatalf("ListVirtualMachines = %+v, err %v", vms, err)
		}
	})
	t.Run("nic", func(t *testing.T) {
		nic, err := rc.GetNetworkInterface(context.Background(), "rg", "web-nic")
		if err != nil || !nicHasPublicIP(nic) {
			t.Fatalf("GetNetworkInterface = %+v, err %v", nic, err)
		}
	})
}

func TestRealCompute_ListError(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":{"code":"AuthorizationFailed"}}`)) //nolint:errcheck // test handler
	}))
	defer srv.Close()

	rc := realComputePointedAt(t, srv)
	if _, err := rc.ListVirtualMachines(context.Background()); err == nil {
		t.Fatal("expected error on 403, got nil")
	}
}
