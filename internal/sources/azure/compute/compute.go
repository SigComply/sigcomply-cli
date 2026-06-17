// Package compute implements the azure.compute source plugin: it lists Azure
// Virtual Machines in a subscription and emits one cross-vendor
// compute_instance record per VM, so network-exposure, encryption, and
// monitoring policies evaluate against Azure exactly as they do against AWS EC2
// and GCP Compute Engine — zero policy changes (Invariant #4).
//
// Field mapping:
//
//   - is_running — derived from the VM power state. The list pager is asked for
//     StatusOnly, which populates each VM's InstanceView (and therefore its
//     "PowerState/<state>" status) in a single subscription-wide call — no
//     per-VM InstanceView round-trip. is_running is true iff that state is
//     "running".
//   - root_volume_encrypted — a platform CONSTANT true. Azure managed disks are
//     encrypted at rest unconditionally (Storage Service Encryption, cannot be
//     disabled); the only real toggle is platform-managed vs customer-managed
//     keys, which rides in the auditable cmek_enabled / kms_key_id extras
//     (mirrors how azure.storage treats always-on SSE, and gcp.compute treats
//     always-on persistent-disk encryption).
//   - has_public_ip — resolved per VM: each referenced NIC is fetched and its IP
//     configurations are checked for the PRESENCE of a public-IP reference (the
//     public-IP resource itself is not resolved — presence is sufficient and
//     cheaper). A VM with no NIC exposing a public IP reads false.
//   - monitoring_enabled — deliberately OMITTED (left nil). Azure exposes no
//     per-VM "detailed monitoring" signal comparable to AWS detailed monitoring
//     (Azure Monitor / the agent is not queryable here), so emitting a value
//     would be fabricated. The monitoring policies guard this field with is_set
//     and scope Azure VMs out as a documented coverage gap, matching gcp.compute.
//
// A list/get failure (e.g. a missing-permission 403) is surfaced as an error
// (tagging only the azure.compute-bound policies `error`) rather than returning
// a partial or insecure-default result — never fabricate has_public_ip=false.
//
// Test injection: the API interface is the single seam and returns raw SDK
// types so 100% of the vendor→canonical mapping stays in Collect under fakeAPI
// unit tests; the real adapter (realCompute) wraps the armcompute VM client and
// the armnetwork interface client.
package compute

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	armcompute "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v7"
	armnetwork "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v9"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/sources/azure/internal/azcommon"
)

// EvidenceTypeID is the single evidence type this plugin emits.
const EvidenceTypeID = "compute_instance"

// SourceID is the registered ID for the azure.compute plugin instance.
const SourceID = "azure.compute"

// powerStatePrefix is the InstanceView status-code prefix that carries the VM
// power state, e.g. "PowerState/running".
const powerStatePrefix = "PowerState/"

// API is the subset of the Azure compute + network management plane this plugin
// uses. It returns raw SDK types so the vendor→canonical mapping is exercised by
// fakeAPI unit tests; the real adapter (realCompute) wraps the SDK clients.
type API interface {
	// ListVirtualMachines returns every VM in the subscription, each carrying
	// its InstanceView (power state) via the StatusOnly list option.
	ListVirtualMachines(ctx context.Context) ([]*armcompute.VirtualMachine, error)
	// GetNetworkInterface fetches a single NIC by resource group + name so its
	// IP configurations can be inspected for a public-IP reference.
	GetNetworkInterface(ctx context.Context, resourceGroup, name string) (*armnetwork.Interface, error)
}

// Plugin is the in-process azure.compute source.
type Plugin struct {
	api            API
	subscriptionID string
	now            func() time.Time
}

// Options is the constructor input.
type Options struct {
	API            API
	SubscriptionID string
	// Now is injected so tests can produce deterministic CollectedAt values.
	// Production callers leave it nil → time.Now().UTC().
	Now func() time.Time
}

// New constructs a Plugin around an explicit API implementation. Callers using
// the real Azure SDK should use NewFromAzure.
func New(opts Options) *Plugin {
	now := opts.Now
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	return &Plugin{
		api:            opts.API,
		subscriptionID: opts.SubscriptionID,
		now:            now,
	}
}

// NewFromAzure constructs a Plugin backed by the real armcompute/armnetwork SDK
// using the given credential (a DefaultAzureCredential) scoped to
// cfg.SubscriptionID.
func NewFromAzure(cred azcore.TokenCredential, cfg azcommon.Config) (*Plugin, error) {
	adapter, err := newRealCompute(cfg.SubscriptionID, cred, nil)
	if err != nil {
		return nil, err
	}
	return New(Options{API: adapter, SubscriptionID: cfg.SubscriptionID}), nil
}

// ID returns the registered plugin ID.
func (*Plugin) ID() string { return SourceID }

// Emits returns the evidence types this plugin can produce.
func (*Plugin) Emits() []string { return []string{EvidenceTypeID} }

// Init is a no-op — configuration is fixed at New.
func (*Plugin) Init(context.Context, map[string]any) error { return nil }

// instancePayload is the cross-vendor compute_instance shape with Azure
// enrichment fields in the additionalProperties tail. The schema-required fields
// (id, name, has_public_ip, is_running, root_volume_encrypted) are always
// present.
type instancePayload struct {
	ID                  string `json:"id"`
	Name                string `json:"name"`
	Provider            string `json:"provider"`
	Region              string `json:"region,omitempty"`
	IsRunning           bool   `json:"is_running"`
	HasPublicIP         bool   `json:"has_public_ip"`
	RootVolumeEncrypted bool   `json:"root_volume_encrypted"`
	// MonitoringEnabled is a pointer so it can be OMITTED for Azure: ARM exposes
	// no per-VM detailed-monitoring signal comparable to AWS detailed
	// monitoring, so a hardcoded value would be fabricated. The monitoring
	// policies guard with is_set and scope Azure VMs out as a documented
	// coverage gap (same pattern as gcp.compute). Optional in the schema.
	MonitoringEnabled *bool `json:"monitoring_enabled,omitempty"`

	// Auditable Azure extras (additionalProperties).
	PowerState       string `json:"power_state,omitempty"`
	VMSize           string `json:"vm_size,omitempty"`
	OSType           string `json:"os_type,omitempty"`
	CMEKEnabled      bool   `json:"cmek_enabled"`
	EncryptionAtHost bool   `json:"encryption_at_host"`
	KMSKeyID         string `json:"kms_key_id,omitempty"`
	ResourceGroup    string `json:"resource_group,omitempty"`
}

// Collect lists VMs in the subscription and emits one compute_instance record
// per VM, sorted by ID (ARM resource id) so envelope bytes are stable across
// runs against stable state.
func (p *Plugin) Collect(ctx context.Context, req core.SlotRequest) ([]core.EvidenceRecord, error) {
	if !req.Accepts(EvidenceTypeID) {
		return nil, fmt.Errorf("azure.compute: slot AcceptedTypes %v does not include %q", req.AcceptedTypes, EvidenceTypeID)
	}
	vms, err := p.api.ListVirtualMachines(ctx)
	if err != nil {
		return nil, fmt.Errorf("azure.compute: list virtual machines: %w", err)
	}
	var scope *core.RecordScope
	if p.subscriptionID != "" {
		scope = &core.RecordScope{Account: p.subscriptionID}
	}
	now := p.now()

	records := make([]core.EvidenceRecord, 0, len(vms))
	for _, vm := range vms {
		if vm == nil {
			continue
		}
		hasPublic, err := p.vmHasPublicIP(ctx, vm)
		if err != nil {
			return nil, err
		}
		state := powerState(vm)
		keyID := cmekKeyID(vm)
		payload := instancePayload{
			ID:                  deref(vm.ID),
			Name:                deref(vm.Name),
			Provider:            "azure",
			Region:              deref(vm.Location),
			IsRunning:           state == "running",
			HasPublicIP:         hasPublic,
			RootVolumeEncrypted: true, // Azure managed disks are always encrypted at rest.
			// MonitoringEnabled deliberately left nil — see field doc.
			PowerState:       state,
			VMSize:           vmSize(vm),
			OSType:           osType(vm),
			CMEKEnabled:      keyID != "",
			EncryptionAtHost: encryptionAtHost(vm),
			KMSKeyID:         keyID,
			ResourceGroup:    resourceGroupOrEmpty(deref(vm.ID)),
		}
		body, err := json.Marshal(payload)
		if err != nil {
			return nil, fmt.Errorf("azure.compute: marshal instance payload for %q: %w", payload.ID, err)
		}
		records = append(records, core.EvidenceRecord{
			Type:        EvidenceTypeID,
			ID:          payload.ID,
			Payload:     body,
			SourceID:    SourceID,
			CollectedAt: now,
			Scope:       scope,
		})
	}
	sort.Slice(records, func(i, j int) bool { return records[i].ID < records[j].ID })
	return records, nil
}

// vmHasPublicIP reports whether any NIC attached to the VM has an IP
// configuration that references a public IP address. It fetches each NIC and
// short-circuits on the first public-IP reference found. A NIC fetch error is
// surfaced (never fabricated as "no public IP").
func (p *Plugin) vmHasPublicIP(ctx context.Context, vm *armcompute.VirtualMachine) (bool, error) {
	if vm.Properties == nil || vm.Properties.NetworkProfile == nil {
		return false, nil
	}
	for _, ref := range vm.Properties.NetworkProfile.NetworkInterfaces {
		if ref == nil {
			continue
		}
		nicID := deref(ref.ID)
		if nicID == "" {
			continue
		}
		rg, err := resourceGroupFromID(nicID)
		if err != nil {
			return false, fmt.Errorf("azure.compute: NIC id %q: %w", nicID, err)
		}
		nic, err := p.api.GetNetworkInterface(ctx, rg, nameFromID(nicID))
		if err != nil {
			return false, fmt.Errorf("azure.compute: get network interface %q: %w", nameFromID(nicID), err)
		}
		if nicHasPublicIP(nic) {
			return true, nil
		}
	}
	return false, nil
}

// --- pure mapping helpers (unit-tested via table tests) ---

// nicHasPublicIP reports whether any IP configuration on the NIC references a
// public IP address (presence of the reference is sufficient — the public-IP
// object itself need not be resolved).
func nicHasPublicIP(nic *armnetwork.Interface) bool {
	if nic == nil || nic.Properties == nil {
		return false
	}
	for _, cfg := range nic.Properties.IPConfigurations {
		if cfg != nil && cfg.Properties != nil && cfg.Properties.PublicIPAddress != nil {
			return true
		}
	}
	return false
}

// powerState returns the VM's power state (the suffix after "PowerState/" in the
// InstanceView statuses), e.g. "running", "deallocated", or "" when unknown.
func powerState(vm *armcompute.VirtualMachine) string {
	if vm.Properties == nil || vm.Properties.InstanceView == nil {
		return ""
	}
	for _, st := range vm.Properties.InstanceView.Statuses {
		if st == nil {
			continue
		}
		if code := deref(st.Code); strings.HasPrefix(code, powerStatePrefix) {
			return strings.TrimPrefix(code, powerStatePrefix)
		}
	}
	return ""
}

func vmSize(vm *armcompute.VirtualMachine) string {
	if vm.Properties == nil || vm.Properties.HardwareProfile == nil || vm.Properties.HardwareProfile.VMSize == nil {
		return ""
	}
	return string(*vm.Properties.HardwareProfile.VMSize)
}

func osType(vm *armcompute.VirtualMachine) string {
	if vm.Properties == nil || vm.Properties.StorageProfile == nil || vm.Properties.StorageProfile.OSDisk == nil || vm.Properties.StorageProfile.OSDisk.OSType == nil {
		return ""
	}
	return string(*vm.Properties.StorageProfile.OSDisk.OSType)
}

// cmekKeyID returns the customer-managed disk-encryption-set key id on the OS
// disk, or "" when the disk uses platform-managed keys (the default).
func cmekKeyID(vm *armcompute.VirtualMachine) string {
	if vm.Properties == nil || vm.Properties.StorageProfile == nil {
		return ""
	}
	osd := vm.Properties.StorageProfile.OSDisk
	if osd == nil || osd.ManagedDisk == nil || osd.ManagedDisk.DiskEncryptionSet == nil {
		return ""
	}
	return deref(osd.ManagedDisk.DiskEncryptionSet.ID)
}

func encryptionAtHost(vm *armcompute.VirtualMachine) bool {
	if vm.Properties == nil || vm.Properties.SecurityProfile == nil {
		return false
	}
	return derefBool(vm.Properties.SecurityProfile.EncryptionAtHost)
}

// resourceGroupFromID extracts the resource group from an ARM resource id,
// case-insensitively (ARM sometimes returns "resourcegroups").
func resourceGroupFromID(id string) (string, error) {
	parts := strings.Split(id, "/")
	for i := 0; i+1 < len(parts); i++ {
		if strings.EqualFold(parts[i], "resourceGroups") {
			if rg := parts[i+1]; rg != "" {
				return rg, nil
			}
		}
	}
	return "", fmt.Errorf("no resourceGroups segment in id %q", id)
}

// resourceGroupOrEmpty is resourceGroupFromID for payload context, returning ""
// (rather than an error) for a malformed id since the field is informational.
func resourceGroupOrEmpty(id string) string {
	rg, err := resourceGroupFromID(id)
	if err != nil {
		return ""
	}
	return rg
}

// nameFromID returns the last path segment of an ARM resource id.
func nameFromID(id string) string {
	if i := strings.LastIndexByte(id, '/'); i >= 0 {
		return id[i+1:]
	}
	return id
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func derefBool(b *bool) bool {
	return b != nil && *b
}

// --- real Azure adapter ---

// realCompute is the production implementation of API. It wraps the armcompute
// VirtualMachinesClient (listed subscription-wide, StatusOnly so power state
// rides along) and the armnetwork InterfacesClient (per-NIC public-IP lookup).
type realCompute struct {
	vms  *armcompute.VirtualMachinesClient
	nics *armnetwork.InterfacesClient
}

// newRealCompute builds the SDK clients. opts is nil in production; tests pass a
// *arm.ClientOptions pointing the clients at an httptest server.
func newRealCompute(subscriptionID string, cred azcore.TokenCredential, opts *arm.ClientOptions) (*realCompute, error) {
	vms, err := armcompute.NewVirtualMachinesClient(subscriptionID, cred, opts)
	if err != nil {
		return nil, fmt.Errorf("azure.compute: virtual machines client: %w", err)
	}
	nics, err := armnetwork.NewInterfacesClient(subscriptionID, cred, opts)
	if err != nil {
		return nil, fmt.Errorf("azure.compute: network interfaces client: %w", err)
	}
	return &realCompute{vms: vms, nics: nics}, nil
}

func (r *realCompute) ListVirtualMachines(ctx context.Context) ([]*armcompute.VirtualMachine, error) {
	var out []*armcompute.VirtualMachine
	pager := r.vms.NewListAllPager(&armcompute.VirtualMachinesClientListAllOptions{
		StatusOnly: to.Ptr("true"), // populate InstanceView (power state) in the single list call
	})
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		out = append(out, page.Value...)
	}
	return out, nil
}

func (r *realCompute) GetNetworkInterface(ctx context.Context, resourceGroup, name string) (*armnetwork.Interface, error) {
	resp, err := r.nics.Get(ctx, resourceGroup, name, nil)
	if err != nil {
		return nil, err
	}
	return &resp.Interface, nil
}

var _ core.SourcePlugin = (*Plugin)(nil)
