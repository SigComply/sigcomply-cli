package gcp

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"google.golang.org/api/compute/v1"

	"github.com/sigcomply/sigcomply-cli/internal/core/evidence"
)

// FirewallRule represents a GCP firewall rule.
type FirewallRule struct {
	Name           string   `json:"name"`
	Network        string   `json:"network"`
	Direction      string   `json:"direction"`
	Priority       int64    `json:"priority"`
	SourceRanges   []string `json:"source_ranges,omitempty"`
	Allowed        []Allow  `json:"allowed,omitempty"`
	Disabled       bool     `json:"disabled"`
	OpenSSH        bool     `json:"open_ssh"`
	OpenRDP        bool     `json:"open_rdp"`
	OpenToInternet bool     `json:"open_to_internet"`
}

// Allow represents an allowed protocol/port combination.
type Allow struct {
	Protocol string   `json:"protocol"`
	Ports    []string `json:"ports,omitempty"`
}

// Subnet represents a GCP VPC subnet.
type Subnet struct {
	Name            string `json:"name"`
	Region          string `json:"region"`
	Network         string `json:"network"`
	IPCIDRRange     string `json:"ip_cidr_range"`
	FlowLogsEnabled bool   `json:"flow_logs_enabled"`
}

// Disk represents a GCP persistent disk.
type Disk struct {
	Name                  string `json:"name"`
	Zone                  string `json:"zone"`
	SizeGb                int64  `json:"size_gb"`
	Type                  string `json:"type"`
	EncryptionEnabled     bool   `json:"encryption_enabled"`
	EncryptionType        string `json:"encryption_type"`
	DiskEncryptionKeyType string `json:"disk_encryption_key_type,omitempty"`
}

// Network represents a GCP VPC network.
type Network struct {
	Name        string `json:"name"`
	AutoCreate  bool   `json:"auto_create_subnetworks"`
	Description string `json:"description,omitempty"`
	IsDefault   bool   `json:"is_default"`
}

// ToEvidence converts a FirewallRule to Evidence.
func (f *FirewallRule) ToEvidence(projectID string) evidence.Evidence {
	data, _ := json.Marshal(f) //nolint:errcheck // json.Marshal on a known-serializable struct will not error
	resourceID := fmt.Sprintf("projects/%s/global/firewalls/%s", projectID, f.Name)
	ev := evidence.New("gcp", "gcp:compute:firewall", resourceID, data)
	ev.Metadata = evidence.Metadata{AccountID: projectID}
	return ev
}

// ToEvidence converts a Subnet to Evidence.
func (s *Subnet) ToEvidence(projectID string) evidence.Evidence {
	data, _ := json.Marshal(s) //nolint:errcheck // json.Marshal on a known-serializable struct will not error
	resourceID := fmt.Sprintf("projects/%s/regions/%s/subnetworks/%s", projectID, s.Region, s.Name)
	ev := evidence.New("gcp", "gcp:compute:subnet", resourceID, data)
	ev.Metadata = evidence.Metadata{AccountID: projectID}
	return ev
}

// ToEvidence converts a Disk to Evidence.
func (d *Disk) ToEvidence(projectID string) evidence.Evidence {
	data, _ := json.Marshal(d) //nolint:errcheck // json.Marshal on a known-serializable struct will not error
	resourceID := fmt.Sprintf("projects/%s/zones/%s/disks/%s", projectID, d.Zone, d.Name)
	ev := evidence.New("gcp", "gcp:compute:disk", resourceID, data)
	ev.Metadata = evidence.Metadata{AccountID: projectID}
	return ev
}

// ToEvidence converts a Network to Evidence.
func (n *Network) ToEvidence(projectID string) evidence.Evidence {
	data, _ := json.Marshal(n) //nolint:errcheck // json.Marshal on a known-serializable struct will not error
	resourceID := fmt.Sprintf("projects/%s/global/networks/%s", projectID, n.Name)
	ev := evidence.New("gcp", "gcp:compute:network", resourceID, data)
	ev.Metadata = evidence.Metadata{AccountID: projectID}
	return ev
}

// ComputeCollector collects GCP Compute Engine data.
type ComputeCollector struct {
	service *compute.Service
}

// NewComputeCollector creates a new Compute Engine collector.
func NewComputeCollector(service *compute.Service) *ComputeCollector {
	return &ComputeCollector{service: service}
}

// CollectFirewallRules retrieves all firewall rules.
func (c *ComputeCollector) CollectFirewallRules(ctx context.Context, projectID string) ([]FirewallRule, error) { //nolint:gocyclo // firewall rule analysis requires nested protocol/port checks
	resp, err := c.service.Firewalls.List(projectID).Context(ctx).Do()
	if err != nil {
		return nil, fmt.Errorf("failed to list firewall rules: %w", err)
	}

	var rules []FirewallRule
	for _, fw := range resp.Items {
		rule := FirewallRule{
			Name:         fw.Name,
			Network:      fw.Network,
			Direction:    fw.Direction,
			Priority:     fw.Priority,
			SourceRanges: fw.SourceRanges,
			Disabled:     fw.Disabled,
		}

		for _, a := range fw.Allowed {
			rule.Allowed = append(rule.Allowed, Allow{
				Protocol: a.IPProtocol,
				Ports:    a.Ports,
			})
		}

		// Check if open to internet (0.0.0.0/0)
		for _, sr := range fw.SourceRanges {
			if sr == "0.0.0.0/0" {
				rule.OpenToInternet = true
				break
			}
		}

		// Check for open SSH/RDP
		if rule.OpenToInternet && rule.Direction == "INGRESS" {
			for _, a := range rule.Allowed {
				if a.Protocol == "tcp" || a.Protocol == "all" {
					for _, port := range a.Ports {
						if port == "22" || containsPort(port, 22) {
							rule.OpenSSH = true
						}
						if port == "3389" || containsPort(port, 3389) {
							rule.OpenRDP = true
						}
					}
					// "all" protocol with no ports = all ports open
					if a.Protocol == "all" || (a.Protocol == "tcp" && len(a.Ports) == 0) {
						rule.OpenSSH = true
						rule.OpenRDP = true
					}
				}
			}
		}

		rules = append(rules, rule)
	}

	return rules, nil
}

// containsPort checks if a port range string contains the given port.
func containsPort(portRange string, target int) bool {
	parts := strings.SplitN(portRange, "-", 2)
	if len(parts) != 2 {
		return false
	}
	var start, end int
	if _, err := fmt.Sscanf(parts[0], "%d", &start); err != nil {
		return false
	}
	if _, err := fmt.Sscanf(parts[1], "%d", &end); err != nil {
		return false
	}
	return target >= start && target <= end
}

// CollectSubnets retrieves all VPC subnets.
func (c *ComputeCollector) CollectSubnets(ctx context.Context, projectID string) ([]Subnet, error) {
	resp, err := c.service.Subnetworks.AggregatedList(projectID).Context(ctx).Do()
	if err != nil {
		return nil, fmt.Errorf("failed to list subnets: %w", err)
	}

	var subnets []Subnet
	for _, scopedList := range resp.Items {
		for _, sn := range scopedList.Subnetworks {
			subnet := Subnet{
				Name:        sn.Name,
				Region:      sn.Region,
				Network:     sn.Network,
				IPCIDRRange: sn.IpCidrRange,
			}

			if sn.LogConfig != nil {
				subnet.FlowLogsEnabled = sn.LogConfig.Enable
			}

			subnets = append(subnets, subnet)
		}
	}

	return subnets, nil
}

// CollectDisks retrieves all persistent disks.
func (c *ComputeCollector) CollectDisks(ctx context.Context, projectID string) ([]Disk, error) {
	resp, err := c.service.Disks.AggregatedList(projectID).Context(ctx).Do()
	if err != nil {
		return nil, fmt.Errorf("failed to list disks: %w", err)
	}

	var disks []Disk
	for _, scopedList := range resp.Items {
		for _, d := range scopedList.Disks {
			disk := Disk{
				Name:   d.Name,
				Zone:   d.Zone,
				SizeGb: d.SizeGb,
				Type:   d.Type,
			}

			// All GCP disks are encrypted by default (Google-managed)
			disk.EncryptionEnabled = true
			disk.EncryptionType = "google-managed"

			if d.DiskEncryptionKey != nil {
				if d.DiskEncryptionKey.KmsKeyName != "" {
					disk.EncryptionType = "cmek"
					disk.DiskEncryptionKeyType = d.DiskEncryptionKey.KmsKeyName
				} else if d.DiskEncryptionKey.RawKey != "" || d.DiskEncryptionKey.Sha256 != "" {
					disk.EncryptionType = "csek"
				}
			}

			disks = append(disks, disk)
		}
	}

	return disks, nil
}

// CollectNetworks retrieves all VPC networks.
func (c *ComputeCollector) CollectNetworks(ctx context.Context, projectID string) ([]Network, error) {
	resp, err := c.service.Networks.List(projectID).Context(ctx).Do()
	if err != nil {
		return nil, fmt.Errorf("failed to list networks: %w", err)
	}

	var networks []Network
	for _, n := range resp.Items {
		network := Network{
			Name:        n.Name,
			AutoCreate:  n.AutoCreateSubnetworks,
			Description: n.Description,
			IsDefault:   n.Name == "default",
		}
		networks = append(networks, network)
	}

	return networks, nil
}

// CollectEvidence collects all Compute Engine evidence.
func (c *ComputeCollector) CollectEvidence(ctx context.Context, projectID string) ([]evidence.Evidence, error) {
	var evidenceList []evidence.Evidence

	// Collect firewall rules
	rules, err := c.CollectFirewallRules(ctx, projectID)
	if err != nil {
		return nil, err
	}
	for i := range rules {
		evidenceList = append(evidenceList, rules[i].ToEvidence(projectID))
	}

	// Collect subnets
	subnets, err := c.CollectSubnets(ctx, projectID)
	if err != nil {
		// Fail-safe: continue without subnets
		_ = err
	} else {
		for i := range subnets {
			evidenceList = append(evidenceList, subnets[i].ToEvidence(projectID))
		}
	}

	// Collect disks
	disks, err := c.CollectDisks(ctx, projectID)
	if err != nil {
		// Fail-safe: continue without disks
		_ = err
	} else {
		for i := range disks {
			evidenceList = append(evidenceList, disks[i].ToEvidence(projectID))
		}
	}

	// Collect networks
	networks, err := c.CollectNetworks(ctx, projectID)
	if err != nil {
		// Fail-safe: continue without networks
		_ = err
	} else {
		for i := range networks {
			evidenceList = append(evidenceList, networks[i].ToEvidence(projectID))
		}
	}

	return evidenceList, nil
}
