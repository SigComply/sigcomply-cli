// Package acm implements the aws.acm source plugin: lists ACM
// certificates and emits tls_certificate evidence records with
// cross-vendor expiry, managed-status, and auto-renewal attributes.
package acm

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"time"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	awsacm "github.com/aws/aws-sdk-go-v2/service/acm"
	acmtypes "github.com/aws/aws-sdk-go-v2/service/acm/types"

	"github.com/sigcomply/sigcomply-cli/internal/core"
)

// EvidenceTypeID is the evidence type this plugin emits.
const EvidenceTypeID = "tls_certificate"

// SourceID is the registered ID for the aws.acm plugin instance.
const SourceID = "aws.acm"

// hoursPerDay is used to convert an expiry duration to whole days.
const hoursPerDay = 24

// API is the subset of the ACM client this plugin uses.
type API interface {
	ListCertificates(ctx context.Context, params *awsacm.ListCertificatesInput, optFns ...func(*awsacm.Options)) (*awsacm.ListCertificatesOutput, error)
	DescribeCertificate(ctx context.Context, params *awsacm.DescribeCertificateInput, optFns ...func(*awsacm.Options)) (*awsacm.DescribeCertificateOutput, error)
}

// Plugin is the in-process aws.acm source.
type Plugin struct {
	api    API
	region string
	now    func() time.Time
}

// Options is the constructor input.
type Options struct {
	API    API
	Region string
	Now    func() time.Time
}

// New constructs a Plugin around an explicit API implementation.
func New(opts Options) *Plugin {
	now := opts.Now
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	return &Plugin{
		api:    opts.API,
		region: opts.Region,
		now:    now,
	}
}

// NewFromAWS constructs a Plugin backed by the real AWS SDK.
func NewFromAWS(ctx context.Context, region string) (*Plugin, error) {
	cfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(region))
	if err != nil {
		return nil, fmt.Errorf("aws.acm: load AWS config: %w", err)
	}
	return New(Options{
		API:    awsacm.NewFromConfig(cfg),
		Region: region,
	}), nil
}

// ID returns the registered plugin ID.
func (*Plugin) ID() string { return SourceID }

// Emits returns the evidence types this plugin can produce.
func (*Plugin) Emits() []string { return []string{EvidenceTypeID} }

// Init is a no-op; configuration is supplied to the constructor.
func (*Plugin) Init(context.Context, map[string]any) error { return nil }

// certPayload is the cross-vendor tls_certificate shape.
type certPayload struct {
	ID       string `json:"id"`
	Domain   string `json:"domain"`
	Provider string `json:"provider"`
	Status   string `json:"status,omitempty"`
	// NotAfter is the absolute expiry timestamp (RFC3339) — the durable,
	// replay-safe field. days_until_expiry is derived from it at collect
	// time for policy convenience.
	NotAfter        string `json:"not_after"`
	DaysUntilExpiry int    `json:"days_until_expiry"`
	IsManaged       bool   `json:"is_managed"`
	// AutoRenew is a pointer so it is omitted (not emitted as false) for
	// imported certificates, which have no auto-renewal concept. Only
	// AMAZON_ISSUED (managed) certificates carry it. A consuming policy
	// guards with is_managed, so imported certs are skipped rather than
	// false-failed.
	AutoRenew *bool `json:"auto_renew,omitempty"`
}

// Collect lists certificates and returns one tls_certificate record per cert.
func (p *Plugin) Collect(ctx context.Context, req core.SlotRequest) ([]core.EvidenceRecord, error) {
	if !req.Accepts(EvidenceTypeID) {
		return nil, fmt.Errorf("aws.acm: slot AcceptedTypes %v does not include %q", req.AcceptedTypes, EvidenceTypeID)
	}
	arns, err := p.listAllCertificateARNs(ctx)
	if err != nil {
		return nil, fmt.Errorf("aws.acm: list certificates: %w", err)
	}
	now := p.now()
	records := make([]core.EvidenceRecord, 0, len(arns))
	for _, arn := range arns {
		detail, err := p.describe(ctx, arn)
		if err != nil {
			return nil, fmt.Errorf("aws.acm: describe certificate: %w", err)
		}
		if detail == nil {
			continue
		}
		id := safeString(detail.CertificateArn)
		if id == "" {
			continue
		}
		payload := buildPayload(detail, now)
		body, err := json.Marshal(payload)
		if err != nil {
			return nil, fmt.Errorf("aws.acm: marshal payload: %w", err)
		}
		records = append(records, core.EvidenceRecord{
			Type:        EvidenceTypeID,
			ID:          id,
			Payload:     body,
			SourceID:    SourceID,
			CollectedAt: now,
		})
	}
	sort.Slice(records, func(i, j int) bool { return records[i].ID < records[j].ID })
	return records, nil
}

// buildPayload maps an ACM CertificateDetail to the cross-vendor shape.
func buildPayload(detail *acmtypes.CertificateDetail, now time.Time) certPayload {
	isManaged := detail.Type == acmtypes.CertificateTypeAmazonIssued
	payload := certPayload{
		ID:              safeString(detail.CertificateArn),
		Domain:          safeString(detail.DomainName),
		Provider:        "aws",
		Status:          string(detail.Status),
		NotAfter:        formatNotAfter(detail.NotAfter),
		DaysUntilExpiry: daysUntil(detail.NotAfter, now),
		IsManaged:       isManaged,
	}
	if isManaged {
		// AWS-managed (AMAZON_ISSUED) certificates auto-renew; imported
		// certs omit the field entirely.
		t := true
		payload.AutoRenew = &t
	}
	return payload
}

func (p *Plugin) listAllCertificateARNs(ctx context.Context) ([]string, error) {
	var (
		out   []string
		token *string
	)
	for {
		page, err := p.api.ListCertificates(ctx, &awsacm.ListCertificatesInput{NextToken: token})
		if err != nil {
			return nil, err
		}
		for i := range page.CertificateSummaryList {
			arn := safeString(page.CertificateSummaryList[i].CertificateArn)
			if arn != "" {
				out = append(out, arn)
			}
		}
		if page.NextToken != nil && *page.NextToken != "" {
			token = page.NextToken
			continue
		}
		return out, nil
	}
}

func (p *Plugin) describe(ctx context.Context, arn string) (*acmtypes.CertificateDetail, error) {
	resp, err := p.api.DescribeCertificate(ctx, &awsacm.DescribeCertificateInput{CertificateArn: &arn})
	if err != nil {
		return nil, err
	}
	if resp == nil {
		return nil, nil
	}
	return resp.Certificate, nil
}

// formatNotAfter renders the expiry timestamp as RFC3339 (UTC). Empty when
// the certificate has no NotAfter (e.g. pending validation).
func formatNotAfter(t *time.Time) string {
	if t == nil {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

// daysUntil returns whole days between now and the expiry timestamp,
// rounded toward zero. Negative means already expired; 0 when unknown.
func daysUntil(notAfter *time.Time, now time.Time) int {
	if notAfter == nil {
		return 0
	}
	hours := notAfter.Sub(now).Hours() / hoursPerDay
	return int(math.Trunc(hours))
}

func safeString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

var _ core.SourcePlugin = (*Plugin)(nil)
