package aws

import (
	"context"
	"encoding/json"
	"math"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/acm"
	"github.com/sigcomply/sigcomply-cli/internal/core/evidence"
)

// ACMClient defines the interface for ACM operations.
type ACMClient interface {
	ListCertificates(ctx context.Context, params *acm.ListCertificatesInput, optFns ...func(*acm.Options)) (*acm.ListCertificatesOutput, error)
	DescribeCertificate(ctx context.Context, params *acm.DescribeCertificateInput, optFns ...func(*acm.Options)) (*acm.DescribeCertificateOutput, error)
}

// ACMCertificate represents an ACM certificate.
type ACMCertificate struct {
	ARN             string `json:"arn"`
	DomainName      string `json:"domain_name"`
	Status          string `json:"status"`
	ExpiresAt       string `json:"expires_at,omitempty"`
	DaysUntilExpiry int    `json:"days_until_expiry"`
	InUse                      bool   `json:"in_use"`
	TransparencyLoggingEnabled bool   `json:"transparency_logging_enabled"`
	RenewalStatus              string `json:"renewal_status"`
}

// ToEvidence converts an ACMCertificate to Evidence.
func (c *ACMCertificate) ToEvidence(accountID string) evidence.Evidence {
	data, _ := json.Marshal(c) //nolint:errcheck // marshaling a known struct type will not fail
	ev := evidence.New("aws", "aws:acm:certificate", c.ARN, data)
	ev.Metadata = evidence.Metadata{AccountID: accountID}
	return ev
}

// ACMCollector collects ACM certificate data.
type ACMCollector struct {
	client ACMClient
}

// NewACMCollector creates a new ACM collector.
func NewACMCollector(client ACMClient) *ACMCollector {
	return &ACMCollector{client: client}
}

// CollectCertificates retrieves all ACM certificates.
func (c *ACMCollector) CollectCertificates(ctx context.Context) ([]ACMCertificate, error) {
	var certs []ACMCertificate
	var nextToken *string

	for {
		output, err := c.client.ListCertificates(ctx, &acm.ListCertificatesInput{
			NextToken: nextToken,
		})
		if err != nil {
			return nil, err
		}

		for i := range output.CertificateSummaryList {
			summary := &output.CertificateSummaryList[i]
			cert := ACMCertificate{
				ARN:        awssdk.ToString(summary.CertificateArn),
				DomainName: awssdk.ToString(summary.DomainName),
				Status:     string(summary.Status),
			}

			c.enrichCertDetails(ctx, &cert)
			certs = append(certs, cert)
		}

		if output.NextToken == nil {
			break
		}
		nextToken = output.NextToken
	}

	return certs, nil
}

func (c *ACMCollector) enrichCertDetails(ctx context.Context, cert *ACMCertificate) {
	output, err := c.client.DescribeCertificate(ctx, &acm.DescribeCertificateInput{
		CertificateArn: awssdk.String(cert.ARN),
	})
	if err != nil {
		return
	}

	if output.Certificate != nil {
		if output.Certificate.NotAfter != nil {
			cert.ExpiresAt = output.Certificate.NotAfter.Format(time.RFC3339)
			cert.DaysUntilExpiry = int(math.Floor(time.Until(*output.Certificate.NotAfter).Hours() / 24))
		}
		cert.InUse = len(output.Certificate.InUseBy) > 0
		if output.Certificate.Options != nil {
			cert.TransparencyLoggingEnabled = string(output.Certificate.Options.CertificateTransparencyLoggingPreference) == statusEnabled
		}
		cert.RenewalStatus = string(output.Certificate.RenewalEligibility)
	}
}

// CollectEvidence collects ACM certificates as evidence.
func (c *ACMCollector) CollectEvidence(ctx context.Context, accountID string) ([]evidence.Evidence, error) {
	certs, err := c.CollectCertificates(ctx)
	if err != nil {
		return nil, err
	}

	evidenceList := make([]evidence.Evidence, 0, len(certs))
	for i := range certs {
		evidenceList = append(evidenceList, certs[i].ToEvidence(accountID))
	}
	return evidenceList, nil
}
