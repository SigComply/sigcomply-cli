package aws

import (
	"context"
	"errors"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/acm"
	acmtypes "github.com/aws/aws-sdk-go-v2/service/acm/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type MockACMClient struct {
	ListCertificatesFunc    func(ctx context.Context, params *acm.ListCertificatesInput, optFns ...func(*acm.Options)) (*acm.ListCertificatesOutput, error)
	DescribeCertificateFunc func(ctx context.Context, params *acm.DescribeCertificateInput, optFns ...func(*acm.Options)) (*acm.DescribeCertificateOutput, error)
}

func (m *MockACMClient) ListCertificates(ctx context.Context, params *acm.ListCertificatesInput, optFns ...func(*acm.Options)) (*acm.ListCertificatesOutput, error) {
	return m.ListCertificatesFunc(ctx, params, optFns...)
}

func (m *MockACMClient) DescribeCertificate(ctx context.Context, params *acm.DescribeCertificateInput, optFns ...func(*acm.Options)) (*acm.DescribeCertificateOutput, error) {
	if m.DescribeCertificateFunc != nil {
		return m.DescribeCertificateFunc(ctx, params, optFns...)
	}
	return &acm.DescribeCertificateOutput{}, nil
}

func TestACMCollector_CollectCertificates(t *testing.T) {
	expiry := time.Now().Add(15 * 24 * time.Hour) // 15 days
	mock := &MockACMClient{
		ListCertificatesFunc: func(ctx context.Context, params *acm.ListCertificatesInput, optFns ...func(*acm.Options)) (*acm.ListCertificatesOutput, error) {
			return &acm.ListCertificatesOutput{
				CertificateSummaryList: []acmtypes.CertificateSummary{
					{CertificateArn: awssdk.String("arn:aws:acm:us-east-1:123:certificate/abc"), DomainName: awssdk.String("example.com"), Status: acmtypes.CertificateStatusIssued},
				},
			}, nil
		},
		DescribeCertificateFunc: func(ctx context.Context, params *acm.DescribeCertificateInput, optFns ...func(*acm.Options)) (*acm.DescribeCertificateOutput, error) {
			return &acm.DescribeCertificateOutput{
				Certificate: &acmtypes.CertificateDetail{
					NotAfter: &expiry,
					InUseBy:  []string{"arn:aws:elasticloadbalancing:us-east-1:123:loadbalancer/app/my-alb"},
				},
			}, nil
		},
	}

	collector := NewACMCollector(mock)
	certs, err := collector.CollectCertificates(context.Background())

	require.NoError(t, err)
	require.Len(t, certs, 1)
	assert.Equal(t, "example.com", certs[0].DomainName)
	assert.InDelta(t, 15, certs[0].DaysUntilExpiry, 1)
	assert.True(t, certs[0].InUse)
}

func TestACMCollector_CollectCertificates_Error(t *testing.T) {
	mock := &MockACMClient{
		ListCertificatesFunc: func(ctx context.Context, params *acm.ListCertificatesInput, optFns ...func(*acm.Options)) (*acm.ListCertificatesOutput, error) {
			return nil, errors.New("access denied")
		},
	}

	collector := NewACMCollector(mock)
	_, err := collector.CollectCertificates(context.Background())
	assert.Error(t, err)
}

func TestACMCertificate_ToEvidence(t *testing.T) {
	cert := &ACMCertificate{ARN: "arn:aws:acm:us-east-1:123:certificate/abc", DomainName: "example.com"}
	ev := cert.ToEvidence("123456789012")
	assert.Equal(t, "aws", ev.Collector)
	assert.Equal(t, "aws:acm:certificate", ev.ResourceType)
	assert.NotEmpty(t, ev.Hash)
}
