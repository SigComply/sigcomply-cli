package acm

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	awsacm "github.com/aws/aws-sdk-go-v2/service/acm"
	acmtypes "github.com/aws/aws-sdk-go-v2/service/acm/types"

	"github.com/sigcomply/sigcomply-cli/internal/core"
)

type fakeCert struct {
	arn      string
	domain   string
	notAfter *time.Time
	status   acmtypes.CertificateStatus
	certType acmtypes.CertificateType
}

type fakeAPI struct {
	certs   []fakeCert
	listErr error
	descErr error

	listCalls int
	descCalls int
}

func (f *fakeAPI) ListCertificates(_ context.Context, _ *awsacm.ListCertificatesInput, _ ...func(*awsacm.Options)) (*awsacm.ListCertificatesOutput, error) {
	f.listCalls++
	if f.listErr != nil {
		return nil, f.listErr
	}
	out := &awsacm.ListCertificatesOutput{}
	for i := range f.certs {
		out.CertificateSummaryList = append(out.CertificateSummaryList, acmtypes.CertificateSummary{
			CertificateArn: ptr(f.certs[i].arn),
		})
	}
	return out, nil
}

func (f *fakeAPI) DescribeCertificate(_ context.Context, in *awsacm.DescribeCertificateInput, _ ...func(*awsacm.Options)) (*awsacm.DescribeCertificateOutput, error) {
	f.descCalls++
	if f.descErr != nil {
		return nil, f.descErr
	}
	arn := ""
	if in.CertificateArn != nil {
		arn = *in.CertificateArn
	}
	for i := range f.certs {
		c := f.certs[i]
		if c.arn != arn {
			continue
		}
		return &awsacm.DescribeCertificateOutput{Certificate: &acmtypes.CertificateDetail{
			CertificateArn: ptr(c.arn),
			DomainName:     ptr(c.domain),
			NotAfter:       c.notAfter,
			Status:         c.status,
			Type:           c.certType,
		}}, nil
	}
	return &awsacm.DescribeCertificateOutput{}, nil
}

func ptr[T any](v T) *T { return &v }

// fixedNow is the deterministic clock used so days_until_expiry is stable.
var fixedNow = time.Date(2026, 6, 3, 0, 0, 0, 0, time.UTC)

func TestPlugin_IDAndEmits(t *testing.T) {
	p := New(Options{API: &fakeAPI{}})
	if p.ID() != SourceID {
		t.Errorf("ID = %q; want %q", p.ID(), SourceID)
	}
	em := p.Emits()
	if len(em) != 1 || em[0] != EvidenceTypeID {
		t.Errorf("Emits = %v; want [%s]", em, EvidenceTypeID)
	}
}

func TestPlugin_InitNoOp(t *testing.T) {
	p := New(Options{API: &fakeAPI{}})
	if err := p.Init(context.Background(), nil); err != nil {
		t.Errorf("Init: %v", err)
	}
}

func unmarshalByID(t *testing.T, records []core.EvidenceRecord) map[string]certPayload {
	t.Helper()
	byID := map[string]certPayload{}
	for _, r := range records {
		var pl certPayload
		if err := json.Unmarshal(r.Payload, &pl); err != nil {
			t.Fatalf("Unmarshal %s: %v", r.ID, err)
		}
		byID[r.ID] = pl
	}
	return byID
}

// twoCertFake returns a fake with one managed (alpha, 45d) and one imported
// (zeta, 10d) certificate, plus a plugin clocked at fixedNow.
func twoCertFake() *fakeAPI {
	managedExpiry := fixedNow.Add(45 * 24 * time.Hour)
	importedExpiry := fixedNow.Add(10 * 24 * time.Hour)
	return &fakeAPI{certs: []fakeCert{
		{arn: "arn:zeta", domain: "zeta.example.com", notAfter: &importedExpiry, status: acmtypes.CertificateStatusIssued, certType: acmtypes.CertificateTypeImported},
		{arn: "arn:alpha", domain: "alpha.example.com", notAfter: &managedExpiry, status: acmtypes.CertificateStatusIssued, certType: acmtypes.CertificateTypeAmazonIssued},
	}}
}

func TestCollect_SortsByIDAndRecordMeta(t *testing.T) {
	p := New(Options{API: twoCertFake(), Now: func() time.Time { return fixedNow }})
	records, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("len(records) = %d; want 2", len(records))
	}
	if records[0].ID != "arn:alpha" || records[1].ID != "arn:zeta" {
		t.Errorf("records not sorted by ID: %v", []string{records[0].ID, records[1].ID})
	}
	for i := range records {
		if records[i].CollectedAt != fixedNow {
			t.Errorf("record[%d].CollectedAt = %v; want %v", i, records[i].CollectedAt, fixedNow)
		}
		if records[i].SourceID != SourceID {
			t.Errorf("record[%d].SourceID = %q", i, records[i].SourceID)
		}
		if records[i].Type != EvidenceTypeID {
			t.Errorf("record[%d].Type = %q", i, records[i].Type)
		}
	}
}

func TestCollect_ManagedCertFields(t *testing.T) {
	p := New(Options{API: twoCertFake(), Now: func() time.Time { return fixedNow }})
	records, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	managed := unmarshalByID(t, records)["arn:alpha"]
	if !managed.IsManaged {
		t.Errorf("alpha.is_managed = false; want true (AMAZON_ISSUED)")
	}
	if managed.AutoRenew == nil || !*managed.AutoRenew {
		t.Errorf("alpha.auto_renew = %v; want true (managed)", managed.AutoRenew)
	}
	if managed.DaysUntilExpiry != 45 {
		t.Errorf("alpha.days_until_expiry = %d; want 45", managed.DaysUntilExpiry)
	}
	want := fixedNow.Add(45 * 24 * time.Hour).UTC().Format(time.RFC3339)
	if managed.NotAfter != want {
		t.Errorf("alpha.not_after = %q; want %q", managed.NotAfter, want)
	}
	if managed.Provider != "aws" {
		t.Errorf("alpha.provider = %q; want aws", managed.Provider)
	}
	if managed.Status != "ISSUED" {
		t.Errorf("alpha.status = %q; want ISSUED", managed.Status)
	}
}

func TestCollect_ImportedCertFields(t *testing.T) {
	p := New(Options{API: twoCertFake(), Now: func() time.Time { return fixedNow }})
	records, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	imported := unmarshalByID(t, records)["arn:zeta"]
	if imported.IsManaged {
		t.Errorf("zeta.is_managed = true; want false (IMPORTED)")
	}
	if imported.AutoRenew != nil {
		t.Errorf("zeta.auto_renew = %v; want nil (imported, omitted)", imported.AutoRenew)
	}
	if imported.DaysUntilExpiry != 10 {
		t.Errorf("zeta.days_until_expiry = %d; want 10", imported.DaysUntilExpiry)
	}
}

func TestCollect_ImportedOmitsAutoRenewKey(t *testing.T) {
	exp := fixedNow.Add(20 * 24 * time.Hour)
	fake := &fakeAPI{certs: []fakeCert{
		{arn: "arn:imported", domain: "i.example.com", notAfter: &exp, status: acmtypes.CertificateStatusIssued, certType: acmtypes.CertificateTypeImported},
	}}
	p := New(Options{API: fake, Now: func() time.Time { return fixedNow }})
	records, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	var raw map[string]any
	if err := json.Unmarshal(records[0].Payload, &raw); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if _, present := raw["auto_renew"]; present {
		t.Errorf("imported payload should omit auto_renew, got present")
	}
	if _, present := raw["not_after"]; !present {
		t.Errorf("payload should always carry not_after")
	}
}

func TestCollect_ExpiredCertNegativeDays(t *testing.T) {
	exp := fixedNow.Add(-5 * 24 * time.Hour)
	fake := &fakeAPI{certs: []fakeCert{
		{arn: "arn:expired", domain: "e.example.com", notAfter: &exp, status: acmtypes.CertificateStatusExpired, certType: acmtypes.CertificateTypeAmazonIssued},
	}}
	p := New(Options{API: fake, Now: func() time.Time { return fixedNow }})
	records, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	byID := unmarshalByID(t, records)
	if got := byID["arn:expired"].DaysUntilExpiry; got != -5 {
		t.Errorf("days_until_expiry = %d; want -5", got)
	}
}

func TestCollect_PaginatesListCertificates(t *testing.T) {
	exp := fixedNow.Add(60 * 24 * time.Hour)
	fake := &pagingAPI{
		pages: [][]string{{"arn:a"}, {"arn:b"}},
		details: map[string]acmtypes.CertificateDetail{
			"arn:a": {CertificateArn: ptr("arn:a"), DomainName: ptr("a"), NotAfter: &exp, Status: acmtypes.CertificateStatusIssued, Type: acmtypes.CertificateTypeAmazonIssued},
			"arn:b": {CertificateArn: ptr("arn:b"), DomainName: ptr("b"), NotAfter: &exp, Status: acmtypes.CertificateStatusIssued, Type: acmtypes.CertificateTypeAmazonIssued},
		},
	}
	p := New(Options{API: fake, Now: func() time.Time { return fixedNow }})
	records, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("len(records) = %d; want 2", len(records))
	}
	if fake.listCalls != 2 {
		t.Errorf("listCalls = %d; want 2 (paged)", fake.listCalls)
	}
}

type pagingAPI struct {
	pages     [][]string
	details   map[string]acmtypes.CertificateDetail
	listCalls int
}

func (f *pagingAPI) ListCertificates(_ context.Context, in *awsacm.ListCertificatesInput, _ ...func(*awsacm.Options)) (*awsacm.ListCertificatesOutput, error) {
	idx := 0
	if in.NextToken != nil {
		// token encodes the next page index as a single digit.
		idx = int((*in.NextToken)[0] - '0')
	}
	f.listCalls++
	out := &awsacm.ListCertificatesOutput{}
	for _, arn := range f.pages[idx] {
		out.CertificateSummaryList = append(out.CertificateSummaryList, acmtypes.CertificateSummary{CertificateArn: ptr(arn)})
	}
	if idx+1 < len(f.pages) {
		out.NextToken = ptr(string(rune('0' + idx + 1)))
	}
	return out, nil
}

func (f *pagingAPI) DescribeCertificate(_ context.Context, in *awsacm.DescribeCertificateInput, _ ...func(*awsacm.Options)) (*awsacm.DescribeCertificateOutput, error) {
	d := f.details[*in.CertificateArn]
	return &awsacm.DescribeCertificateOutput{Certificate: &d}, nil
}

func TestCollect_RejectsWrongEvidenceType(t *testing.T) {
	p := New(Options{API: &fakeAPI{}})
	_, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{"directory_user"}})
	if err == nil || !strings.Contains(err.Error(), "does not include") {
		t.Errorf("want error; got %v", err)
	}
}

func TestCollect_ListError(t *testing.T) {
	p := New(Options{API: &fakeAPI{listErr: errors.New("kaboom")}})
	_, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}})
	if err == nil || !strings.Contains(err.Error(), "list certificates") {
		t.Errorf("want list error; got %v", err)
	}
}

func TestCollect_DescribeError(t *testing.T) {
	fake := &fakeAPI{certs: []fakeCert{{arn: "arn:a"}}, descErr: errors.New("boom")}
	p := New(Options{API: fake})
	_, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}})
	if err == nil || !strings.Contains(err.Error(), "describe certificate") {
		t.Errorf("want describe error; got %v", err)
	}
}

func TestCollect_DefaultNowIsUsed(t *testing.T) {
	exp := time.Now().Add(100 * 24 * time.Hour)
	fake := &fakeAPI{certs: []fakeCert{{arn: "arn:a", notAfter: &exp, certType: acmtypes.CertificateTypeAmazonIssued}}}
	p := New(Options{API: fake})
	records, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if records[0].CollectedAt.IsZero() {
		t.Errorf("CollectedAt zero")
	}
}

func TestCollect_SkipsCertWithEmptyARN(t *testing.T) {
	// A summary with empty ARN is filtered before Describe; a detail with
	// empty ARN is filtered after.
	fake := &fakeAPI{certs: []fakeCert{
		{arn: ""},
		{arn: "arn:ok", certType: acmtypes.CertificateTypeAmazonIssued},
	}}
	p := New(Options{API: fake, Now: func() time.Time { return fixedNow }})
	records, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(records) != 1 || records[0].ID != "arn:ok" {
		t.Errorf("records = %v", records)
	}
}

func TestFormatAndDaysHelpers(t *testing.T) {
	if formatNotAfter(nil) != "" {
		t.Errorf("nil notAfter not empty")
	}
	if daysUntil(nil, fixedNow) != 0 {
		t.Errorf("nil notAfter days != 0")
	}
	if safeString(nil) != "" {
		t.Errorf("nil string not empty")
	}
	if got := safeString(ptr("x")); got != "x" {
		t.Errorf("safeString = %q", got)
	}
}

func TestNewFromAWS_SmokeTest(t *testing.T) {
	p, err := NewFromAWS(context.Background(), "us-east-1")
	if err != nil {
		t.Logf("NewFromAWS errored (acceptable in CI): %v", err)
		return
	}
	if p.ID() != SourceID {
		t.Errorf("ID = %q", p.ID())
	}
}
