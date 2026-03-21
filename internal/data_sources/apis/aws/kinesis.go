package aws

import (
	"context"
	"encoding/json"
	"fmt"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kinesis"
	kinesistypes "github.com/aws/aws-sdk-go-v2/service/kinesis/types"
	"github.com/sigcomply/sigcomply-cli/internal/core/evidence"
)

// KinesisClient defines the interface for Kinesis operations.
type KinesisClient interface {
	ListStreams(ctx context.Context, params *kinesis.ListStreamsInput, optFns ...func(*kinesis.Options)) (*kinesis.ListStreamsOutput, error)
	DescribeStreamSummary(ctx context.Context, params *kinesis.DescribeStreamSummaryInput, optFns ...func(*kinesis.Options)) (*kinesis.DescribeStreamSummaryOutput, error)
}

// KinesisStream represents a Kinesis data stream.
type KinesisStream struct {
	StreamName     string `json:"stream_name"`
	ARN            string `json:"arn"`
	Encrypted      bool   `json:"encrypted"`
	RetentionHours int    `json:"retention_hours"`
}

// ToEvidence converts a KinesisStream to Evidence.
func (s *KinesisStream) ToEvidence(accountID string) evidence.Evidence {
	data, _ := json.Marshal(s) //nolint:errcheck // marshaling a known struct type will not fail
	ev := evidence.New("aws", "aws:kinesis:stream", s.ARN, data)
	ev.Metadata = evidence.Metadata{AccountID: accountID}
	return ev
}

// KinesisCollector collects Kinesis data stream data.
type KinesisCollector struct {
	client KinesisClient
}

// NewKinesisCollector creates a new Kinesis collector.
func NewKinesisCollector(client KinesisClient) *KinesisCollector {
	return &KinesisCollector{client: client}
}

// CollectStreams retrieves all Kinesis data streams.
func (c *KinesisCollector) CollectStreams(ctx context.Context) ([]KinesisStream, error) {
	var streams []KinesisStream
	var nextToken *string

	for {
		output, err := c.client.ListStreams(ctx, &kinesis.ListStreamsInput{
			NextToken: nextToken,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to list Kinesis streams: %w", err)
		}

		// Use StreamSummaries (newer SDK) if available; fall back to StreamNames.
		if len(output.StreamSummaries) > 0 {
			for _, summary := range output.StreamSummaries {
				stream := KinesisStream{
					StreamName: awssdk.ToString(summary.StreamName),
					ARN:        awssdk.ToString(summary.StreamARN),
				}
				c.enrichStreamDetails(ctx, &stream, summary.StreamName)
				streams = append(streams, stream)
			}
		} else {
			for _, name := range output.StreamNames {
				stream := KinesisStream{StreamName: name}
				namePtr := awssdk.String(name)
				c.enrichStreamDetails(ctx, &stream, namePtr)
				streams = append(streams, stream)
			}
		}

		if !awssdk.ToBool(output.HasMoreStreams) {
			break
		}
		nextToken = output.NextToken
	}

	return streams, nil
}

// enrichStreamDetails fetches detailed stream info and populates encryption and retention.
func (c *KinesisCollector) enrichStreamDetails(ctx context.Context, stream *KinesisStream, streamName *string) {
	desc, err := c.client.DescribeStreamSummary(ctx, &kinesis.DescribeStreamSummaryInput{
		StreamName: streamName,
	})
	if err != nil || desc.StreamDescriptionSummary == nil {
		return // Fail-safe
	}

	sd := desc.StreamDescriptionSummary
	stream.Encrypted = sd.EncryptionType != kinesistypes.EncryptionTypeNone
	if sd.RetentionPeriodHours != nil {
		stream.RetentionHours = int(*sd.RetentionPeriodHours)
	}
	// Populate ARN if it was not available from ListStreams (StreamNames path).
	if stream.ARN == "" && sd.StreamARN != nil {
		stream.ARN = awssdk.ToString(sd.StreamARN)
	}
}

// CollectEvidence collects Kinesis streams as evidence.
func (c *KinesisCollector) CollectEvidence(ctx context.Context, accountID string) ([]evidence.Evidence, error) {
	streams, err := c.CollectStreams(ctx)
	if err != nil {
		return nil, err
	}

	evidenceList := make([]evidence.Evidence, 0, len(streams))
	for i := range streams {
		evidenceList = append(evidenceList, streams[i].ToEvidence(accountID))
	}
	return evidenceList, nil
}
