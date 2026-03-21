package aws

import (
	"context"
	"encoding/json"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	elbtypes "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2/types"
	"github.com/sigcomply/sigcomply-cli/internal/core/evidence"
)

// ELBv2Client defines the interface for ELBv2 operations.
type ELBv2Client interface {
	DescribeLoadBalancers(ctx context.Context, params *elasticloadbalancingv2.DescribeLoadBalancersInput, optFns ...func(*elasticloadbalancingv2.Options)) (*elasticloadbalancingv2.DescribeLoadBalancersOutput, error)
	DescribeListeners(ctx context.Context, params *elasticloadbalancingv2.DescribeListenersInput, optFns ...func(*elasticloadbalancingv2.Options)) (*elasticloadbalancingv2.DescribeListenersOutput, error)
	DescribeLoadBalancerAttributes(ctx context.Context, params *elasticloadbalancingv2.DescribeLoadBalancerAttributesInput, optFns ...func(*elasticloadbalancingv2.Options)) (*elasticloadbalancingv2.DescribeLoadBalancerAttributesOutput, error)
}

// ListenerAction represents a listener default action.
type ListenerAction struct {
	Type             string `json:"type"`
	RedirectProtocol string `json:"redirect_protocol,omitempty"`
}

// Listener represents an ELBv2 listener.
type Listener struct {
	Protocol       string           `json:"protocol"`
	Port           int32            `json:"port"`
	SSLPolicy      string           `json:"ssl_policy,omitempty"`
	DefaultActions []ListenerAction `json:"default_actions"`
}

// LoadBalancer represents an ELBv2 load balancer with its listeners.
type LoadBalancer struct {
	ARN               string     `json:"arn"`
	Name              string     `json:"name"`
	Type              string     `json:"type"`
	Scheme            string     `json:"scheme"`
	Listeners         []Listener `json:"listeners"`
	HTTPSEnforced      bool       `json:"https_enforced"`
	AccessLogsEnabled  bool       `json:"access_logs_enabled"`
	DeletionProtection bool       `json:"deletion_protection"`
	CrossZoneEnabled   bool       `json:"cross_zone_enabled"`
	HasInsecureSSLPolicy    bool `json:"has_insecure_ssl_policy"`
	DropInvalidHeaders      bool `json:"drop_invalid_headers"`
	HasHTTPToHTTPSRedirect  bool `json:"has_http_to_https_redirect"`
}

// ToEvidence converts a LoadBalancer to Evidence.
func (lb *LoadBalancer) ToEvidence(accountID string) evidence.Evidence {
	data, _ := json.Marshal(lb) //nolint:errcheck
	ev := evidence.New("aws", "aws:elbv2:load-balancer", lb.ARN, data)
	ev.Metadata = evidence.Metadata{AccountID: accountID}
	return ev
}

// insecureSSLPolicies contains ELB SSL policies considered insecure.
var insecureSSLPolicies = map[string]bool{
	"ELBSecurityPolicy-2016-08":           true,
	"ELBSecurityPolicy-TLS-1-0-2015-04":  true,
	"ELBSecurityPolicy-TLS-1-1-2017-01":  true,
}

// ELBv2Collector collects ELBv2 load balancer data.
type ELBv2Collector struct {
	client ELBv2Client
}

// NewELBv2Collector creates a new ELBv2 collector.
func NewELBv2Collector(client ELBv2Client) *ELBv2Collector {
	return &ELBv2Collector{client: client}
}

// CollectLoadBalancers retrieves all ELBv2 load balancers with their listeners.
func (c *ELBv2Collector) CollectLoadBalancers(ctx context.Context) ([]LoadBalancer, error) {
	var loadBalancers []LoadBalancer
	var marker *string

	for {
		output, err := c.client.DescribeLoadBalancers(ctx, &elasticloadbalancingv2.DescribeLoadBalancersInput{
			Marker: marker,
		})
		if err != nil {
			return nil, err
		}

		for i := range output.LoadBalancers {
			item := &output.LoadBalancers[i]
			lb := LoadBalancer{
				ARN:    awssdk.ToString(item.LoadBalancerArn),
				Name:   awssdk.ToString(item.LoadBalancerName),
				Type:   string(item.Type),
				Scheme: string(item.Scheme),
			}

			listeners, err := c.describeListeners(ctx, lb.ARN)
			if err != nil {
				return nil, err
			}
			lb.Listeners = listeners
			lb.HTTPSEnforced = isHTTPSEnforced(listeners)
			c.enrichAccessLogs(ctx, &lb)

			// Check for HTTP to HTTPS redirect
			for _, l := range listeners {
				if l.Protocol == "HTTP" && hasHTTPSRedirect(l) {
					lb.HasHTTPToHTTPSRedirect = true
					break
				}
			}

			for _, l := range lb.Listeners {
				if l.SSLPolicy != "" && insecureSSLPolicies[l.SSLPolicy] {
					lb.HasInsecureSSLPolicy = true
					break
				}
			}

			loadBalancers = append(loadBalancers, lb)
		}

		if output.NextMarker == nil {
			break
		}
		marker = output.NextMarker
	}

	return loadBalancers, nil
}

// describeListeners retrieves all listeners for a load balancer.
func (c *ELBv2Collector) describeListeners(ctx context.Context, lbARN string) ([]Listener, error) {
	var listeners []Listener
	var marker *string

	for {
		output, err := c.client.DescribeListeners(ctx, &elasticloadbalancingv2.DescribeListenersInput{
			LoadBalancerArn: awssdk.String(lbARN),
			Marker:          marker,
		})
		if err != nil {
			return nil, err
		}

		for i := range output.Listeners {
			item := &output.Listeners[i]
			l := Listener{
				Protocol:  string(item.Protocol),
				Port:      awssdk.ToInt32(item.Port),
				SSLPolicy: awssdk.ToString(item.SslPolicy),
			}
			for _, action := range item.DefaultActions {
				la := ListenerAction{
					Type: string(action.Type),
				}
				if action.RedirectConfig != nil {
					la.RedirectProtocol = awssdk.ToString(action.RedirectConfig.Protocol)
				}
				l.DefaultActions = append(l.DefaultActions, la)
			}
			listeners = append(listeners, l)
		}

		if output.NextMarker == nil {
			break
		}
		marker = output.NextMarker
	}

	return listeners, nil
}

// enrichAccessLogs checks if access logging is enabled for a load balancer.
func (c *ELBv2Collector) enrichAccessLogs(ctx context.Context, lb *LoadBalancer) {
	output, err := c.client.DescribeLoadBalancerAttributes(ctx, &elasticloadbalancingv2.DescribeLoadBalancerAttributesInput{
		LoadBalancerArn: awssdk.String(lb.ARN),
	})
	if err != nil {
		return // Fail-safe
	}

	for _, attr := range output.Attributes {
		key := awssdk.ToString(attr.Key)
		val := awssdk.ToString(attr.Value)
		switch key {
		case "access_logs.s3.enabled":
			lb.AccessLogsEnabled = val == statusTrue
		case "deletion_protection.enabled":
			lb.DeletionProtection = val == statusTrue
		case "load_balancing.cross_zone.enabled":
			lb.CrossZoneEnabled = val == statusTrue
		case "routing.http.drop_invalid_header_fields.enabled":
			lb.DropInvalidHeaders = val == statusTrue
		}
	}
}

// isHTTPSEnforced checks if all listeners enforce HTTPS.
// A load balancer enforces HTTPS if every listener is either:
// - An HTTPS/TLS listener, or
// - An HTTP listener that redirects to HTTPS.
func isHTTPSEnforced(listeners []Listener) bool {
	if len(listeners) == 0 {
		return false
	}

	for _, l := range listeners {
		switch l.Protocol {
		case string(elbtypes.ProtocolEnumHttps), string(elbtypes.ProtocolEnumTls):
			continue
		case string(elbtypes.ProtocolEnumHttp):
			if !hasHTTPSRedirect(l) {
				return false
			}
		default:
			// TCP/UDP listeners — not HTTPS-enforced
			return false
		}
	}
	return true
}

// hasHTTPSRedirect checks if an HTTP listener has a redirect-to-HTTPS action.
func hasHTTPSRedirect(l Listener) bool {
	for _, action := range l.DefaultActions {
		if action.Type == string(elbtypes.ActionTypeEnumRedirect) && action.RedirectProtocol == "HTTPS" {
			return true
		}
	}
	return false
}

// CollectEvidence collects ELBv2 load balancers as evidence.
func (c *ELBv2Collector) CollectEvidence(ctx context.Context, accountID string) ([]evidence.Evidence, error) {
	loadBalancers, err := c.CollectLoadBalancers(ctx)
	if err != nil {
		return nil, err
	}

	evidenceList := make([]evidence.Evidence, 0, len(loadBalancers))
	for i := range loadBalancers {
		evidenceList = append(evidenceList, loadBalancers[i].ToEvidence(accountID))
	}
	return evidenceList, nil
}
