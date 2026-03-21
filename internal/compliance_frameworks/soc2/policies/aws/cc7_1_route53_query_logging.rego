# METADATA
# title: CC7.1 - Route53 Query Logging
# description: Public Route53 hosted zones must have query logging enabled for security monitoring
# scope: package
package sigcomply.soc2.cc7_1_route53_query_logging

metadata := {
	"id": "soc2-cc7.1-route53-query-logging",
	"name": "Route53 Query Logging Enabled",
	"framework": "soc2",
	"control": "CC7.1",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:route53:hosted-zone"],
	"remediation": "Enable query logging for public Route53 hosted zones: aws route53 create-query-logging-config --hosted-zone-id ZONE_ID --cloud-watch-logs-log-group-arn LOG_GROUP_ARN",
}

violations contains violation if {
	input.resource_type == "aws:route53:hosted-zone"
	input.data.is_private == false
	input.data.query_logging == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("Route53 hosted zone '%s' does not have query logging enabled", [input.data.zone_name]),
		"details": {
			"zone_name": input.data.zone_name,
			"zone_id": input.data.zone_id,
		},
	}
}
