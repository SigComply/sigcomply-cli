# METADATA
# title: CC7.2 - CIS Metric Filter for Network Gateway Changes
# description: A metric filter and alarm should exist for network gateway changes
# scope: package
package sigcomply.soc2.cc7_2_cis_network_gateway_changes

metadata := {
	"id": "soc2-cc7.2-cis-network-gateway-changes",
	"name": "CIS Alarm - Network Gateway Changes",
	"framework": "soc2",
	"control": "CC7.2",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:cloudwatch:cis-metric-filter"],
	"remediation": "Create a CloudWatch metric filter for network gateway changes (CreateCustomerGateway, DeleteCustomerGateway, AttachInternetGateway, etc.) and associate an SNS alarm.",
	"evidence_type": "automated",
}

violations contains violation if {
	input.resource_type == "aws:cloudwatch:cis-metric-filter"
	input.data.filter_name == "network_gateway_changes"
	input.data.configured == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": "No metric filter and alarm configured for network gateway changes (CIS 4.12)",
		"details": {
			"cis_control": "4.12",
			"filter_name": "network_gateway_changes",
		},
	}
}
