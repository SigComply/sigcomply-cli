# METADATA
# title: CC7.2 - CIS Metric Filter for Route Table Changes
# description: A metric filter and alarm should exist for route table changes
# scope: package
package sigcomply.soc2.cc7_2_cis_route_table_changes

metadata := {
	"id": "soc2-cc7.2-cis-route-table-changes",
	"name": "CIS Alarm - Route Table Changes",
	"framework": "soc2",
	"control": "CC7.2",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:cloudwatch:cis-metric-filter"],
	"remediation": "Create a CloudWatch metric filter for route table changes (CreateRoute, DeleteRoute, ReplaceRoute, etc.) and associate an SNS alarm.",
	"evidence_type": "automated",
}

violations contains violation if {
	input.resource_type == "aws:cloudwatch:cis-metric-filter"
	input.data.filter_name == "route_table_changes"
	input.data.configured == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": "No metric filter and alarm configured for route table changes (CIS 4.13)",
		"details": {
			"cis_control": "4.13",
			"filter_name": "route_table_changes",
		},
	}
}
