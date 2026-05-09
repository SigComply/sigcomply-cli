# METADATA
# title: CC7.2 - CIS Organizations Changes Alarm
# description: A CloudWatch alarm should be configured for AWS Organizations changes
# scope: package
package sigcomply.soc2.cc7_2_cis_organizations_changes

metadata := {
	"id": "soc2-cc7.2-cis-organizations-changes",
	"name": "CIS Organizations Changes Alarm",
	"framework": "soc2",
	"control": "CC7.2",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:cloudwatch:cis-metric-filter"],
	"remediation": "Create a CloudWatch metric filter and alarm for Organizations changes: aws logs put-metric-filter --log-group-name <cloudtrail-log-group> --filter-name OrganizationsChanges --filter-pattern '{ ($.eventSource = organizations.amazonaws.com) }'",
	"evidence_type": "automated",
}

violations contains violation if {
	input.resource_type == "aws:cloudwatch:cis-metric-filter"
	input.data.filter_name == "organizations_changes"
	input.data.configured == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": "No CloudWatch alarm configured for AWS Organizations changes",
		"details": {
			"filter_name": "organizations_changes",
			"region": input.data.region,
		},
	}
}
