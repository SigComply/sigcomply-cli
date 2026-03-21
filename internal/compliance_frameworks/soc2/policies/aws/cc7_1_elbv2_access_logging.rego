# METADATA
# title: CC7.1 - ELBv2 Access Logging
# description: ELBv2 load balancers should have access logging enabled
# scope: package
package sigcomply.soc2.cc7_1_elbv2_access_logging

metadata := {
	"id": "soc2-cc7.1-elbv2-access-logging",
	"name": "ELBv2 Access Logging",
	"framework": "soc2",
	"control": "CC7.1",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:elbv2:load-balancer"],
	"remediation": "Enable access logging for the load balancer by configuring an S3 bucket to receive access logs.",
}

violations contains violation if {
	input.resource_type == "aws:elbv2:load-balancer"
	input.data.access_logs_enabled == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("ELBv2 load balancer '%s' does not have access logging enabled", [input.data.name]),
		"details": {
			"name": input.data.name,
			"type": input.data.type,
		},
	}
}
