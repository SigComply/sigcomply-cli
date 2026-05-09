# METADATA
# title: CC6.6 - Default Security Group Restrictions
# description: Default security groups should not have any inbound rules allowing traffic
# scope: package
package sigcomply.soc2.cc6_6_default_sg_restrictions

metadata := {
	"id": "soc2-cc6.6-default-sg-restrictions",
	"name": "Default Security Group Restrictions",
	"framework": "soc2",
	"control": "CC6.6",
	"severity": "high",
	"evaluation_mode": "individual",
	"resource_types": ["aws:ec2:security-group"],
	"remediation": "Remove all inbound and outbound rules from the default security group. Use custom security groups for resource access instead.",
	"evidence_type": "automated",
}

violations contains violation if {
	input.resource_type == "aws:ec2:security-group"
	input.data.group_name == "default"
	count(input.data.ingress_rules) > 0
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("Default security group '%s' has %d inbound rules configured", [input.data.group_id, count(input.data.ingress_rules)]),
		"details": {
			"group_id": input.data.group_id,
			"vpc_id": input.data.vpc_id,
			"ingress_rule_count": count(input.data.ingress_rules),
		},
	}
}
