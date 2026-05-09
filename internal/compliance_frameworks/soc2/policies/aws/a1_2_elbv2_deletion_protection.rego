# METADATA
# title: A1.2 - ELBv2 Deletion Protection Enabled
# description: ELBv2 load balancers should have deletion protection enabled
# scope: package
package sigcomply.soc2.a1_2_elbv2_deletion_protection

metadata := {
	"id": "soc2-a1.2-elbv2-deletion-protection",
	"name": "ELBv2 Deletion Protection Enabled",
	"framework": "soc2",
	"control": "A1.2",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:elbv2:load-balancer"],
	"remediation": "Enable deletion protection on the load balancer to prevent accidental deletion.",
	"evidence_type": "automated",
}

violations contains violation if {
	input.resource_type == "aws:elbv2:load-balancer"
	input.data.deletion_protection == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("ELBv2 load balancer '%s' does not have deletion protection enabled", [input.data.name]),
		"details": {"name": input.data.name, "type": input.data.type},
	}
}
