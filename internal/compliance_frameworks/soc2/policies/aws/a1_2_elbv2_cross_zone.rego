# METADATA
# title: A1.2 - ELBv2 Cross-Zone Load Balancing
# description: ELBv2 load balancers should have cross-zone load balancing enabled
# scope: package
package sigcomply.soc2.a1_2_elbv2_cross_zone

metadata := {
	"id": "soc2-a1.2-elbv2-cross-zone",
	"name": "ELBv2 Cross-Zone Load Balancing",
	"framework": "soc2",
	"control": "A1.2",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:elbv2:load-balancer"],
	"remediation": "Enable cross-zone load balancing to distribute traffic evenly across all registered targets in all enabled Availability Zones.",
}

violations contains violation if {
	input.resource_type == "aws:elbv2:load-balancer"
	input.data.cross_zone_enabled == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("ELBv2 load balancer '%s' does not have cross-zone load balancing enabled", [input.data.name]),
		"details": {"name": input.data.name, "type": input.data.type},
	}
}
