# METADATA
# title: CC6.8 - ECS Container Insights
# description: ECS clusters must have Container Insights enabled for monitoring
# scope: package
package sigcomply.soc2.cc6_8_ecs_security

metadata := {
	"id": "soc2-cc6.8-ecs-security",
	"name": "ECS Container Insights Enabled",
	"framework": "soc2",
	"control": "CC6.8",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:ecs:cluster"],
	"remediation": "Enable Container Insights: aws ecs update-cluster-settings --cluster CLUSTER --settings name=containerInsights,value=enabled",
	"evidence_type": "automated",
}

violations contains violation if {
	input.resource_type == "aws:ecs:cluster"
	input.data.container_insights_enabled == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("ECS cluster '%s' does not have Container Insights enabled", [input.data.name]),
		"details": {"name": input.data.name},
	}
}
