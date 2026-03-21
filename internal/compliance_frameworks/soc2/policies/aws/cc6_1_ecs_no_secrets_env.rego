# METADATA
# title: CC6.1 - ECS No Secrets in Environment Variables
# description: ECS task definitions should not contain secrets in environment variables
# scope: package
package sigcomply.soc2.cc6_1_ecs_no_secrets_env

metadata := {
	"id": "soc2-cc6.1-ecs-no-secrets-env",
	"name": "ECS No Secrets in Environment Variables",
	"framework": "soc2",
	"control": "CC6.1",
	"severity": "critical",
	"evaluation_mode": "individual",
	"resource_types": ["aws:ecs:task-definition"],
	"remediation": "Use AWS Secrets Manager or SSM Parameter Store to inject secrets instead of environment variables.",
}

violations contains violation if {
	input.resource_type == "aws:ecs:task-definition"
	input.data.has_secrets_in_env_vars == true
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("ECS task definition '%s' has potential secrets in environment variables", [input.data.family]),
		"details": {
			"family": input.data.family,
		},
	}
}
