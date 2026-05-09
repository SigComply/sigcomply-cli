# METADATA
# title: CC6.1 - ElastiCache AUTH Token Enabled
# description: ElastiCache replication groups should have AUTH token enabled
# scope: package
package sigcomply.soc2.cc6_1_elasticache_auth

metadata := {
	"id": "soc2-cc6.1-elasticache-auth",
	"name": "ElastiCache AUTH Token Enabled",
	"framework": "soc2",
	"control": "CC6.1",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:elasticache:replication_group"],
	"remediation": "Enable AUTH token (password) for the ElastiCache replication group to require authentication.",
	"evidence_type": "automated",
}

violations contains violation if {
	input.resource_type == "aws:elasticache:replication_group"
	input.data.auth_token_enabled == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("ElastiCache replication group '%s' does not have AUTH token enabled", [input.data.replication_group_id]),
		"details": {"replication_group_id": input.data.replication_group_id},
	}
}
