# METADATA
# title: CC6.2 - ElastiCache At-Rest Encryption
# description: ElastiCache replication groups should have at-rest encryption enabled
# scope: package
package sigcomply.soc2.cc6_2_elasticache_encryption

metadata := {
	"id": "soc2-cc6.2-elasticache-encryption",
	"name": "ElastiCache At-Rest Encryption",
	"framework": "soc2",
	"control": "CC6.2",
	"severity": "high",
	"evaluation_mode": "individual",
	"resource_types": ["aws:elasticache:replication_group"],
	"remediation": "Enable at-rest encryption for the ElastiCache replication group to protect data stored on disk.",
}

violations contains violation if {
	input.resource_type == "aws:elasticache:replication_group"
	input.data.at_rest_encryption == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("ElastiCache replication group '%s' does not have at-rest encryption enabled", [input.data.replication_group_id]),
		"details": {"replication_group_id": input.data.replication_group_id},
	}
}
