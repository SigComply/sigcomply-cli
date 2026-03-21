# METADATA
# title: CC6.6 - ElastiCache Transit Encryption
# description: ElastiCache replication groups should have in-transit encryption enabled
# scope: package
package sigcomply.soc2.cc6_6_elasticache_transit_encryption

metadata := {
	"id": "soc2-cc6.6-elasticache-transit-encryption",
	"name": "ElastiCache Transit Encryption",
	"framework": "soc2",
	"control": "CC6.6",
	"severity": "high",
	"evaluation_mode": "individual",
	"resource_types": ["aws:elasticache:replication_group"],
	"remediation": "Enable in-transit encryption for the ElastiCache replication group to protect data during transmission.",
}

violations contains violation if {
	input.resource_type == "aws:elasticache:replication_group"
	input.data.transit_encryption == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("ElastiCache replication group '%s' does not have in-transit encryption enabled", [input.data.replication_group_id]),
		"details": {"replication_group_id": input.data.replication_group_id},
	}
}
