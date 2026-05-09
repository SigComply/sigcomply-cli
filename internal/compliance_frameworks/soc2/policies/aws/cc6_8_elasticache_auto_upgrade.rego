# METADATA
# title: CC6.8 - ElastiCache Auto Minor Version Upgrade
# description: ElastiCache replication groups must have automatic minor version upgrades enabled
# scope: package
package sigcomply.soc2.cc6_8_elasticache_auto_upgrade

metadata := {
	"id": "soc2-cc6.8-elasticache-auto-upgrade",
	"name": "ElastiCache Auto Minor Version Upgrade",
	"framework": "soc2",
	"control": "CC6.8",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:elasticache:replication_group"],
	"remediation": "Enable automatic minor version upgrades for ElastiCache clusters to receive security patches automatically.",
	"evidence_type": "automated",
}

violations contains violation if {
	input.resource_type == "aws:elasticache:replication_group"
	input.data.auto_minor_version_upgrade == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("ElastiCache replication group '%s' does not have automatic minor version upgrades enabled", [input.data.replication_group_id]),
		"details": {
			"replication_group_id": input.data.replication_group_id,
		},
	}
}
