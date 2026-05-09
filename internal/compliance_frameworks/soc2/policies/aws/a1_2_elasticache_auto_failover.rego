# METADATA
# title: A1.2 - ElastiCache Automatic Failover Enabled
# description: ElastiCache replication groups should have automatic failover enabled
# scope: package
package sigcomply.soc2.a1_2_elasticache_auto_failover

metadata := {
	"id": "soc2-a1.2-elasticache-auto-failover",
	"name": "ElastiCache Automatic Failover Enabled",
	"framework": "soc2",
	"control": "A1.2",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:elasticache:replication_group"],
	"remediation": "Enable automatic failover for the ElastiCache replication group for high availability.",
	"evidence_type": "automated",
}

violations contains violation if {
	input.resource_type == "aws:elasticache:replication_group"
	input.data.automatic_failover_enabled == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("ElastiCache replication group '%s' does not have automatic failover enabled", [input.data.replication_group_id]),
		"details": {"replication_group_id": input.data.replication_group_id},
	}
}
