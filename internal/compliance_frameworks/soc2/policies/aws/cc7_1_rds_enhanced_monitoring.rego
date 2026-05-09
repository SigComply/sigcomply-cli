# METADATA
# title: CC7.1 - RDS Enhanced Monitoring
# description: RDS instances should have Enhanced Monitoring enabled for OS-level metrics
# scope: package
package sigcomply.soc2.cc7_1_rds_enhanced_monitoring

metadata := {
	"id": "soc2-cc7.1-rds-enhanced-monitoring",
	"name": "RDS Enhanced Monitoring",
	"framework": "soc2",
	"control": "CC7.1",
	"severity": "low",
	"evaluation_mode": "individual",
	"resource_types": ["aws:rds:instance"],
	"remediation": "Enable Enhanced Monitoring on the RDS instance to collect OS-level metrics at granular intervals.",
	"evidence_type": "automated",
}

violations contains violation if {
	input.resource_type == "aws:rds:instance"
	input.data.enhanced_monitoring_enabled == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("RDS instance '%s' does not have Enhanced Monitoring enabled", [input.data.db_instance_id]),
		"details": {"db_instance_id": input.data.db_instance_id},
	}
}
