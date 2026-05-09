# METADATA
# title: CC6.2 - RDS Performance Insights Encryption
# description: RDS instances with Performance Insights should use CMK encryption
# scope: package
package sigcomply.soc2.cc6_2_rds_performance_insights_encryption

metadata := {
	"id": "soc2-cc6.2-rds-performance-insights-encryption",
	"name": "RDS Performance Insights Encryption",
	"framework": "soc2",
	"control": "CC6.2",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:rds:instance"],
	"remediation": "Enable Performance Insights with a CMK: aws rds modify-db-instance --db-instance-identifier INSTANCE --enable-performance-insights --performance-insights-kms-key-id KEY_ARN",
	"evidence_type": "automated",
}

violations contains violation if {
	input.resource_type == "aws:rds:instance"
	input.data.performance_insights_encrypted == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("RDS instance '%s' does not have Performance Insights encrypted with a CMK", [input.data.db_instance_id]),
		"details": {"db_instance_id": input.data.db_instance_id},
	}
}
