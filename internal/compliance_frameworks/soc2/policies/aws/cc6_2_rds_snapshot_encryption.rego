# METADATA
# title: CC6.2 - RDS Snapshot Encryption
# description: RDS snapshots should be encrypted at rest
# scope: package
package sigcomply.soc2.cc6_2_rds_snapshot_encryption

metadata := {
	"id": "soc2-cc6.2-rds-snapshot-encryption",
	"name": "RDS Snapshot Encryption",
	"framework": "soc2",
	"control": "CC6.2",
	"severity": "high",
	"evaluation_mode": "individual",
	"resource_types": ["aws:rds:snapshot"],
	"remediation": "Create encrypted snapshots from encrypted RDS instances. Copy unencrypted snapshots to encrypted ones using a KMS key.",
}

violations contains violation if {
	input.resource_type == "aws:rds:snapshot"
	input.data.encrypted == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("RDS snapshot '%s' is not encrypted", [input.data.snapshot_id]),
		"details": {
			"snapshot_id": input.data.snapshot_id,
			"db_instance_id": input.data.db_instance_id,
		},
	}
}
