# METADATA
# title: C1.1 - Encryption Coverage
# description: All data storage resources must have encryption enabled
# scope: package
package sigcomply.soc2.c1_1_encryption

metadata := {
	"id": "soc2-c1.1-encryption-coverage",
	"name": "Encryption Coverage",
	"framework": "soc2",
	"control": "C1.1",
	"severity": "high",
	"evaluation_mode": "individual",
	"resource_types": ["aws:s3:bucket", "aws:rds:instance", "aws:ec2:ebs-encryption", "gcp:storage:bucket", "gcp:sql:instance", "gcp:compute:disk"],
	"remediation": "Ensure all data storage resources have encryption at rest enabled.",
	"evidence_type": "automated",
}

# AWS S3
violations contains violation if {
	input.resource_type == "aws:s3:bucket"
	input.data.encryption_enabled == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("S3 bucket '%s' is not encrypted", [input.data.name]),
		"details": {"resource_name": input.data.name},
	}
}

# AWS RDS
violations contains violation if {
	input.resource_type == "aws:rds:instance"
	input.data.storage_encrypted == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("RDS instance '%s' is not encrypted", [input.data.db_instance_id]),
		"details": {"resource_name": input.data.db_instance_id},
	}
}

# AWS EBS
violations contains violation if {
	input.resource_type == "aws:ec2:ebs-encryption"
	input.data.encryption_by_default == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("EBS default encryption not enabled in region '%s'", [input.data.region]),
		"details": {"region": input.data.region},
	}
}
