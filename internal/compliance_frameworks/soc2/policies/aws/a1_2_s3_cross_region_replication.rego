# METADATA
# title: A1.2 - S3 Cross-Region Replication
# description: S3 buckets should have cross-region replication enabled for disaster recovery
# scope: package
package sigcomply.soc2.a1_2_s3_cross_region_replication

metadata := {
	"id": "soc2-a1.2-s3-cross-region-replication",
	"name": "S3 Cross-Region Replication",
	"framework": "soc2",
	"control": "A1.2",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:s3:bucket"],
	"remediation": "Enable cross-region replication: aws s3api put-bucket-replication --bucket <bucket> --replication-configuration file://replication.json",
}

violations contains violation if {
	input.resource_type == "aws:s3:bucket"
	input.data.replication_enabled == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("S3 bucket '%s' does not have cross-region replication enabled", [input.data.name]),
		"details": {
			"bucket_name": input.data.name,
		},
	}
}
