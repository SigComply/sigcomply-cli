# METADATA
# title: CC6.2 - S3 No ACL-Based Access
# description: S3 buckets should use bucket policies instead of ACLs for access control
# scope: package
package sigcomply.soc2.cc6_2_s3_no_acl

metadata := {
	"id": "soc2-cc6.2-s3-no-acl",
	"name": "S3 No ACL-Based Access",
	"framework": "soc2",
	"control": "CC6.2",
	"severity": "low",
	"evaluation_mode": "individual",
	"resource_types": ["aws:s3:bucket"],
	"remediation": "Enable S3 Object Ownership with BucketOwnerEnforced to disable ACLs: aws s3api put-bucket-ownership-controls --bucket <name> --ownership-controls Rules=[{ObjectOwnership=BucketOwnerEnforced}]",
	"evidence_type": "automated",
}

violations contains violation if {
	input.resource_type == "aws:s3:bucket"
	input.data.acls_enabled == true
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("S3 bucket '%s' has ACLs enabled instead of using bucket policies only", [input.data.bucket_name]),
		"details": {
			"bucket_name": input.data.bucket_name,
			"object_ownership": input.data.object_ownership,
		},
	}
}
