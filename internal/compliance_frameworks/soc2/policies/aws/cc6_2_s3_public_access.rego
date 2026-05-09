# METADATA
# title: CC6.2 - S3 Public Access Blocked
# description: S3 buckets must have public access blocked
# scope: package
package sigcomply.soc2.cc6_2_s3_public

metadata := {
	"id": "soc2-cc6.2-s3-public-access",
	"name": "S3 Public Access Blocked",
	"framework": "soc2",
	"control": "CC6.2",
	"severity": "high",
	"evaluation_mode": "individual",
	"resource_types": ["aws:s3:bucket"],
	"remediation": "Enable S3 Block Public Access at the bucket level: aws s3api put-public-access-block",
	"evidence_type": "automated",
}

violations contains violation if {
	input.resource_type == "aws:s3:bucket"
	input.data.public_access_blocked == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("S3 bucket '%s' does not have public access blocked", [input.data.name]),
		"details": {
			"bucket_name": input.data.name,
		},
	}
}
