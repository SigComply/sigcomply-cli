# METADATA
# title: CC6.6 - S3 Cross-Account Access Restrictions
# description: S3 bucket policies should restrict access to specific AWS accounts
# scope: package
package sigcomply.soc2.cc6_6_s3_cross_account

metadata := {
	"id": "soc2-cc6.6-s3-cross-account",
	"name": "S3 Cross-Account Access Restricted",
	"framework": "soc2",
	"control": "CC6.6",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:s3:bucket"],
	"remediation": "Review S3 bucket policies granting cross-account access. Ensure access is restricted to known, authorized AWS accounts only.",
	"evidence_type": "automated",
}

violations contains violation if {
	input.resource_type == "aws:s3:bucket"
	input.data.unrestricted_cross_account_access == true
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("S3 bucket '%s' has unrestricted cross-account access in its bucket policy", [input.data.bucket_name]),
		"details": {
			"bucket_name": input.data.bucket_name,
		},
	}
}
