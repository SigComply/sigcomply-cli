# METADATA
# title: CC6.7 - S3 HTTPS Enforcement
# description: S3 bucket policies should deny non-HTTPS requests
# scope: package
package sigcomply.soc2.cc6_7_s3_https

metadata := {
	"id": "soc2-cc6.7-s3-https",
	"name": "S3 HTTPS Enforcement",
	"framework": "soc2",
	"control": "CC6.7",
	"severity": "high",
	"evaluation_mode": "individual",
	"resource_types": ["aws:s3:bucket"],
	"remediation": "Add a bucket policy that denies requests where aws:SecureTransport is false.",
}

violations contains violation if {
	input.resource_type == "aws:s3:bucket"
	input.data.has_ssl_enforcement == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("S3 bucket '%s' does not enforce HTTPS-only access via bucket policy", [input.data.name]),
		"details": {
			"bucket_name": input.data.name,
			"bucket_policy_exists": input.data.bucket_policy_exists,
		},
	}
}
