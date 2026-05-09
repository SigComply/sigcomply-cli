# METADATA
# title: CC6.2 - S3 Account-Level Public Access Block
# description: Account-level S3 public access block must be fully enabled
# scope: package
package sigcomply.soc2.cc6_2_s3_account_public_access

metadata := {
	"id": "soc2-cc6.2-s3-account-public-access",
	"name": "S3 Account Public Access Blocked",
	"framework": "soc2",
	"control": "CC6.2",
	"severity": "high",
	"evaluation_mode": "individual",
	"resource_types": ["aws:s3control:account-public-access"],
	"remediation": "Enable account-level public access block: aws s3control put-public-access-block --account-id ACCOUNT_ID --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true",
	"evidence_type": "automated",
}

violations contains violation if {
	input.resource_type == "aws:s3control:account-public-access"
	input.data.all_blocked == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": "Account-level S3 public access block is not fully enabled",
		"details": {
			"block_public_acls": input.data.block_public_acls,
			"block_public_policy": input.data.block_public_policy,
			"ignore_public_acls": input.data.ignore_public_acls,
			"restrict_public_buckets": input.data.restrict_public_buckets,
		},
	}
}
