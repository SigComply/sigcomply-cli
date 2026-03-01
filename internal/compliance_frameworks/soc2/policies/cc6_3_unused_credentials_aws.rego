# METADATA
# title: CC6.3 - Unused AWS Credentials
# description: AWS IAM users with credentials inactive for 90+ days should be investigated
# scope: package
package sigcomply.soc2.cc6_3_unused_aws

metadata := {
	"id": "soc2-cc6.3-unused-credentials-aws",
	"name": "Unused AWS Credentials",
	"framework": "soc2",
	"control": "CC6.3",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:iam:user"],
	"remediation": "Disable or delete AWS IAM credentials that have been inactive for more than 90 days.",
}

# Console user with password inactive for more than 90 days
violations contains violation if {
	input.resource_type == "aws:iam:user"
	input.data.has_login_profile == true
	input.data.password_inactive_days > 90
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("IAM user '%s' has not used console login for %d days", [input.data.user_name, input.data.password_inactive_days]),
		"details": {
			"user_name": input.data.user_name,
			"password_inactive_days": input.data.password_inactive_days,
		},
	}
}

# Active access key not used for more than 90 days
violations contains violation if {
	input.resource_type == "aws:iam:user"
	key := input.data.access_keys[_]
	key.status == "Active"
	key.last_used_days > 90
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("IAM user '%s' has active access key '%s' unused for %d days", [input.data.user_name, key.access_key_id, key.last_used_days]),
		"details": {
			"user_name": input.data.user_name,
			"access_key_id": key.access_key_id,
			"last_used_days": key.last_used_days,
		},
	}
}

# Active access key never used and older than 90 days
violations contains violation if {
	input.resource_type == "aws:iam:user"
	key := input.data.access_keys[_]
	key.status == "Active"
	key.last_used_days == -1
	key.age_days > 90
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("IAM user '%s' has active access key '%s' that was never used (created %d days ago)", [input.data.user_name, key.access_key_id, key.age_days]),
		"details": {
			"user_name": input.data.user_name,
			"access_key_id": key.access_key_id,
			"age_days": key.age_days,
		},
	}
}
