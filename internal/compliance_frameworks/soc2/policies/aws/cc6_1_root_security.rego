# METADATA
# title: CC6.1 - Root Account Security
# description: Root/super admin account must have MFA enabled and no access keys
# scope: package
package sigcomply.soc2.cc6_1_root

metadata := {
	"id": "soc2-cc6.1-root-security",
	"name": "Root Account Security",
	"framework": "soc2",
	"control": "CC6.1",
	"severity": "critical",
	"evaluation_mode": "individual",
	"resource_types": ["aws:iam:root-account"],
	"remediation": "Enable MFA on the root account and delete all root access keys. Use IAM users for daily operations.",
	"evidence_type": "automated",
}

violations contains violation if {
	input.resource_type == "aws:iam:root-account"
	input.data.account_mfa_enabled == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": "Root account does not have MFA enabled",
		"details": {},
	}
}

violations contains violation if {
	input.resource_type == "aws:iam:root-account"
	input.data.account_access_keys_present > 0
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("Root account has %d access key(s). Remove all root access keys.", [input.data.account_access_keys_present]),
		"details": {
			"access_keys_present": input.data.account_access_keys_present,
		},
	}
}
