# METADATA
# title: CC6.1 - Root Account Hardware MFA
# description: Root account should use a hardware MFA device for stronger protection
# scope: package
package sigcomply.soc2.cc6_1_root_hardware_mfa

metadata := {
	"id": "soc2-cc6.1-root-hardware-mfa",
	"name": "Root Account Hardware MFA",
	"framework": "soc2",
	"control": "CC6.1",
	"severity": "high",
	"evaluation_mode": "individual",
	"resource_types": ["aws:iam:root-account"],
	"remediation": "Configure a hardware MFA device for the root account. Hardware MFA (YubiKey, Gemalto) provides stronger security than virtual MFA.",
	"evidence_type": "automated",
}

violations contains violation if {
	input.resource_type == "aws:iam:root-account"
	input.data.mfa_enabled == true
	input.data.hardware_mfa == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": "Root account uses virtual MFA instead of hardware MFA device",
		"details": {
			"mfa_type": "virtual",
		},
	}
}
