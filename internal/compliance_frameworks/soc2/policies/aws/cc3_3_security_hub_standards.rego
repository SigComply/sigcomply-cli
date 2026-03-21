# METADATA
# title: CC3.3 - Security Hub Standards Enabled
# description: Security Hub should have FSBP and CIS standards enabled for comprehensive security assessment
# scope: package
package sigcomply.soc2.cc3_3_security_hub_standards

metadata := {
	"id": "soc2-cc3.3-security-hub-standards",
	"name": "Security Hub Standards Enabled",
	"framework": "soc2",
	"control": "CC3.3",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:securityhub:hub"],
	"remediation": "Enable security standards in Security Hub: aws securityhub batch-enable-standards --standards-subscription-requests",
}

# Violation: Security Hub disabled
violations contains violation if {
	input.resource_type == "aws:securityhub:hub"
	input.data.enabled == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("Security Hub is not enabled in region '%s'", [input.data.region]),
		"details": {
			"region": input.data.region,
		},
	}
}

# Violation: FSBP not enabled
violations contains violation if {
	input.resource_type == "aws:securityhub:hub"
	input.data.enabled == true
	input.data.has_fsbp == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("Security Hub in region '%s' does not have AWS Foundational Security Best Practices standard enabled", [input.data.region]),
		"details": {
			"region": input.data.region,
			"missing_standard": "FSBP",
		},
	}
}

# Violation: CIS not enabled
violations contains violation if {
	input.resource_type == "aws:securityhub:hub"
	input.data.enabled == true
	input.data.has_cis == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("Security Hub in region '%s' does not have CIS AWS Foundations Benchmark standard enabled", [input.data.region]),
		"details": {
			"region": input.data.region,
			"missing_standard": "CIS",
		},
	}
}
