# METADATA
# title: CC1.1 - Employee NDA Acknowledgment
# description: Annual employee NDA acknowledgment declaration must be completed
# scope: package
package sigcomply.soc2.cc1_1_employee_nda

metadata := {
	"id": "soc2-cc1.1-employee-nda",
	"name": "Employee NDA Acknowledgment",
	"framework": "soc2",
	"control": "CC1.1",
	"severity": "high",
	"evaluation_mode": "individual",
	"resource_types": ["manual:employee_nda"],
	"category": "hr_governance",
	"remediation": "Declare that all employees have acknowledged the current NDA and code-of-conduct in this period.",
}

# Violation: not uploaded and overdue
violations contains violation if {
	input.resource_type == "manual:employee_nda"
	input.data.status == "not_uploaded"
	input.data.temporal_status == "overdue"
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("Employee NDA acknowledgment for period %s is overdue and not completed", [input.data.period]),
		"details": {
			"evidence_id": input.data.evidence_id,
			"period": input.data.period,
			"temporal_status": input.data.temporal_status,
		},
	}
}

# Violation: declaration not accepted
violations contains violation if {
	input.resource_type == "manual:employee_nda"
	input.data.status == "uploaded"
	input.data.accepted != true
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": "Employee NDA acknowledgment declaration was not accepted",
		"details": {
			"evidence_id": input.data.evidence_id,
			"period": input.data.period,
		},
	}
}

# Violation: hash verification failed
violations contains violation if {
	input.resource_type == "manual:employee_nda"
	input.data.status == "uploaded"
	input.data.hash_verified == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": "Employee NDA acknowledgment evidence failed integrity verification",
		"details": {
			"evidence_id": input.data.evidence_id,
			"period": input.data.period,
		},
	}
}
