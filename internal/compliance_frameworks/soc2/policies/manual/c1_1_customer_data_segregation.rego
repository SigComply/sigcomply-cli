# METADATA
# title: C1.1 - Customer Data Segregation Attestation
# description: Annual customer data segregation declaration must be completed
# scope: package
package sigcomply.soc2.c1_1_customer_data_segregation

metadata := {
	"id": "soc2-c1.1-customer-data-segregation",
	"name": "Customer Data Segregation Attestation",
	"framework": "soc2",
	"control": "C1.1",
	"severity": "high",
	"evaluation_mode": "individual",
	"resource_types": ["manual:customer_data_segregation"],
	"category": "data_protection",
	"remediation": "Declare that customer data is logically or physically segregated and that controls prevent cross-tenant access.",
	"evidence_type": "manual",
}

violations contains violation if {
	input.resource_type == "manual:customer_data_segregation"
	input.data.status == "not_uploaded"
	input.data.temporal_status == "overdue"
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("Customer Data Segregation Attestation for period %s is overdue and not uploaded", [input.data.period]),
		"details": {
			"evidence_id": input.data.evidence_id,
			"period": input.data.period,
			"temporal_status": input.data.temporal_status,
		},
	}
}
