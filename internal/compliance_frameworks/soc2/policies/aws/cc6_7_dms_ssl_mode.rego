# METADATA
# title: CC6.7 - DMS Endpoint SSL Mode
# description: DMS endpoints must use SSL/TLS for data in transit
# scope: package
package sigcomply.soc2.cc6_7_dms_ssl_mode

metadata := {
	"id": "soc2-cc6.7-dms-ssl-mode",
	"name": "DMS Endpoint SSL Mode",
	"framework": "soc2",
	"control": "CC6.7",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:dms:endpoint"],
	"remediation": "Modify the DMS endpoint to use an SSL mode other than 'none' (e.g., 'require', 'verify-ca', or 'verify-full').",
	"evidence_type": "automated",
}

violations contains violation if {
	input.resource_type == "aws:dms:endpoint"
	input.data.ssl_mode == "none"
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("DMS endpoint '%s' has SSL mode set to 'none'", [input.data.id]),
		"details": {
			"id": input.data.id,
		},
	}
}
