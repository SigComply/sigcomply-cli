# METADATA
# title: CC6.7 - No IAM Server Certificates
# description: IAM server certificates should not be used; use AWS Certificate Manager (ACM) instead
# scope: package
package sigcomply.soc2.cc6_7_iam_no_server_certificates

metadata := {
	"id": "soc2-cc6.7-iam-no-server-certificates",
	"name": "No IAM Server Certificates",
	"framework": "soc2",
	"control": "CC6.7",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:iam:server-certificate-status"],
	"remediation": "Migrate IAM server certificates to AWS Certificate Manager (ACM) for automated renewal and better security.",
	"evidence_type": "automated",
}

violations contains violation if {
	input.resource_type == "aws:iam:server-certificate-status"
	input.data.has_server_certificates == true
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("Account has %d IAM server certificate(s). Use AWS Certificate Manager (ACM) instead.", [input.data.certificate_count]),
		"details": {
			"certificate_count": input.data.certificate_count,
		},
	}
}
