# METADATA
# title: CC6.2 - EFS Encryption at Rest
# description: EFS file systems must have encryption at rest enabled
# scope: package
package sigcomply.soc2.cc6_2_efs_encryption

metadata := {
	"id": "soc2-cc6.2-efs-encryption",
	"name": "EFS Encryption at Rest",
	"framework": "soc2",
	"control": "CC6.2",
	"severity": "high",
	"evaluation_mode": "individual",
	"resource_types": ["aws:efs:file_system"],
	"remediation": "Enable encryption at rest when creating EFS file systems. Existing unencrypted file systems must be recreated with encryption enabled.",
	"evidence_type": "automated",
}

violations contains violation if {
	input.resource_type == "aws:efs:file_system"
	input.data.encrypted == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("EFS file system '%s' does not have encryption at rest enabled", [input.data.file_system_id]),
		"details": {
			"file_system_id": input.data.file_system_id,
			"name": input.data.name,
		},
	}
}
