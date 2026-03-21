# METADATA
# title: CC6.2 - FSx File System Encryption
# description: FSx file systems should be encrypted at rest
# scope: package
package sigcomply.soc2.cc6_2_fsx_encryption

metadata := {
	"id": "soc2-cc6.2-fsx-encryption",
	"name": "FSx File System Encryption",
	"framework": "soc2",
	"control": "CC6.2",
	"severity": "high",
	"evaluation_mode": "individual",
	"resource_types": ["aws:fsx:filesystem"],
	"remediation": "Enable encryption at rest with a KMS key for the FSx file system.",
}

violations contains violation if {
	input.resource_type == "aws:fsx:filesystem"
	input.data.encrypted == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("FSx file system '%s' is not encrypted at rest", [input.data.file_system_id]),
		"details": {"file_system_id": input.data.file_system_id},
	}
}
