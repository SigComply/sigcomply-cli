# METADATA
# title: A1.2 - FSx Multi-AZ Deployment
# description: FSx file systems should use Multi-AZ deployment for high availability
# scope: package
package sigcomply.soc2.a1_2_fsx_multi_az

metadata := {
	"id": "soc2-a1.2-fsx-multi-az",
	"name": "FSx Multi-AZ Deployment",
	"framework": "soc2",
	"control": "A1.2",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:fsx:filesystem"],
	"remediation": "Deploy FSx file systems with Multi-AZ configuration by selecting a deployment type that spans multiple Availability Zones (e.g., MULTI_AZ_1 for Windows or ONTAP file systems).",
	"evidence_type": "automated",
}

violations contains violation if {
	input.resource_type == "aws:fsx:filesystem"
	input.data.multi_az == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("FSx file system '%s' does not have Multi-AZ deployment enabled", [input.data.file_system_id]),
		"details": {
			"file_system_id": input.data.file_system_id,
			"file_system_type": input.data.file_system_type,
		},
	}
}
