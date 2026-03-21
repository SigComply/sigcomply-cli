# METADATA
# title: CC7.5 - EBS Volumes Have Snapshots
# description: EBS volumes should have snapshots for recovery purposes
# scope: package
package sigcomply.soc2.cc7_5_ebs_snapshots_exist

metadata := {
	"id": "soc2-cc7.5-ebs-snapshots-exist",
	"name": "EBS Volumes Have Snapshots",
	"framework": "soc2",
	"control": "CC7.5",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:ec2:volume"],
	"remediation": "Create EBS snapshots for the volume to enable recovery.",
}

violations contains violation if {
	input.resource_type == "aws:ec2:volume"
	input.data.has_snapshots == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("EBS volume '%s' does not have any snapshots for recovery", [input.resource_id]),
		"details": {},
	}
}
