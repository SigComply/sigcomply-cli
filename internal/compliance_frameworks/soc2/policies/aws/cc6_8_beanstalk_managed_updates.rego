# METADATA
# title: CC6.8 - Elastic Beanstalk Managed Updates
# description: Elastic Beanstalk environments must have managed platform updates enabled
# scope: package
package sigcomply.soc2.cc6_8_beanstalk_managed_updates

metadata := {
	"id": "soc2-cc6.8-beanstalk-managed-updates",
	"name": "Elastic Beanstalk Managed Updates",
	"framework": "soc2",
	"control": "CC6.8",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:elasticbeanstalk:environment"],
	"remediation": "Enable managed platform updates on the Elastic Beanstalk environment by setting ManagedActionsEnabled to true in the aws:elasticbeanstalk:managedactions namespace.",
}

violations contains violation if {
	input.resource_type == "aws:elasticbeanstalk:environment"
	input.data.managed_updates_enabled == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("Elastic Beanstalk environment '%s' does not have managed platform updates enabled", [input.data.environment_name]),
		"details": {"environment_name": input.data.environment_name},
	}
}
