# METADATA
# title: CC7.1 - Elastic Beanstalk Enhanced Health Reporting
# description: Elastic Beanstalk environments must have enhanced health reporting enabled
# scope: package
package sigcomply.soc2.cc7_1_beanstalk_health_reporting

metadata := {
	"id": "soc2-cc7.1-beanstalk-health-reporting",
	"name": "Elastic Beanstalk Enhanced Health Reporting",
	"framework": "soc2",
	"control": "CC7.1",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:elasticbeanstalk:environment"],
	"remediation": "Enable enhanced health reporting on the Elastic Beanstalk environment by setting the SystemType option in the aws:elasticbeanstalk:healthreporting:system namespace to 'enhanced'.",
}

violations contains violation if {
	input.resource_type == "aws:elasticbeanstalk:environment"
	input.data.enhanced_health_reporting == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("Elastic Beanstalk environment '%s' does not have enhanced health reporting enabled", [input.data.environment_name]),
		"details": {"environment_name": input.data.environment_name},
	}
}
