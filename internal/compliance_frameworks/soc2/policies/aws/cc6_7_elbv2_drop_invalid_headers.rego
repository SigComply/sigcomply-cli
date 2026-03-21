# METADATA
# title: CC6.7 - ELBv2 Drop Invalid Headers
# description: Application Load Balancers should be configured to drop invalid HTTP headers
# scope: package
package sigcomply.soc2.cc6_7_elbv2_drop_invalid_headers

metadata := {
	"id": "soc2-cc6.7-elbv2-drop-invalid-headers",
	"name": "ELBv2 Drop Invalid Headers",
	"framework": "soc2",
	"control": "CC6.7",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:elbv2:load-balancer"],
	"remediation": "Enable drop invalid headers: aws elbv2 modify-load-balancer-attributes --load-balancer-arn <arn> --attributes Key=routing.http.drop_invalid_header_fields.enabled,Value=true",
}

violations contains violation if {
	input.resource_type == "aws:elbv2:load-balancer"
	input.data.type == "application"
	input.data.drop_invalid_headers == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("ALB '%s' is not configured to drop invalid HTTP headers", [input.data.name]),
		"details": {"load_balancer_name": input.data.name},
	}
}
