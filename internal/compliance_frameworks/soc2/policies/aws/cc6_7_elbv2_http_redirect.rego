# METADATA
# title: CC6.7 - ELBv2 HTTP to HTTPS Redirect
# description: Application Load Balancers should redirect HTTP to HTTPS
# scope: package
package sigcomply.soc2.cc6_7_elbv2_http_redirect

metadata := {
	"id": "soc2-cc6.7-elbv2-http-redirect",
	"name": "ELBv2 HTTP to HTTPS Redirect",
	"framework": "soc2",
	"control": "CC6.7",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:elbv2:load-balancer"],
	"remediation": "Configure HTTP listener to redirect to HTTPS: aws elbv2 create-listener --load-balancer-arn <arn> --protocol HTTP --port 80 --default-actions Type=redirect,RedirectConfig='{Protocol=HTTPS,Port=443,StatusCode=HTTP_301}'",
	"evidence_type": "automated",
}

violations contains violation if {
	input.resource_type == "aws:elbv2:load-balancer"
	input.data.type == "application"
	input.data.has_http_to_https_redirect == false
	input.data.https_enforced == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("ALB '%s' does not redirect HTTP to HTTPS", [input.data.name]),
		"details": {"load_balancer_name": input.data.name},
	}
}
