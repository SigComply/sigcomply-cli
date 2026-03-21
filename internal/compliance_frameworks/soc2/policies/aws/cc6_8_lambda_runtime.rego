# METADATA
# title: CC6.8 - Lambda Supported Runtime
# description: Lambda functions must use supported (non-deprecated) runtimes
# scope: package
package sigcomply.soc2.cc6_8_lambda_runtime

metadata := {
	"id": "soc2-cc6.8-lambda-runtime",
	"name": "Lambda Supported Runtime",
	"framework": "soc2",
	"control": "CC6.8",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:lambda:function"],
	"remediation": "Update the Lambda function to use a supported runtime version. Deprecated runtimes no longer receive security patches.",
}

deprecated_runtimes := {
	"nodejs12.x", "nodejs14.x", "nodejs16.x",
	"python3.6", "python3.7", "python3.8",
	"java8", "java8.al2",
	"dotnetcore3.1", "dotnet5.0", "dotnet6",
	"go1.x",
	"ruby2.5", "ruby2.7",
	"provided",
}

violations contains violation if {
	input.resource_type == "aws:lambda:function"
	input.data.runtime != null
	deprecated_runtimes[input.data.runtime]
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("Lambda function '%s' uses deprecated runtime '%s'", [input.data.function_name, input.data.runtime]),
		"details": {
			"function_name": input.data.function_name,
			"runtime": input.data.runtime,
		},
	}
}
