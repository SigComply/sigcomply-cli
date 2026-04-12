package sigcomply.soc2.p3_1_data_minimization_proof_test

import data.sigcomply.soc2.p3_1_data_minimization_proof

test_overdue if {
	result := p3_1_data_minimization_proof.violations with input as {
		"resource_type": "manual:data_minimization_proof",
		"resource_id": "data_minimization_proof/2026",
		"data": {
			"evidence_id": "data_minimization_proof",
			"type": "declaration",
			"status": "not_uploaded",
			"period": "2026",
			"temporal_status": "overdue",
		},
	}
	count(result) == 1
}

test_accepted if {
	result := p3_1_data_minimization_proof.violations with input as {
		"resource_type": "manual:data_minimization_proof",
		"resource_id": "data_minimization_proof/2026",
		"data": {
			"evidence_id": "data_minimization_proof",
			"type": "declaration",
			"status": "uploaded",
			"period": "2026",
			"temporal_status": "within_window",
			"hash_verified": true,
			"accepted": true,
		},
	}
	count(result) == 0
}

test_unaccepted if {
	result := p3_1_data_minimization_proof.violations with input as {
		"resource_type": "manual:data_minimization_proof",
		"resource_id": "data_minimization_proof/2026",
		"data": {
			"evidence_id": "data_minimization_proof",
			"type": "declaration",
			"status": "uploaded",
			"period": "2026",
			"temporal_status": "within_window",
			"hash_verified": true,
			"accepted": false,
		},
	}
	count(result) == 1
}

test_wrong_resource_type if {
	result := p3_1_data_minimization_proof.violations with input as {
		"resource_type": "aws:iam:user",
		"resource_id": "arn",
		"data": {"status": "not_uploaded", "temporal_status": "overdue"},
	}
	count(result) == 0
}
