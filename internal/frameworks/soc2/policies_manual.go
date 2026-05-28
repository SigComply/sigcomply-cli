package soc2

import "github.com/sigcomply/sigcomply-cli/internal/core"

// manualPolicies returns every manual-evidence SOC 2 policy. Each maps
// to a catalog entry (see ManualCatalog) that resolves the expected PDF
// upload path. The catalog ID equals the descriptive suffix of the
// policy ID.
func manualPolicies() []core.Policy {
	return []core.Policy{
		// CC1 — Control environment.
		manualPolicy{id: "soc2.cc1.1.security_awareness_training", control: "CC1.1", cadence: "annual", catalog: "security_awareness_training", desc: "Employees complete security awareness training.", rem: "Upload evidence of completed security awareness training."}.policy(),
		manualPolicy{id: "soc2.cc1.1.code_of_conduct_acknowledgment", control: "CC1.1", cadence: "annual", catalog: "code_of_conduct_acknowledgment", desc: "Employees acknowledge the code of conduct.", rem: "Upload signed code-of-conduct acknowledgements."}.policy(),
		manualPolicy{id: "soc2.cc1.2.board_security_oversight", control: "CC1.2", cadence: "annual", catalog: "board_security_oversight", desc: "The board exercises security oversight.", rem: "Upload board/exec security review minutes."}.policy(),
		manualPolicy{id: "soc2.cc1.3.org_chart_security_roles", control: "CC1.3", cadence: "annual", catalog: "org_chart_security_roles", desc: "An org chart documents security responsibilities.", rem: "Upload an org chart showing security roles."}.policy(),
		manualPolicy{id: "soc2.cc1.4.background_check_policy", control: "CC1.4", cadence: "annual", catalog: "background_check_policy", desc: "A background-check process is documented.", rem: "Upload the background-check policy."}.policy(),

		// CC2 — Communication and information.
		manualPolicy{id: "soc2.cc2.1.information_security_policy", control: "CC2.1", cadence: "annual", catalog: "information_security_policy", desc: "A written information security policy exists.", rem: "Upload the approved information security policy."}.policy(),
		manualPolicy{id: "soc2.cc2.2.internal_security_communication", control: "CC2.2", cadence: "annual", catalog: "internal_security_communication", desc: "Security responsibilities are communicated internally.", rem: "Upload evidence of internal security communications."}.policy(),

		// CC3 — Risk assessment.
		manualPolicy{id: "soc2.cc3.1.risk_assessment", control: "CC3.1", cadence: "annual", catalog: "risk_assessment", desc: "An annual risk assessment is performed.", rem: "Upload the latest risk assessment."}.policy(),
		manualPolicy{id: "soc2.cc3.2.fraud_risk_assessment", control: "CC3.2", cadence: "annual", catalog: "fraud_risk_assessment", desc: "Fraud risk is assessed.", rem: "Upload the fraud risk assessment."}.policy(),

		// CC4 — Monitoring activities.
		manualPolicy{id: "soc2.cc4.1.control_monitoring", control: "CC4.1", cadence: "quarterly", catalog: "control_monitoring", desc: "Controls are monitored on an ongoing basis.", rem: "Upload evidence of ongoing control monitoring."}.policy(),

		// CC5 — Control activities.
		manualPolicy{id: "soc2.cc5.1.control_selection_rationale", control: "CC5.1", cadence: "annual", catalog: "control_selection_rationale", desc: "Control design rationale is documented.", rem: "Upload the control selection rationale."}.policy(),
		manualPolicy{id: "soc2.cc5.3.technology_controls_deployment", control: "CC5.3", cadence: "annual", catalog: "technology_controls_deployment", desc: "Technology controls are deployed per policy.", rem: "Upload evidence of technology control deployment."}.policy(),

		// CC6 — Logical access (manual portions).
		manualPolicy{id: "soc2.cc6.3.access_review_quarterly", control: "CC6.3", cadence: "quarterly", catalog: "access_review_quarterly", desc: "A quarterly user access review is performed and signed.", rem: "Upload the signed quarterly access review."}.policy(),
		manualPolicy{id: "soc2.cc6.5.termination_access_removal_process", control: "CC6.5", cadence: "annual", catalog: "termination_process_documented", desc: "An offboarding access-removal process is documented.", rem: "Upload the user offboarding procedure."}.policy(),
		manualPolicy{id: "soc2.cc6.1.privileged_access_policy", control: "CC6.1", cadence: "annual", catalog: "privileged_access_policy", desc: "A privileged access management policy exists.", rem: "Upload the privileged access management policy."}.policy(),
		manualPolicy{id: "soc2.cc6.2.user_provisioning_process", control: "CC6.2", cadence: "annual", catalog: "user_provisioning_process", desc: "A user provisioning/onboarding SOP exists.", rem: "Upload the user provisioning procedure."}.policy(),
		manualPolicy{id: "soc2.cc6.6.network_segmentation_policy", control: "CC6.6", cadence: "annual", catalog: "network_segmentation_policy", desc: "A network segmentation policy exists.", rem: "Upload the network segmentation policy."}.policy(),
		manualPolicy{id: "soc2.cc6.6.firewall_review_policy", control: "CC6.6", cadence: "annual", catalog: "firewall_review_policy", desc: "A firewall-rule review process is documented.", rem: "Upload the firewall review policy."}.policy(),
		manualPolicy{id: "soc2.cc6.7.data_classification_policy", control: "CC6.7", cadence: "annual", catalog: "data_classification_policy", desc: "A data classification policy exists.", rem: "Upload the data classification policy."}.policy(),

		// CC7 — System operations (manual portions).
		manualPolicy{id: "soc2.cc7.1.log_review_process", control: "CC7.1", cadence: "annual", catalog: "log_review_process", desc: "A log review and alerting process is documented.", rem: "Upload the log review process."}.policy(),
		manualPolicy{id: "soc2.cc7.3.incident_response_plan", control: "CC7.3", cadence: "annual", catalog: "incident_response_plan", desc: "An incident response plan exists.", rem: "Upload the incident response plan."}.policy(),
		manualPolicy{id: "soc2.cc7.3.incident_response_tested", control: "CC7.3", cadence: "annual", catalog: "incident_response_tested", desc: "The incident response plan is tested.", rem: "Upload incident response test results."}.policy(),
		manualPolicy{id: "soc2.cc7.3.security_monitoring_policy", control: "CC7.3", cadence: "annual", catalog: "security_monitoring_policy", desc: "A security monitoring and alerting policy exists.", rem: "Upload the security monitoring policy."}.policy(),
		manualPolicy{id: "soc2.cc7.4.vulnerability_disclosure_policy", control: "CC7.4", cadence: "annual", catalog: "vulnerability_disclosure_policy", desc: "A vulnerability disclosure policy exists.", rem: "Upload the vulnerability disclosure policy."}.policy(),

		// CC8 — Change management (manual portions).
		manualPolicy{id: "soc2.cc8.1.change_management_policy", control: "CC8.1", cadence: "annual", catalog: "change_management_policy", desc: "A change management policy exists.", rem: "Upload the change management policy."}.policy(),
		manualPolicy{id: "soc2.cc8.1.security_sdlc_process", control: "CC8.1", cadence: "annual", catalog: "security_sdlc_process", desc: "A secure SDLC process is documented.", rem: "Upload the secure SDLC process."}.policy(),
		manualPolicy{id: "soc2.cc8.1.penetration_test_annual", control: "CC8.1", cadence: "annual", catalog: "penetration_test_annual", desc: "An annual penetration test is performed.", rem: "Upload the latest penetration test report."}.policy(),
		manualPolicy{id: "soc2.cc8.1.vulnerability_management_policy", control: "CC8.1", cadence: "annual", catalog: "vulnerability_management_policy", desc: "A vulnerability management policy exists.", rem: "Upload the vulnerability management policy."}.policy(),
		manualPolicy{id: "soc2.cc8.1.code_review_policy", control: "CC8.1", cadence: "annual", catalog: "code_review_policy", desc: "Code review requirements are documented.", rem: "Upload the code review policy."}.policy(),

		// CC9 — Vendor / third-party risk.
		manualPolicy{id: "soc2.cc9.1.vendor_risk_assessment", control: "CC9.1", cadence: "annual", catalog: "vendor_risk_assessment", desc: "Third-party / vendor risk is assessed.", rem: "Upload the vendor risk assessment."}.policy(),
		manualPolicy{id: "soc2.cc9.1.due_diligence_process", control: "CC9.1", cadence: "annual", catalog: "due_diligence_process", desc: "A vendor due-diligence process is documented.", rem: "Upload the vendor due-diligence process."}.policy(),
		manualPolicy{id: "soc2.cc9.2.vendor_contracts_reviewed", control: "CC9.2", cadence: "annual", catalog: "vendor_contracts_reviewed", desc: "Vendor contracts include security clauses.", rem: "Upload reviewed vendor contracts with security clauses."}.policy(),

		// A1 — Availability (manual portions).
		manualPolicy{id: "soc2.a1.2.business_continuity_plan", control: "A1.2", cadence: "annual", catalog: "business_continuity_plan", desc: "A business continuity plan exists.", rem: "Upload the business continuity plan."}.policy(),
		manualPolicy{id: "soc2.a1.3.recovery_procedures_tested", control: "A1.3", cadence: "annual", catalog: "recovery_procedures_tested", desc: "Disaster-recovery procedures are tested.", rem: "Upload DR/recovery test results."}.policy(),

		// C1 — Confidentiality (manual portions).
		manualPolicy{id: "soc2.c1.2.data_retention_policy", control: "C1.2", cadence: "annual", catalog: "data_retention_policy", desc: "A data retention policy exists.", rem: "Upload the data retention policy."}.policy(),
		manualPolicy{id: "soc2.c1.3.nda_policy", control: "C1.3", cadence: "annual", catalog: "nda_policy", desc: "An NDA policy and template exist.", rem: "Upload the NDA policy and template."}.policy(),

		// P-series — Privacy.
		manualPolicy{id: "soc2.p1.1.privacy_notice", control: "P1.1", cadence: "annual", catalog: "privacy_notice", desc: "A privacy notice is published.", rem: "Upload the privacy notice."}.policy(),
		manualPolicy{id: "soc2.p3.1.data_collection_policy", control: "P3.1", cadence: "annual", catalog: "data_collection_policy", desc: "A data collection and use policy exists.", rem: "Upload the data collection policy."}.policy(),
		manualPolicy{id: "soc2.p6.1.data_retention_disposal", control: "P6.1", cadence: "annual", catalog: "data_retention_disposal", desc: "A data retention and disposal policy exists.", rem: "Upload the data retention and disposal policy."}.policy(),

		// PI1 — Processing integrity.
		manualPolicy{id: "soc2.pi1.1.processing_integrity_policy", control: "PI1.1", cadence: "annual", catalog: "processing_integrity_policy", desc: "Processing integrity is documented.", rem: "Upload the processing integrity documentation."}.policy(),
	}
}
