package rules

import (
	"fmt"
	"strings"

	"github.com/terraform-linters/tflint-plugin-sdk/hclext"
	"github.com/terraform-linters/tflint-plugin-sdk/logger"
	"github.com/terraform-linters/tflint-plugin-sdk/tflint"
)

// OktaGroupNamePrefixRule checks if the 'name' attribute of an okta_group resource
// starts with the required prefix "terraform-".
type OktaGroupNamePrefixRule struct {
	tflint.DefaultRule
	resourceType  string
	attributeName string
	prefix        string
}

// NewOktaGroupNamePrefixRule creates a new instance of the rule with defined constraints.
func NewOktaGroupNamePrefixRule() *OktaGroupNamePrefixRule {
	return &OktaGroupNamePrefixRule{
		resourceType:  "okta_group",
		attributeName: "name",
		prefix:        "terraform-",
	}
}

// Name returns the rule's name.
func (r *OktaGroupNamePrefixRule) Name() string {
	return "okta_group_name_prefix"
}

// Enabled returns whether the rule is enabled by default.
func (r *OktaGroupNamePrefixRule) Enabled() bool {
	return true
}

// Severity returns the rule's severity.
func (r *OktaGroupNamePrefixRule) Severity() tflint.Severity {
	return tflint.ERROR
}

// Check contains the core logic for checking the group name prefix.
func (r *OktaGroupNamePrefixRule) Check(runner tflint.Runner) error {
	logger.Debug(fmt.Sprintf("checking %s rule", r.Name()))

	// 1. Get all okta_group resources, requesting only the 'name' attribute.
	resources, err := runner.GetResourceContent(r.resourceType, &hclext.BodySchema{
		Attributes: []hclext.AttributeSchema{{Name: r.attributeName}},
	}, nil)
	if err != nil {
		return err
	}

	// 2. Iterate through each okta_group resource block found.
	for _, resource := range resources.Blocks {
		attribute, exists := resource.Body.Attributes[r.attributeName]
		if !exists {
			// Skip if the 'name' attribute is not explicitly set (e.g., using a computed value).
			continue
		}

		// 3. Evaluate the attribute's HCL expression to get the string value.
		err := runner.EvaluateExpr(attribute.Expr, func(groupName string) error {
			// 4. Check if the string value starts with the required prefix.
			if !strings.HasPrefix(groupName, r.prefix) {
				// 5. If it does not start with the prefix, emit an issue (error).
				issueMsg := fmt.Sprintf("Okta group name must start with '%s'", r.prefix)
				err = runner.EmitIssue(r, issueMsg, attribute.Range)
				if err != nil {
					return err
				}
			}
			return nil
		}, nil)

		if err != nil {
			return err
		}
	}

	return nil
}
