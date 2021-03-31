package query

/*
Query processing involves multiple steps to produce a query to evaluate.

To unify multiple concerns, query processing is abstracted to a sequence of
steps that entail parsing, validity checking, transformation, and conditional
processing logic driven by external options.
*/

// A step performs a transformation on nodes, which may fail.
type Step func(nodes []Node) ([]Node, error)

// A pass is a step that never fails.
type Pass func(nodes []Node) []Node

// sequence sequences zero or more steps to create a single step.
func Sequence(steps ...Step) Step {
	return func(nodes []Node) ([]Node, error) {
		var err error
		for _, step := range steps {
			nodes, err = step(nodes)
			if err != nil {
				return nil, err
			}
		}
		return nodes, nil
	}
}

// succeeds converts a sequence of passes into a single step.
func succeeds(passes ...Pass) Step {
	return func(nodes []Node) ([]Node, error) {
		for _, pass := range passes {
			nodes = pass(nodes)
		}
		return nodes, nil
	}
}

// With returns step if enabled is true. Use it to compose a pipeline that
// conditionally run steps.
func With(enabled bool, step Step) Step {
	if !enabled {
		return identity
	}
	return step
}

// For runs processing steps for a given search type. This includes
// normalization, substitution for whitespace, and pattern labeling.
func For(searchType SearchType) Step {
	var processType Step
	switch searchType {
	case SearchTypeLiteral:
		processType = succeeds(substituteConcat(space))
	case SearchTypeRegex:
		processType = succeeds(escapeParensHeuristic, substituteConcat(fuzzyRegexp))
	case SearchTypeStructural:
		processType = succeeds(labelStructural, ellipsesForHoles, substituteConcat(space))
	}
	normalize := succeeds(LowercaseFieldNames, SubstituteAliases(searchType))
	return Sequence(normalize, processType)
}

// Init creates a step from an input string and search type. It parses the
// initial input string.
func Init(in string, searchType SearchType) Step {
	parser := func([]Node) ([]Node, error) {
		return Parse(in, searchType)
	}
	return Sequence(parser, For(searchType))
}

// InitLiteral is Init where SearchType is Literal.
func InitLiteral(in string) Step {
	return Init(in, SearchTypeLiteral)
}

// InitRegexp is Init where SearchType is Regex.
func InitRegexp(in string) Step {
	return Init(in, SearchTypeRegex)
}

// InitStructural is Init where SearchType is Structural.
func InitStructural(in string) Step {
	return Init(in, SearchTypeStructural)
}

func Run(step Step) ([]Node, error) {
	return step(nil)
}

func Validate(disjuncts [][]Node) error {
	for _, disjunct := range disjuncts {
		if err := validate(disjunct); err != nil {
			return err
		}
	}
	return nil
}

// A basicPass is a transformation on Basic queries.
type basicPass func(Basic) Basic

// MapPlan applies a conversion to all Basic queries in a plan. It expects a
// valid plan. guarantee transformation succeeds.
func MapPlan(plan Plan, pass basicPass) Plan {
	updated := make([]Basic, 0, len(plan))
	for _, query := range plan {
		updated = append(updated, pass(query))
	}
	return Plan(updated)
}

func ToPlan(disjuncts [][]Node) (Plan, error) {
	plan := make([]Basic, 0, len(disjuncts))
	for _, disjunct := range disjuncts {
		basic, err := ToBasicQuery(disjunct)
		if err != nil {
			return nil, err
		}
		plan = append(plan, *basic)
	}
	return plan, nil
}
