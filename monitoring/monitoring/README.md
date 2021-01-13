<!-- Code generated by gomarkdoc. DO NOT EDIT -->

# monitoring

```go
import "github.com/sourcegraph/sourcegraph/monitoring/monitoring"
```

Package monitoring declares types for Sourcegraph's monitoring generator as well as the generator implementation itself\.

To learn more about developing monitoring\, see the guide: https://about.sourcegraph.com/handbook/engineering/observability/monitoring

To learn more about the generator\, see the top\-level program: https://github.com/sourcegraph/sourcegraph/tree/main/monitoring

## Index

- [func Generate(logger log15.Logger, opts GenerateOptions, containers ...*Container) error](<#func-generate>)
- [type Container](<#type-container>)
- [type GenerateOptions](<#type-generateoptions>)
- [type Group](<#type-group>)
- [type Observable](<#type-observable>)
- [type ObservableAlertDefinition](<#type-observablealertdefinition>)
  - [func Alert() *ObservableAlertDefinition](<#func-alert>)
  - [func (a *ObservableAlertDefinition) For(d time.Duration) *ObservableAlertDefinition](<#func-observablealertdefinition-for>)
  - [func (a *ObservableAlertDefinition) Greater(f float64) *ObservableAlertDefinition](<#func-observablealertdefinition-greater>)
  - [func (a *ObservableAlertDefinition) GreaterOrEqual(f float64) *ObservableAlertDefinition](<#func-observablealertdefinition-greaterorequal>)
  - [func (a *ObservableAlertDefinition) Less(f float64) *ObservableAlertDefinition](<#func-observablealertdefinition-less>)
  - [func (a *ObservableAlertDefinition) LessOrEqual(f float64) *ObservableAlertDefinition](<#func-observablealertdefinition-lessorequal>)
- [type ObservableOwner](<#type-observableowner>)
- [type ObservablePanelOptions](<#type-observablepaneloptions>)
  - [func PanelOptions() ObservablePanelOptions](<#func-paneloptions>)
  - [func (p ObservablePanelOptions) Interval(ms int) ObservablePanelOptions](<#func-observablepaneloptions-interval>)
  - [func (p ObservablePanelOptions) LegendFormat(format string) ObservablePanelOptions](<#func-observablepaneloptions-legendformat>)
  - [func (p ObservablePanelOptions) Max(max float64) ObservablePanelOptions](<#func-observablepaneloptions-max>)
  - [func (p ObservablePanelOptions) Min(min float64) ObservablePanelOptions](<#func-observablepaneloptions-min>)
  - [func (p ObservablePanelOptions) MinAuto() ObservablePanelOptions](<#func-observablepaneloptions-minauto>)
  - [func (p ObservablePanelOptions) Unit(t UnitType) ObservablePanelOptions](<#func-observablepaneloptions-unit>)
- [type Row](<#type-row>)
- [type UnitType](<#type-unittype>)


## func [Generate](<https://github.com/sourcegraph/sourcegraph/blob/main/monitoring/monitoring/generator.go#L40>)

```go
func Generate(logger log15.Logger, opts GenerateOptions, containers ...*Container) error
```

Generate is the main Sourcegraph monitoring generator entrypoint\.

## type [Container](<https://github.com/sourcegraph/sourcegraph/blob/main/monitoring/monitoring/monitoring.go#L17-L30>)

Container describes a Docker container to be observed\.

These correspond to dashboards in Grafana\.

```go
type Container struct {
    // Name of the Docker container, e.g. "syntect-server".
    Name string

    // Title of the Docker container, e.g. "Syntect Server".
    Title string

    // Description of the Docker container. It should describe what the container
    // is responsible for, so that the impact of issues in it is clear.
    Description string

    // Groups of observable information about the container.
    Groups []Group
}
```

## type [GenerateOptions](<https://github.com/sourcegraph/sourcegraph/blob/main/monitoring/monitoring/generator.go#L25-L37>)

GenerateOptions declares options for the monitoring generator\.

```go
type GenerateOptions struct {
    // Toggles pruning of dangling generated assets through simple heuristic, should be disabled during builds
    DisablePrune bool
    // Trigger reload of active Prometheus or Grafana instance (requires respective output directories)
    Reload bool

    // Output directory for generated Grafana assets
    GrafanaDir string
    // Output directory for generated Prometheus assets
    PrometheusDir string
    // Output directory for generated documentation
    DocsDir string
}
```

## type [Group](<https://github.com/sourcegraph/sourcegraph/blob/main/monitoring/monitoring/monitoring.go#L418-L433>)

Group describes a group of observable information about a container\.

These correspond to collapsible sections in a Grafana dashboard\.

```go
type Group struct {
    // Title of the group, briefly summarizing what this group is about, or
    // "General" if the group is just about the container in general.
    Title string

    // Hidden indicates whether or not the group should be hidden by default.
    //
    // This should only be used when the dashboard is already full of information
    // and the information presented in this group is unlikely to be the cause of
    // issues and should generally only be inspected in the event that an alert
    // for that information is firing.
    Hidden bool

    // Rows of observable metrics.
    Rows []Row
}
```

## type [Observable](<https://github.com/sourcegraph/sourcegraph/blob/main/monitoring/monitoring/monitoring.go#L481-L587>)

Observable describes a metric about a container that can be observed\. For example\, memory usage\.

These correspond to Grafana graphs\.

```go
type Observable struct {
    // Name is a short and human-readable lower_snake_case name describing what is being observed.
    //
    // It must be unique relative to the service name.
    //
    // Good examples:
    //
    //  github_rate_limit_remaining
    // 	search_error_rate
    //
    // Bad examples:
    //
    //  repo_updater_github_rate_limit
    // 	search_error_rate_over_5m
    //
    Name string

    // Description is a human-readable description of exactly what is being observed.
    //
    // Good examples:
    //
    // 	"remaining GitHub API rate limit quota"
    // 	"number of search errors every 5m"
    //  "90th percentile search request duration over 5m"
    //
    // Bad examples:
    //
    // 	"GitHub rate limit"
    // 	"search errors[5m]"
    // 	"P90 search latency"
    //
    Description string

    // Owner indicates the team that owns this Observable (including its alerts and maintainence).
    Owner ObservableOwner

    // Query is the actual Prometheus query that should be observed.
    Query string

    // DataMustExist indicates if the query must return data.
    //
    // For example, repo_updater_memory_usage should always have data present and an alert should
    // fire if for some reason that query is not returning any data, so this would be set to true.
    // In contrast, search_error_rate would depend on users actually performing searches and we
    // would not want an alert to fire if no data was present, so this will not need to be set.
    DataMustExist bool

    // Warning and Critical alert definitions.
    // Consider adding at least a Warning or Critical alert to each Observable to make it
    // easy to identify when the target of this metric is misbehaving. If no alerts are
    // provided, NoAlert must be set and Interpretation must be provided.
    Warning, Critical *ObservableAlertDefinition

    // NoAlerts must be set by Observables that do not have any alerts.
    // This ensures the omission of alerts is intentional. If set to true, an Interpretation
    // must be provided in place of PossibleSolutions.
    NoAlert bool

    // PossibleSolutions is Markdown describing possible solutions in the event that the
    // alert is firing. This field not required if no alerts are attached to this Observable.
    // If there is no clear potential resolution or there is no alert configured, "none"
    // must be explicitly stated.
    //
    // Use the Interpretation field for additional guidance on understanding this Observable that isn't directly related to solving it.
    // it, the Interpretation field can be provided as well.
    //
    // Contacting support should not be mentioned as part of a possible solution, as it is
    // communicated elsewhere.
    //
    // To make writing the Markdown more friendly in Go, string literals like this:
    //
    // 	Observable{
    // 		PossibleSolutions: `
    // 			- Foobar 'some code'
    // 		`
    // 	}
    //
    // Becomes:
    //
    // 	- Foobar `some code`
    //
    // In other words:
    //
    // 1. The preceding newline is removed.
    // 2. The indentation in the string literal is removed (based on the last line).
    // 3. Single quotes become backticks.
    // 4. The last line (which is all indention) is removed.
    // 5. Non-list items are converted to a list.
    //
    PossibleSolutions string

    // Interpretation is Markdown that can serve as a reference for interpreting this
    // observable. For example, Interpretation could provide guidance on what sort of
    // patterns to look for in the observable's graph and document why this observable is
    // usefule.
    //
    // If no alerts are configured for an observable, this field is required. If the
    // Description is sufficient to capture what this Observable describes, "none" must be
    // explicitly stated.
    //
    // To make writing the Markdown more friendly in Go, string literal processing as
    // PossibleSolutions is provided, though the output is not converted to a list.
    Interpretation string

    // PanelOptions describes some options for how to render the metric in the Grafana panel.
    PanelOptions ObservablePanelOptions
}
```

## type [ObservableAlertDefinition](<https://github.com/sourcegraph/sourcegraph/blob/main/monitoring/monitoring/monitoring.go#L651-L657>)

ObservableAlertDefinition defines when an alert would be considered firing\.

```go
type ObservableAlertDefinition struct {
    // contains filtered or unexported fields
}
```

### func [Alert](<https://github.com/sourcegraph/sourcegraph/blob/main/monitoring/monitoring/monitoring.go#L646>)

```go
func Alert() *ObservableAlertDefinition
```

Alert provides a builder for defining alerting on an Observable\.

### func \(\*ObservableAlertDefinition\) [For](<https://github.com/sourcegraph/sourcegraph/blob/main/monitoring/monitoring/monitoring.go#L689>)

```go
func (a *ObservableAlertDefinition) For(d time.Duration) *ObservableAlertDefinition
```

For indicates how long the given thresholds must be exceeded for this alert to be considered firing\. Defaults to 0s \(immediately alerts when threshold is exceeded\)\.

### func \(\*ObservableAlertDefinition\) [Greater](<https://github.com/sourcegraph/sourcegraph/blob/main/monitoring/monitoring/monitoring.go#L674>)

```go
func (a *ObservableAlertDefinition) Greater(f float64) *ObservableAlertDefinition
```

Greater indicates the alert should fire when strictly greater to this value\.

### func \(\*ObservableAlertDefinition\) [GreaterOrEqual](<https://github.com/sourcegraph/sourcegraph/blob/main/monitoring/monitoring/monitoring.go#L660>)

```go
func (a *ObservableAlertDefinition) GreaterOrEqual(f float64) *ObservableAlertDefinition
```

GreaterOrEqual indicates the alert should fire when greater or equal the given value\.

### func \(\*ObservableAlertDefinition\) [Less](<https://github.com/sourcegraph/sourcegraph/blob/main/monitoring/monitoring/monitoring.go#L681>)

```go
func (a *ObservableAlertDefinition) Less(f float64) *ObservableAlertDefinition
```

Less indicates the alert should fire when strictly less than this value\.

### func \(\*ObservableAlertDefinition\) [LessOrEqual](<https://github.com/sourcegraph/sourcegraph/blob/main/monitoring/monitoring/monitoring.go#L667>)

```go
func (a *ObservableAlertDefinition) LessOrEqual(f float64) *ObservableAlertDefinition
```

LessOrEqual indicates the alert should fire when less than or equal to the given value\.

## type [ObservableOwner](<https://github.com/sourcegraph/sourcegraph/blob/main/monitoring/monitoring/monitoring.go#L466>)

ObservableOwner denotes a team that owns an Observable\. The current teams are described in the handbook: https://about.sourcegraph.com/company/team/org_chart#engineering

```go
type ObservableOwner string
```

```go
const (
    ObservableOwnerSearch       ObservableOwner = "search"
    ObservableOwnerCampaigns    ObservableOwner = "campaigns"
    ObservableOwnerCodeIntel    ObservableOwner = "code-intel"
    ObservableOwnerDistribution ObservableOwner = "distribution"
    ObservableOwnerSecurity     ObservableOwner = "security"
    ObservableOwnerWeb          ObservableOwner = "web"
    ObservableOwnerCloud        ObservableOwner = "cloud"
)
```

## type [ObservablePanelOptions](<https://github.com/sourcegraph/sourcegraph/blob/main/monitoring/monitoring/monitoring.go#L754-L760>)

ObservablePanelOptions declares options for visualizing an Observable\.

```go
type ObservablePanelOptions struct {
    // contains filtered or unexported fields
}
```

### func [PanelOptions](<https://github.com/sourcegraph/sourcegraph/blob/main/monitoring/monitoring/monitoring.go#L763>)

```go
func PanelOptions() ObservablePanelOptions
```

PanelOptions provides a builder for customizing an Observable visualization\.

### func \(ObservablePanelOptions\) [Interval](<https://github.com/sourcegraph/sourcegraph/blob/main/monitoring/monitoring/monitoring.go#L800>)

```go
func (p ObservablePanelOptions) Interval(ms int) ObservablePanelOptions
```

Interval declares the panel's interval in milliseconds\.

### func \(ObservablePanelOptions\) [LegendFormat](<https://github.com/sourcegraph/sourcegraph/blob/main/monitoring/monitoring/monitoring.go#L788>)

```go
func (p ObservablePanelOptions) LegendFormat(format string) ObservablePanelOptions
```

LegendFormat sets the panel's legend format\, which may use Go template strings to select labels from the Prometheus query\.

### func \(ObservablePanelOptions\) [Max](<https://github.com/sourcegraph/sourcegraph/blob/main/monitoring/monitoring/monitoring.go#L781>)

```go
func (p ObservablePanelOptions) Max(max float64) ObservablePanelOptions
```

Max sets the maximum value of the Y axis on the panel\. The default is auto\.

### func \(ObservablePanelOptions\) [Min](<https://github.com/sourcegraph/sourcegraph/blob/main/monitoring/monitoring/monitoring.go#L766>)

```go
func (p ObservablePanelOptions) Min(min float64) ObservablePanelOptions
```

Min sets the minimum value of the Y axis on the panel\. The default is zero\.

### func \(ObservablePanelOptions\) [MinAuto](<https://github.com/sourcegraph/sourcegraph/blob/main/monitoring/monitoring/monitoring.go#L775>)

```go
func (p ObservablePanelOptions) MinAuto() ObservablePanelOptions
```

Min sets the minimum value of the Y axis on the panel to auto\, instead of the default zero\.

This is generally only useful if trying to show negative numbers\.

### func \(ObservablePanelOptions\) [Unit](<https://github.com/sourcegraph/sourcegraph/blob/main/monitoring/monitoring/monitoring.go#L794>)

```go
func (p ObservablePanelOptions) Unit(t UnitType) ObservablePanelOptions
```

Unit sets the panel's Y axis unit type\.

## type [Row](<https://github.com/sourcegraph/sourcegraph/blob/main/monitoring/monitoring/monitoring.go#L450>)

Row of observable metrics\.

These correspond to a row of Grafana graphs\.

```go
type Row []Observable
```

## type [UnitType](<https://github.com/sourcegraph/sourcegraph/blob/main/monitoring/monitoring/monitoring.go#L709>)

UnitType for controlling the unit type display on graphs\.

```go
type UnitType string
```

From https://sourcegraph.com/github.com/grafana/grafana@b63b82976b3708b082326c0b7d42f38d4bc261fa/-/blob/packages/grafana-data/src/valueFormats/categories.ts#L23

```go
const (
    // Number is the default unit type.
    Number UnitType = "short"

    // Milliseconds for representing time.
    Milliseconds UnitType = "dtdurationms"

    // Seconds for representing time.
    Seconds UnitType = "dtdurations"

    // Percentage in the range of 0-100.
    Percentage UnitType = "percent"

    // Bytes in IEC (1024) format, e.g. for representing storage sizes.
    Bytes UnitType = "bytes"

    // BitsPerSecond, e.g. for representing network and disk IO.
    BitsPerSecond UnitType = "bps"
)
```



Generated by [gomarkdoc](<https://github.com/princjef/gomarkdoc>)