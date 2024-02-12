package dns

// Source describes where the data for the answer of a query comes from.
type Source string

// Sources.
const (
	SourceNone          Source = ""
	SourceInternal      Source = "internal"
	SourceResolveConfig Source = "resolve-config"
	SourceForbidden     Source = "forbidden"
	SourceFriend        Source = "friend"
	SourceMapping       Source = "mapping"
)
