package mgr

import (
	"maps"
	"slices"
	"sync"
	"time"
)

const keepResolvedAlertsFor = 10 * time.Minute

// AlertMgr manages reported alerts.
type AlertMgr struct {
	alerts     map[string]*Alert
	alertsLock sync.Mutex

	alertEvents *EventMgr[AlertUpdate]

	mgr *Manager
}

// Alert describes a reported alert by a manager or module.
type Alert struct {
	// ID is unique ID for this alert.
	// The same alert should use the same ID across time.
	ID string

	// Name is a human comprehensible name of the alert.
	Name string

	// Message describes the alert and most notable should include actionable
	// information and suggestion on how to handle the alert.
	Message string

	// Severity describes the severity of the alert.
	Severity AlertSeverity

	// ReportedAt describes the time when the alert was reported.
	ReportedAt time.Time

	// CheckedAt describes the time when the alert was last check to still be valid.
	CheckedAt time.Time

	// ResolvedAt describes the time when the alert was resolved.
	ResolvedAt time.Time

	// AlertData is alert-specific custom data.
	AlertData any
}

// Equals returns whether the two alerts are identical.
// The alert data is not compared.
func (a *Alert) Equals(b *Alert) bool {
	switch {
	case a.ID != b.ID:
		return false
	case a.Name != b.Name:
		return false
	case a.Message != b.Message:
		return false
	case a.Severity != b.Severity:
		return false
	case !a.ReportedAt.Equal(b.ReportedAt):
		return false
	case !a.CheckedAt.Equal(b.CheckedAt):
		return false
	case !a.ResolvedAt.Equal(b.ResolvedAt):
		return false
	default:
		return true
	}
}

// Copy returns a copy of the alert.
func (a *Alert) Copy() *Alert {
	return &Alert{
		ID:         a.ID,
		Name:       a.Name,
		Message:    a.Message,
		Severity:   a.Severity,
		ReportedAt: a.ReportedAt,
		CheckedAt:  a.CheckedAt,
		ResolvedAt: a.ResolvedAt,
		AlertData:  a.AlertData,
	}
}

// AlertSeverity defines severity of an alert.
type AlertSeverity string

// Alert Severities.
const (
	AlertSeverityUndefined = ""
	AlertSeverityInfo      = "info"
	AlertSeverityWarning   = "warning"
	AlertSeverityError     = "error"
)

// Weight returns a number weighing the gravity of the alert for ordering.
// Higher is worse.
func (as AlertSeverity) Weight() int {
	switch as {
	case AlertSeverityUndefined:
		return 0
	case AlertSeverityInfo:
		return 1
	case AlertSeverityWarning:
		return 2
	case AlertSeverityError:
		return 3
	default:
		return 0
	}
}

// AlertUpdate is used to update others about an alert change.
type AlertUpdate struct {
	Module string
	Alerts []*Alert
}

// AlertingModule is used for interface checks on modules.
type AlertingModule interface {
	Alerts() *AlertMgr
}

// NewAlertMgr returns a new alert manager.
func NewAlertMgr(mgr *Manager) *AlertMgr {
	return &AlertMgr{
		alerts:      make(map[string]*Alert),
		alertEvents: NewEventMgr[AlertUpdate]("alert update", mgr),
		mgr:         mgr,
	}
}

// NewAlertMgr returns a new alert manager.
func (m *Manager) NewAlertMgr() *AlertMgr {
	return NewAlertMgr(m)
}

// Report reports an alert.
// If an alert with the same ID already exists, it is replaced.
func (m *AlertMgr) Report(a Alert) {
	m.alertsLock.Lock()
	defer m.alertsLock.Unlock()

	// Set default times.
	if a.ReportedAt.IsZero() {
		a.ReportedAt = time.Now()
	}

	// Update or add alert.
	existingAlert, ok := m.alerts[a.ID]
	switch {
	case !ok:
		m.alerts[a.ID] = &a
	case !existingAlert.Equals(&a):
		m.alerts[a.ID] = &a
	default:
		// Alert did not change.
		return
	}

	// Export alerts.
	m.clean()
	m.alertEvents.Submit(m.export())
}

// Resolve resolves a reported alert with the given ID, if it exists.
func (m *AlertMgr) Resolve(id string) {
	m.alertsLock.Lock()
	defer m.alertsLock.Unlock()

	// Nothing to do when no alerts have been reported.
	if len(m.alerts) == 0 {
		return
	}

	// Get the alert that should be resolved.
	alert, ok := m.alerts[id]
	if !ok {
		return
	}

	// Copy the alert, set it to resolved and save it.
	copied := alert.Copy()
	copied.ResolvedAt = time.Now()
	m.alerts[id] = copied

	// Clean and export.
	m.clean()
	m.alertEvents.Submit(m.export())
}

// ResolveAll resolves all reported alerts.
func (m *AlertMgr) ResolveAll() {
	m.alertsLock.Lock()
	defer m.alertsLock.Unlock()

	// Resolve all alerts that aren't resolved yet.
	var resolved int
	for id, alert := range m.alerts {
		if alert.ResolvedAt.IsZero() {
			// Copy the alert, set it to resolved and save it.
			copied := alert.Copy()
			copied.ResolvedAt = time.Now()
			m.alerts[id] = copied

			resolved++
		}
	}

	// Return if nothing changed.
	if resolved == 0 {
		return
	}

	// Clean and export.
	m.clean()
	m.alertEvents.Submit(m.export())
}

// Export returns the current reported alerts.
func (m *AlertMgr) Export() AlertUpdate {
	m.alertsLock.Lock()
	defer m.alertsLock.Unlock()

	return m.export()
}

// export returns the current reported alerts.
func (m *AlertMgr) export() AlertUpdate {
	// Get name from manager, if set.
	name := ""
	if m.mgr != nil {
		name = m.mgr.name
	}

	// Copy alerts to slice.
	exportList := make([]*Alert, 0, len(m.alerts))
	for _, alert := range m.alerts {
		exportList = append(exportList, alert)
	}

	// Sort slice by severity, then reported at.
	slices.SortFunc(exportList, func(a, b *Alert) int {
		aW, bW := a.Severity.Weight(), b.Severity.Weight()
		if aW != bW {
			return bW - aW
		}
		return a.ReportedAt.Compare(b.ReportedAt)
	})

	// Make a copy of all alerts.
	return AlertUpdate{
		Module: name,
		Alerts: exportList,
	}
}

func (m *AlertMgr) clean() (deleted int) {
	deleteResolvedAlertsBefore := time.Now().Add(-keepResolvedAlertsFor)

	maps.DeleteFunc(m.alerts, func(id string, alert *Alert) bool {
		if !alert.ResolvedAt.IsZero() && alert.ResolvedAt.Before(deleteResolvedAlertsBefore) {
			deleted++
			return true
		}
		return false
	})
	return deleted
}

// Subscribe subscribes to alert update events.
func (m *AlertMgr) Subscribe(subscriberName string, eventChanSize int) *EventSubscription[AlertUpdate] {
	return m.alertEvents.Subscribe(subscriberName, eventChanSize)
}

// AddCallback adds a callback to alert update events.
func (m *AlertMgr) AddCallback(callbackName string, eventCallback EventCallbackFunc[AlertUpdate]) {
	m.alertEvents.AddCallback(callbackName, eventCallback)
}
