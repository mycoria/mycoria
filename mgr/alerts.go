package mgr

import (
	"slices"
	"sync"
	"time"
)

const maxIdleAlertBufferSize = 4

// AlertMgr manages reported alerts.
type AlertMgr struct {
	alerts     []Alert
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

	// AlertData is alert-specific custom data.
	AlertData any
}

// AlertSeverity defines severity of an alert.
type AlertSeverity string

// Alert Severities.
const (
	AlertSeverityResolved = "resolved"
	AlertSeverityInfo     = "info"
	AlertSeverityWarning  = "warning"
	AlertSeverityError    = "error"
)

// Weight returns a number weighing the gravity of the alert for ordering.
// Higher is worse.
func (as AlertSeverity) Weight() int {
	switch as {
	case AlertSeverityResolved:
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
	Alerts []Alert
}

// AlertingModule is used for interface checks on modules.
type AlertingModule interface {
	Alerts() *AlertMgr
}

// NewAlertMgr returns a new alert manager.
func NewAlertMgr(mgr *Manager) *AlertMgr {
	return &AlertMgr{
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
	if a.CheckedAt.IsZero() {
		a.CheckedAt = a.ReportedAt
	}

	// Update or add alert in list.
	index := slices.IndexFunc(m.alerts, func(al Alert) bool {
		return al.ID == a.ID
	})
	if index >= 0 {
		m.alerts[index] = a
	} else {
		m.alerts = append(m.alerts, a)
	}

	// Export alerts.
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

	// Remove the alert with the given ID from the reported alerts.
	var alertRemoved bool
	m.alerts = slices.DeleteFunc(m.alerts, func(a Alert) bool {
		if a.ID == id {
			alertRemoved = true
			return true
		}
		return false
	})

	// If we removed an alert, submit an event with the updated alerts.
	if alertRemoved {
		m.alertEvents.Submit(m.export())

		// If there are no reported alerts left, reset the slice if too big.
		if len(m.alerts) == 0 && cap(m.alerts) > maxIdleAlertBufferSize {
			m.alerts = nil
		}
	}
}

// ResolveAll resolves all reported alerts.
func (m *AlertMgr) ResolveAll() {
	m.alertsLock.Lock()

	// Clear all entries.
	clear(m.alerts)
	// Reset slice if too big.
	if cap(m.alerts) > maxIdleAlertBufferSize {
		m.alerts = nil
	}

	m.alertsLock.Unlock()

	// Submit alert update outside of lock to allow changes to alerts within callback.
	defer m.alertEvents.Submit(m.Export())
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

	// Make a copy of all alerts.
	return AlertUpdate{
		Module: name,
		Alerts: slices.Clone(m.alerts),
	}
}

// Subscribe subscribes to alert update events.
func (m *AlertMgr) Subscribe(subscriberName string, eventChanSize int) *EventSubscription[AlertUpdate] {
	return m.alertEvents.Subscribe(subscriberName, eventChanSize)
}

// AddCallback adds a callback to alert update events.
func (m *AlertMgr) AddCallback(callbackName string, eventCallback EventCallbackFunc[AlertUpdate]) {
	m.alertEvents.AddCallback(callbackName, eventCallback)
}
