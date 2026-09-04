package service

import (
	"fmt"
	"sync"
	"time"
)

// LogEntry represents an in-memory runtime log record.
type LogEntry struct {
	Timestamp string `json:"time"`
	Level     string `json:"level"` // INFO, WARN, ERROR, EVENT, SUCCESS
	Message   string `json:"message"`
}

const maxLogEntries = 500

// MemoryLogger manages a thread-safe, in-memory fixed-size ring buffer of runtime logs.
// It generates zero disk I/O and automatically discards the oldest logs upon reaching capacity.
type MemoryLogger struct {
	mu      sync.RWMutex
	entries []LogEntry
}

var globalLogger = &MemoryLogger{
	entries: make([]LogEntry, 0, maxLogEntries),
}

// GetLogger returns the global in-memory logger instance.
func GetLogger() *MemoryLogger {
	return globalLogger
}

// Add appends a new log entry to the in-memory ring buffer.
func (l *MemoryLogger) Add(level, format string, args ...any) {
	msg := format
	if len(args) > 0 {
		msg = fmt.Sprintf(format, args...)
	}

	entry := LogEntry{
		Timestamp: time.Now().Format("15:04:05"),
		Level:     level,
		Message:   msg,
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	if len(l.entries) >= maxLogEntries {
		// Evict oldest log entry (FIFO)
		l.entries = l.entries[1:]
	}
	l.entries = append(l.entries, entry)
}

// GetEntries returns a copy of all current in-memory log entries.
func (l *MemoryLogger) GetEntries() []LogEntry {
	l.mu.RLock()
	defer l.mu.RUnlock()

	res := make([]LogEntry, len(l.entries))
	copy(res, l.entries)
	return res
}

// Clear wipes all in-memory log entries.
func (l *MemoryLogger) Clear() {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.entries = make([]LogEntry, 0, maxLogEntries)
}

// Convenience package-level logging functions
func LogInfo(format string, args ...any) {
	globalLogger.Add("INFO", format, args...)
}

func LogWarn(format string, args ...any) {
	globalLogger.Add("WARN", format, args...)
}

func LogError(format string, args ...any) {
	globalLogger.Add("ERROR", format, args...)
}

func LogEvent(format string, args ...any) {
	globalLogger.Add("EVENT", format, args...)
}

func LogSuccess(format string, args ...any) {
	globalLogger.Add("SUCCESS", format, args...)
}
