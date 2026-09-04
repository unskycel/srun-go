package service

import (
	"sync"
	"testing"
)

func TestMemoryLogger_CapacityAndFIFO(t *testing.T) {
	logger := &MemoryLogger{
		entries: make([]LogEntry, 0, maxLogEntries),
	}

	// Add 550 entries
	for i := 1; i <= 550; i++ {
		logger.Add("INFO", "Message %d", i)
	}

	entries := logger.GetEntries()
	if len(entries) != maxLogEntries {
		t.Fatalf("expected %d entries, got %d", maxLogEntries, len(entries))
	}

	// First entry should be Message 51
	if entries[0].Message != "Message 51" {
		t.Errorf("expected first entry to be 'Message 51', got %s", entries[0].Message)
	}

	// Last entry should be Message 550
	if entries[len(entries)-1].Message != "Message 550" {
		t.Errorf("expected last entry to be 'Message 550', got %s", entries[len(entries)-1].Message)
	}

	// Test Clear
	logger.Clear()
	if len(logger.GetEntries()) != 0 {
		t.Fatalf("expected 0 entries after Clear")
	}
}

func TestMemoryLogger_Concurrency(t *testing.T) {
	logger := &MemoryLogger{
		entries: make([]LogEntry, 0, maxLogEntries),
	}

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for j := 0; j < 30; j++ {
				logger.Add("EVENT", "Worker %d log %d", workerID, j)
			}
		}(i)
	}
	wg.Wait()

	entries := logger.GetEntries()
	if len(entries) != maxLogEntries {
		t.Fatalf("expected maxLogEntries (%d), got %d", maxLogEntries, len(entries))
	}
}

func TestConvenienceFunctions(t *testing.T) {
	GetLogger().Clear()
	LogInfo("Info test %d", 1)
	LogWarn("Warn test %s", "warn")
	LogError("Error test")
	LogEvent("Event test")
	LogSuccess("Success test")

	entries := GetLogger().GetEntries()
	if len(entries) != 5 {
		t.Fatalf("expected 5 entries, got %d", len(entries))
	}

	levels := []string{"INFO", "WARN", "ERROR", "EVENT", "SUCCESS"}
	for i, lvl := range levels {
		if entries[i].Level != lvl {
			t.Errorf("expected level %s, got %s", lvl, entries[i].Level)
		}
	}
}
