package main

import (
	"testing"

	"srun/internal/platform/windows"
)

func TestParseStartupFlags(t *testing.T) {
	tests := []struct {
		args     []string
		expected bool
	}{
		{args: []string{"srun.exe"}, expected: false},
		{args: []string{"srun.exe", "--no-auto-open"}, expected: true},
		{args: []string{"srun.exe", "--other-flag"}, expected: false},
		{args: []string{}, expected: false},
		{args: []string{"srun.exe", "--no-auto-open", "extra"}, expected: true},
	}

	for _, tc := range tests {
		got := ParseStartupFlags(tc.args)
		if got != tc.expected {
			t.Errorf("ParseStartupFlags(%v) = %v; want %v", tc.args, got, tc.expected)
		}
	}
}

func TestSingleInstanceMutexAndWakeup(t *testing.T) {
	testMutexName := "Local\\SRun_Test_Wakeup_Mutex_" + t.Name()

	release1, alreadyRunning1, err1 := windows.AcquireSingleInstanceMutex(testMutexName)
	if err1 != nil {
		t.Fatalf("first AcquireSingleInstanceMutex failed: %v", err1)
	}
	defer release1()

	if alreadyRunning1 {
		t.Fatalf("expected alreadyRunning1 = false, got true")
	}

	release2, alreadyRunning2, err2 := windows.AcquireSingleInstanceMutex(testMutexName)
	if err2 != nil {
		t.Fatalf("second AcquireSingleInstanceMutex failed: %v", err2)
	}
	defer release2()

	if !alreadyRunning2 {
		t.Fatalf("expected alreadyRunning2 = true, got false")
	}

	woke := windows.WakeExistingWindow("NonExistent_Test_Window_XYZ_999")
	if woke {
		t.Errorf("WakeExistingWindow on non-existent window returned true, expected false")
	}
}
