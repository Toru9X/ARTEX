package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
)

func TestValidateWorkerPools(t *testing.T) {
	cases := []struct {
		name    string
		pools   []WorkerPool
		wantErr string
	}{
		{"empty is valid and means no pinning", nil, ""},
		{"single pool", []WorkerPool{{ProfileID: 1, Workers: 3}}, ""},
		{"two pools", []WorkerPool{{ProfileID: 1, Workers: 2}, {ProfileID: 2, Workers: 2}}, ""},
		{"profile id must be positive", []WorkerPool{{ProfileID: 0, Workers: 1}}, "profile_id"},
		{"workers must be positive", []WorkerPool{{ProfileID: 1, Workers: 0}}, "workers"},
		// Two groups for one profile would make the saved order ambiguous.
		{"duplicate profile", []WorkerPool{{ProfileID: 1, Workers: 1}, {ProfileID: 1, Workers: 1}}, "duplicate"},
		{"at the total limit", []WorkerPool{{ProfileID: 1, Workers: db.MaxTaskWorkerCount}}, ""},
		{"over the total limit", []WorkerPool{{ProfileID: 1, Workers: db.MaxTaskWorkerCount + 1}}, "between 1 and"},
		{
			"sum over the limit",
			[]WorkerPool{{ProfileID: 1, Workers: db.MaxTaskWorkerCount}, {ProfileID: 2, Workers: 1}},
			"between 1 and",
		},
		// The check must compare before adding, or a huge value overflows int.
		{"huge value does not overflow", []WorkerPool{{ProfileID: 1, Workers: 1 << 40}}, "between 1 and"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateWorkerPools(tc.pools)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error = %v, want one containing %q", err, tc.wantErr)
			}
		})
	}
}

func TestExpandWorkerSlots(t *testing.T) {
	// No pools: the historical behaviour, N unpinned lanes named work#1..work#N.
	slots, err := ExpandWorkerSlots(nil, 3)
	if err != nil {
		t.Fatal(err)
	}
	if len(slots) != 3 {
		t.Fatalf("got %d slots, want 3", len(slots))
	}
	for i, slot := range slots {
		if slot.ProfileID != 0 {
			t.Fatalf("slot %d is pinned to #%d with no pools configured", i, slot.ProfileID)
		}
	}
	if slots[0].Name != "work#1" || slots[2].Name != "work#3" {
		t.Fatalf("names = %q..%q, want work#1..work#3", slots[0].Name, slots[2].Name)
	}

	// A zero or negative legacy count falls back to the default rather than
	// starting a task with no workers at all.
	if slots, err = ExpandWorkerSlots(nil, 0); err != nil || len(slots) != defaultWorkers {
		t.Fatalf("legacy 0 gave %d slots (err=%v), want %d", len(slots), err, defaultWorkers)
	}

	// With pools, lanes are expanded in the saved order and numbered after.
	slots, err = ExpandWorkerSlots([]WorkerPool{{ProfileID: 7, Workers: 2}, {ProfileID: 9, Workers: 1}}, 5)
	if err != nil {
		t.Fatal(err)
	}
	want := []WorkerSlot{
		{Name: "work#1", ProfileID: 7},
		{Name: "work#2", ProfileID: 7},
		{Name: "work#3", ProfileID: 9},
	}
	if len(slots) != len(want) {
		t.Fatalf("got %d slots, want %d", len(slots), len(want))
	}
	for i := range want {
		if slots[i] != want[i] {
			t.Fatalf("slot %d = %+v, want %+v", i, slots[i], want[i])
		}
	}
}

// A per-task worker override stays authoritative: the task asked for N lanes,
// so it gets N unpinned lanes rather than the global pool plan.
func TestWorkerSlotsForTaskHonoursPerTaskOverride(t *testing.T) {
	pools := []WorkerPool{{ProfileID: 7, Workers: 4}}

	slots, err := workerSlotsForTask(&Task{WorkerCount: 2}, pools, 5)
	if err != nil {
		t.Fatal(err)
	}
	if len(slots) != 2 {
		t.Fatalf("got %d slots, want the task's 2", len(slots))
	}
	for _, slot := range slots {
		if slot.ProfileID != 0 {
			t.Fatalf("a per-task override must not inherit a pool pin, got #%d", slot.ProfileID)
		}
	}

	// No override: inherit the pools.
	slots, err = workerSlotsForTask(&Task{}, pools, 5)
	if err != nil {
		t.Fatal(err)
	}
	if len(slots) != 4 || slots[0].ProfileID != 7 {
		t.Fatalf("without an override the pools should apply, got %+v", slots)
	}
}

// A direct database edit can bypass API validation, so the engine clamps the
// per-task count before it forks that many goroutines.
func TestWorkerCountForTaskClamps(t *testing.T) {
	if got := workerCountForTask(&Task{WorkerCount: db.MaxTaskWorkerCount + 500}, 3); got != db.MaxTaskWorkerCount {
		t.Fatalf("workerCountForTask() = %d, want it clamped to %d", got, db.MaxTaskWorkerCount)
	}
	if got := workerCountForTask(&Task{}, 4); got != 4 {
		t.Fatalf("no override should use the global count, got %d", got)
	}
	if got := workerCountForTask(nil, 4); got != 4 {
		t.Fatalf("a nil task should use the global count, got %d", got)
	}
}

// The web client sends profile_id as a string to dodge JavaScript's 53-bit
// integer limit; saved payloads and tests use numbers. Both must decode.
func TestWorkerPoolUnmarshalAcceptsStringAndNumber(t *testing.T) {
	var pools []WorkerPool
	if err := json.Unmarshal([]byte(`[{"profile_id":"42","workers":2},{"profile_id":7,"workers":1}]`), &pools); err != nil {
		t.Fatal(err)
	}
	if len(pools) != 2 || pools[0].ProfileID != 42 || pools[1].ProfileID != 7 {
		t.Fatalf("decoded %+v", pools)
	}
	if err := json.Unmarshal([]byte(`[{"profile_id":"abc","workers":1}]`), &pools); err == nil {
		t.Fatal("a non-numeric profile_id must fail to decode")
	}
}

// The scope rule from the porting decision: a task that owns an LLM chain owns
// its routing. A slot pin outside that chain must be refused so the chain's
// rotation and failover stay in charge; the caller then falls back to the
// task's normal bundle instead of silently running on another model.
func TestWorkerForTaskSlotScopedToTaskChain(t *testing.T) {
	s := &Server{m: proxyTestManager(t), taskAgents: map[string]*taskAgentBundle{}}

	if _, err := s.workerForTaskSlot(&Task{ID: "1"}, WorkerSlot{Name: "work#1"}); err == nil {
		t.Fatal("an unpinned slot must not resolve a pinned worker")
	}

	chained := &Task{ID: "2", LLMProfileIDs: []int64{10, 11}}
	_, err := s.workerForTaskSlot(chained, WorkerSlot{Name: "work#1", ProfileID: 99})
	if err == nil || !strings.Contains(err.Error(), "not in the task's chain") {
		t.Fatalf("a pin outside the chain must be refused, got %v", err)
	}

	// A pin inside the chain gets past the scope check; it then fails on the
	// profile not existing, which is the next gate and not what this asserts.
	_, err = s.workerForTaskSlot(chained, WorkerSlot{Name: "work#1", ProfileID: 10})
	if err == nil || strings.Contains(err.Error(), "not in the task's chain") {
		t.Fatalf("a pin inside the chain must pass the scope check, got %v", err)
	}

	// A task with no chain of its own leaves the pool pin in charge, so the
	// scope check must not reject it.
	_, err = s.workerForTaskSlot(&Task{ID: "3"}, WorkerSlot{Name: "work#1", ProfileID: 10})
	if err != nil && strings.Contains(err.Error(), "not in the task's chain") {
		t.Fatalf("a task without a chain must not be scope-checked, got %v", err)
	}
}

// A lane pinned outside the task's own chain must run on the task's bundle,
// not idle forever; any other resolve failure idles the lane (nil).
func TestLaneWorkerFallsBackOutsideChain(t *testing.T) {
	bundleW, pinnedW := &agent.Worker{}, &agent.Worker{}
	var resolveErr error
	e := &Engine{
		resolve: func(*Task) (*agent.Planner, *agent.Worker) { return &agent.Planner{}, bundleW },
		workerResolve: func(*Task, WorkerSlot) (*agent.Worker, error) {
			if resolveErr != nil {
				return nil, resolveErr
			}
			return pinnedW, nil
		},
	}
	task, last := &Task{ID: "1"}, ""
	pinned := WorkerSlot{Name: "work#1", ProfileID: 5}

	if w := e.laneWorker(task, pinned, &last); w != pinnedW {
		t.Fatal("a resolvable pin must use its own worker")
	}
	resolveErr = fmt.Errorf("LLM profile #5 is %w", errSlotOutsideChain)
	if w := e.laneWorker(task, pinned, &last); w != bundleW {
		t.Fatal("a pin outside the task's chain must fall back to the bundle worker")
	}
	resolveErr = errors.New("task 1 has no agent bundle yet")
	if w := e.laneWorker(task, pinned, &last); w != nil || last == "" {
		t.Fatalf("other failures must idle the lane and record the error, got w=%v last=%q", w, last)
	}
	if w := e.laneWorker(task, WorkerSlot{Name: "work#2"}, &last); w != bundleW {
		t.Fatal("an unpinned lane uses the bundle worker")
	}
}
