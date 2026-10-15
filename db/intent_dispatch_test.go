package db

import (
	"fmt"
	"slices"
	"sync"
	"testing"
)

func TestIntentDispatchKey(t *testing.T) {
	assets := []int64{3, 1, 3}
	key := intentDispatchKey(" inspect /Admin ", assets, []int64{8, 7, 8})
	if key != intentDispatchKey("inspect /Admin", []int64{1, 3}, []int64{7, 8}) {
		t.Fatal("set order changed identity")
	}
	if !slices.Equal(assets, []int64{3, 1, 3}) {
		t.Fatal("modified caller slice")
	}
	for _, other := range []string{
		intentDispatchKey("inspect /admin", assets, []int64{7, 8}),
		intentDispatchKey("inspect /Admin", []int64{1}, []int64{7, 8}),
		intentDispatchKey("inspect /Admin", assets, []int64{7, 9}),
	} {
		if other == key {
			t.Fatal("distinct conditions collapsed")
		}
	}
	if intentDispatchKey("x", nil, nil) != intentDispatchKey("x", []int64{}, []int64{}) {
		t.Fatal("empty sets differ")
	}
}

func dispatchTestStore(t *testing.T) (*DB, *ExplorationStore) {
	t.Helper()
	d, err := Open(testDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	exp, err := d.CreateExploration("dispatch test", "dispatch test")
	if err != nil {
		d.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Exec(`DELETE FROM explorations WHERE id=$1`, exp); d.Close() })
	return d, d.Exploration(exp)
}

func TestIntentDispatchConcurrentAndAtomic(t *testing.T) {
	d, s := dispatchTestStore(t)
	parent, err := s.AddNode("fact", map[string]any{"text": "condition"}, 0, "confirmed", "test", nil)
	if err != nil {
		t.Fatal(err)
	}
	asset, err := d.Assets().UpsertRootDomain(UpsertRootDomainReq{Domain: fmt.Sprintf("dispatch-%d.invalid", s.ID())})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Exec(`DELETE FROM assets WHERE id=$1`, asset) })
	var wg sync.WaitGroup
	var mu sync.Mutex
	ids := []int64{}
	createdCount := 0
	for range 12 {
		wg.Go(func() {
			id, created, err := s.AddIntentOnce(map[string]any{"summary": "inspect endpoint"}, 5, []int64{asset, asset}, []int64{parent, parent}, "planner")
			if err != nil {
				t.Error(err)
				return
			}
			mu.Lock()
			defer mu.Unlock()
			ids = append(ids, id)
			if created {
				createdCount++
			}
		})
	}
	wg.Wait()
	if len(ids) != 12 || createdCount != 1 {
		t.Fatalf("calls=%d created=%d", len(ids), createdCount)
	}
	for _, id := range ids {
		if id != ids[0] {
			t.Fatalf("duplicate IDs: %v", ids)
		}
	}
	var nodes, anchors, edges int
	if err := d.QueryRow(`SELECT count(*) FROM exploration_nodes WHERE exploration_id=$1 AND kind='intent'`, s.ID()).Scan(&nodes); err != nil {
		t.Fatal(err)
	}
	if err := d.QueryRow(`SELECT count(*) FROM exploration_anchors WHERE node_id=$1`, ids[0]).Scan(&anchors); err != nil {
		t.Fatal(err)
	}
	if err := d.QueryRow(`SELECT count(*) FROM exploration_edges WHERE exploration_id=$1 AND dst_id=$2 AND src_id=$3`, s.ID(), ids[0], parent).Scan(&edges); err != nil {
		t.Fatal(err)
	}
	if nodes != 1 || anchors != 1 || edges != 1 {
		t.Fatalf("partial provenance nodes=%d anchors=%d edges=%d", nodes, anchors, edges)
	}
}

func TestIntentDispatchStatesAndChangedConditions(t *testing.T) {
	_, s := dispatchTestStore(t)
	payload := map[string]any{"summary": "check endpoint"}
	id, created, err := s.AddIntentOnce(payload, 1, nil, nil, "planner")
	if err != nil || !created {
		t.Fatal(id, created, err)
	}
	if _, ok := payload["_dispatch_key"]; ok {
		t.Fatal("mutated caller payload")
	}
	for _, state := range []string{"open", "running", "paused"} {
		if err := s.SetIntentState(id, state); err != nil {
			t.Fatal(err)
		}
		again, created, err := s.AddIntentOnce(payload, 9, nil, nil, "planner")
		if err != nil || created || again != id {
			t.Fatal("active state not reused", state, again, created, err)
		}
	}
	fact, err := s.AddNode("fact", map[string]any{"text": "new condition"}, 0, "confirmed", "test", nil)
	if err != nil {
		t.Fatal(err)
	}
	changed, created, err := s.AddIntentOnce(payload, 5, nil, []int64{fact}, "planner")
	if err != nil || !created || changed == id {
		t.Fatal("new facts suppressed", changed, created, err)
	}
	for _, state := range []string{"done", "blocked", "exhausted", "stopped", "deleted"} {
		if err := s.SetIntentState(id, state); err != nil {
			t.Fatal(err)
		}
		next, created, err := s.AddIntentOnce(payload, 1, nil, nil, "planner")
		if err != nil || !created || next == id {
			t.Fatal("retest suppressed", state, next, created, err)
		}
		id = next
	}
}

func TestIntentDispatchRollbackAndIsolation(t *testing.T) {
	d, s := dispatchTestStore(t)
	payload := map[string]any{"summary": "atomic test"}
	_, _, err := s.AddIntentOnce(payload, 5, nil, []int64{9223372036854775807}, "planner")
	if err == nil {
		t.Fatal("invalid provenance accepted")
	}
	var count int
	if err := d.QueryRow(`SELECT count(*) FROM exploration_nodes WHERE exploration_id=$1`, s.ID()).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatal("failed write left orphan intent")
	}
	a, _, err := s.AddIntentOnce(payload, 5, nil, nil, "planner")
	if err != nil {
		t.Fatal(err)
	}
	other, err := d.CreateExploration("other dispatch", "other")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Exec(`DELETE FROM explorations WHERE id=$1`, other) })
	b, created, err := d.Exploration(other).AddIntentOnce(payload, 5, nil, nil, "planner")
	if err != nil || !created || a == b {
		t.Fatal("cross-exploration reuse", a, b, created, err)
	}
}
