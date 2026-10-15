package db

import (
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
)

// dispatchIDs canonicalizes set-valued inputs without changing the caller's slice.
func dispatchIDs(ids []int64) []int64 {
	out := make([]int64, 0, len(ids))
	for _, id := range ids {
		if id > 0 {
			out = append(out, id)
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// intentDispatchKey deliberately preserves case and internal whitespace. A
// summary can contain case-sensitive URLs or commands; semantic/fuzzy matching
// must not silently suppress distinct work. Priority is scheduling, not identity.
func intentDispatchKey(summary string, anchors, parents []int64) string {
	raw, _ := json.Marshal(struct {
		Summary         string
		Assets, Parents []int64
	}{
		strings.TrimSpace(summary), dispatchIDs(anchors), dispatchIDs(parents),
	})
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// AddIntentOnce atomically creates a planner intent and all its provenance, or
// reuses an identical open/running/paused intent in this exploration. Completed
// work is deliberately eligible for a new explicit test; changed parents or
// assets also create a new identity. Legacy AddIntent callers remain unchanged.
func (s *ExplorationStore) AddIntentOnce(payload map[string]any, priority int, anchors, parents []int64, origin string) (id int64, created bool, err error) {
	summary, _ := payload["summary"].(string)
	if strings.TrimSpace(summary) == "" {
		return 0, false, fmt.Errorf("intent summary must not be empty")
	}
	anchors, parents = dispatchIDs(anchors), dispatchIDs(parents)
	key := intentDispatchKey(summary, anchors, parents)
	cp := make(map[string]any, len(payload)+1)
	for k, v := range payload {
		cp[k] = v
	}
	cp["_dispatch_key"] = key
	if len(anchors) > 0 {
		cp["asset_ids"] = anchors
	} else {
		delete(cp, "asset_ids")
	}
	raw, err := json.Marshal(cp)
	if err != nil {
		return 0, false, err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return 0, false, err
	}
	defer tx.Rollback()
	// Lock the logical identity, including exploration, across independent agents
	// and server processes. The lookup occurs AFTER the lock so it sees the last
	// winner's commit under PostgreSQL's READ COMMITTED isolation.
	lockHash := sha256.Sum256([]byte(fmt.Sprintf("artex/dispatch/%d/%s", s.expID, key)))
	if _, err = tx.Exec(`SELECT pg_advisory_xact_lock($1)`, int64(binary.BigEndian.Uint64(lockHash[:8]))); err != nil {
		return 0, false, err
	}
	err = tx.QueryRow(`SELECT id FROM exploration_nodes WHERE exploration_id=$1 AND kind='intent'
  AND state IN ('open','running','paused') AND payload->>'_dispatch_key'=$2 ORDER BY id LIMIT 1`, s.expID, key).Scan(&id)
	if err == nil {
		return id, false, tx.Commit()
	}
	if err != sql.ErrNoRows {
		return 0, false, err
	}
	if origin == "" {
		origin = "planner"
	}
	err = tx.QueryRow(`INSERT INTO exploration_nodes(exploration_id,kind,payload,priority,state,origin)
  VALUES($1,'intent',$2,$3,'open',$4) RETURNING id`, s.expID, string(raw), priority, origin).Scan(&id)
	if err != nil {
		return 0, false, err
	}
	for _, a := range anchors {
		if _, err = tx.Exec(`INSERT INTO exploration_anchors(node_id,asset_id) VALUES($1,$2) ON CONFLICT DO NOTHING`, id, a); err != nil {
			return 0, false, err
		}
	}
	for _, parent := range parents {
		if _, err = tx.Exec(`INSERT INTO exploration_edges(exploration_id,src_id,rel,dst_id) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING`, s.expID, parent, RelDerivedFrom, id); err != nil {
			return 0, false, err
		}
	}
	if err = tx.Commit(); err != nil {
		return 0, false, err
	}
	return id, true, nil
}
