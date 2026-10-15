package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestIntentDispatchToolReportsReuse(t *testing.T) {
	d := testDB(t)
	defer d.Close()
	exp, err := d.CreateExploration("dispatch tool", "dispatch tool")
	if err != nil {
		t.Fatal(err)
	}
	defer d.Exec(`DELETE FROM explorations WHERE id=$1`, exp)
	store := d.Exploration(exp)
	tools := &ToolSet{ts: store}
	resumed := 0
	tools.resumeTask = func() { resumed++ }
	result, err := tools.addIntent().Call(context.Background(), json.RawMessage(`{"intents":[{"summary":"inspect same target"},{"summary":"inspect same target","priority":9}]}`), nil)
	if err != nil || result.IsError {
		t.Fatal(result, err)
	}
	var out struct {
		IDs     []int64 `json:"ids"`
		Created []bool  `json:"created"`
	}
	if err := json.Unmarshal([]byte(result.Flatten()), &out); err != nil {
		t.Fatal(err)
	}
	if len(out.IDs) != 2 || out.IDs[0] != out.IDs[1] || len(out.Created) != 2 || !out.Created[0] || out.Created[1] || resumed != 1 {
		t.Fatal(result.Flatten(), resumed)
	}
	result, err = tools.addIntent().Call(context.Background(), json.RawMessage(`{"summary":"inspect same target"}`), nil)
	if err != nil || result.IsError || !strings.Contains(result.Flatten(), fmt.Sprint(out.IDs[0])) || !strings.Contains(result.Flatten(), "already active") || resumed != 1 {
		t.Fatal(result, err, resumed)
	}
}
