package report

import (
	"bytes"
	"encoding/csv"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/Autumn-27/artex/db"
)

func TestFindingExportOrderAndSummary(t *testing.T) {
	fs := []*db.DBFinding{
		{ID: 1, Name: "unknown", Severity: "unexpected"},
		{ID: 2, Name: "high", Severity: "high"},
		{ID: 3, Name: "critical", Severity: "critical"},
		{ID: 4, Name: "high tie", Severity: "high"},
	}
	out := FindingsMarkdown(fs, time.Time{})
	if !(strings.Index(out, "CRITICAL") < strings.Index(out, "HIGH") && strings.Index(out, "HIGH") < strings.Index(out, "UNEXPECTED")) {
		t.Fatal("severity order", out)
	}
	if !strings.Contains(out, "| 信息 / 未分类 | 1 |") {
		t.Fatal("summary lost unknown severity")
	}
	rows, err := csv.NewReader(bytes.NewReader(FindingsCSV(fs)[3:])).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	for i, want := range []string{"3", "4", "2", "1"} {
		if rows[i+1][0] != want {
			t.Fatalf("order: %v", rows)
		}
	}
	if fs[0].ID != 1 {
		t.Fatal("export mutated caller order")
	}
}

func TestFindingFilenameKeepsUniqueIDAndUTF8(t *testing.T) {
	f := &db.DBFinding{ID: 123, Severity: "high", Name: strings.Repeat("漏洞", 100) + "/../x"}
	a := FindingFilename(f)
	f.ID = 124
	b := FindingFilename(f)
	if !utf8.ValidString(a) || len(a) > 123 || strings.ContainsAny(a, "/\\") || a == b || !strings.HasSuffix(a, "_123.md") {
		t.Fatalf("invalid names: %q %q", a, b)
	}
}

func TestEvidenceFencesAndRetestHistory(t *testing.T) {
	fid := int64(77)
	f := &db.DBFinding{ID: 1, Evidence: "request\n```\n# untrusted", Retests: []*db.FindingRetest{
		{ID: 2, Status: "stopped", Verdict: "fixed", Summary: "staged summary", Evidence: "```\nproof", Error: "interrupted", ConversationID: &fid},
		{ID: 1, Status: "completed", Verdict: "reproduced", Notes: "version v1"},
	}}
	for _, out := range []string{SingleFindingMarkdown(f, time.Time{}), FindingsMarkdown([]*db.DBFinding{f}, time.Time{})} {
		for _, want := range []string{"````\nrequest\n```", "复测 #2", "暂存结论（未成功完成，不作为修复依据）", "interrupted", "仍可复现", "version v1", "会话 ID：77"} {
			if !strings.Contains(out, want) {
				t.Fatalf("missing %q in %s", want, out)
			}
		}
	}
	rows, err := csv.NewReader(bytes.NewReader(FindingsCSV([]*db.DBFinding{f})[3:])).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if rows[1][10] != "2" || rows[1][11] != "stopped" || rows[1][12] != "" {
		t.Fatal("staged verdict leaked", rows)
	}
	f.Retests = f.Retests[1:]
	rows, err = csv.NewReader(bytes.NewReader(FindingsCSV([]*db.DBFinding{f})[3:])).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if rows[1][12] != "reproduced" {
		t.Fatal("completed verdict omitted", rows)
	}
}

func TestCSVNeutralizesFormulaCells(t *testing.T) {
	for _, value := range []string{"=1+1", " +SUM(1)", "\t@cmd", "\rvalue", "\nvalue", "\x00=1", "-cmd"} {
		f := &db.DBFinding{Name: value, TaskDescription: value, VulnClass: value, Summary: value}
		rows, err := csv.NewReader(bytes.NewReader(FindingsCSV([]*db.DBFinding{f})[3:])).ReadAll()
		if err != nil {
			t.Fatal(err)
		}
		for _, i := range []int{1, 2, 5, 7} {
			if !strings.HasPrefix(rows[1][i], "'") {
				t.Fatalf("unsafe cell %q", rows[1][i])
			}
		}
	}
	if got := spreadsheetCell("普通摘要"); got != "普通摘要" {
		t.Fatal(got)
	}
}
