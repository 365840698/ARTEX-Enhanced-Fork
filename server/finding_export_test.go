package server

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/Autumn-27/artex/db"
	"io"
	"net/http/httptest"
	"strings"
	"testing"
)

// A nil manager proves invalid formats are rejected before accessing storage.
func TestFindingExportRejectsInvalidFormatBeforeIO(t *testing.T) {
	s := &Server{}
	w := httptest.NewRecorder()
	s.findingsExport(w, httptest.NewRequest("GET", "/?format=invalid&scope=all", nil))
	if w.Code != 400 || !strings.Contains(w.Body.String(), "bad format") {
		t.Fatal(w.Code, w.Body)
	}
}

func TestFindingExportIncludesRetestHistory(t *testing.T) {
	if _, _, err := db.DSN(); err != nil {
		t.Skip("PostgreSQL not configured")
	}
	s, f, request := trafficEvidenceServer(t)
	r, _, _, err := s.m.pg.CreateFindingRetest(t.Context(), f.FindingID, "export history condition")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.m.pg.Exec(`DELETE FROM conversations WHERE id=$1`, *r.ConversationID) })
	for _, format := range []string{"md-single", "md-zip", "json", "csv"} {
		w := request("GET", fmt.Sprintf("/api/exploration/findings/export?scope=selected&ids=%d&format=%s", f.FindingID, format), "")
		if w.Code != 200 {
			t.Fatal(format, w.Code, w.Body)
		}
		body := w.Body.String()
		if format == "md-zip" {
			z, err := zip.NewReader(bytes.NewReader(w.Body.Bytes()), int64(w.Body.Len()))
			if err != nil {
				t.Fatal(err)
			}
			body = ""
			for _, file := range z.File {
				if strings.HasSuffix(file.Name, ".md") {
					rc, err := file.Open()
					if err != nil {
						t.Fatal(err)
					}
					b, err := io.ReadAll(rc)
					rc.Close()
					if err != nil {
						t.Fatal(err)
					}
					body += string(b)
				}
			}
		}
		if format == "json" {
			var out []FindingDTO
			if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
				t.Fatal(err)
			}
			if len(out) != 1 || len(out[0].Retests) != 1 || out[0].Retests[0].ID != r.ID {
				t.Fatal("missing JSON history", body)
			}
			if strings.Contains(body, `"snapshot"`) {
				t.Fatal("agent snapshot leaked", body)
			}
		}
		if format == "csv" {
			if !strings.Contains(body, "复测次数") || !strings.Contains(body, "pending") {
				t.Fatal("missing CSV history", body)
			}
		} else if !strings.Contains(body, "export history condition") {
			t.Fatal("missing history", format, body)
		}
	}
}

func TestFindingExportDTOCarriesHistoryWithoutSnapshots(t *testing.T) {
	f := &db.DBFinding{ID: 7, Retests: []*db.FindingRetest{{ID: 9, Status: "completed", Verdict: "fixed"}}}
	data, err := json.Marshal(findingFromDB(f, nil))
	if err != nil {
		t.Fatal(err)
	}
	var out FindingDTO
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Retests) != 1 || out.Retests[0].ID != 9 || out.Retests[0].Verdict != "fixed" {
		t.Fatal(string(data))
	}
	if strings.Contains(string(data), `"snapshot"`) {
		t.Fatal("snapshot leaked")
	}
}
