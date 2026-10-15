package report

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/Autumn-27/artex/db"
)

// 发现页「导出」用的渲染:把一批 findings 表行渲染成汇总 Markdown、单条 Markdown、
// 或 CSV。JSON 由 server 层直接用 DTO 序列化,不在此处。

// sortFindingsForExport 按严重等级降序、再按时间倒序排,与汇总报告的分组一致。
func sortFindingsForExport(fs []*db.DBFinding) {
	sort.SliceStable(fs, func(i, j int) bool {
		ri, rj := severityRank(fs[i].Severity), severityRank(fs[j].Severity)
		if ri != rj {
			return ri < rj // sevRank 越小越严重
		}
		if fs[i].CreatedAt.Equal(fs[j].CreatedAt) {
			return fs[i].ID > fs[j].ID
		}
		return fs[i].CreatedAt.After(fs[j].CreatedAt)
	})
}

// findingTitle 取漏洞可读标题:名称 → 类别 → 「未分类」。
func findingTitle(f *db.DBFinding) string {
	return nz(f.Name, nz(f.VulnClass, "未分类"))
}

// FindingsMarkdown 把一批 findings 整合成一份汇总报告(摘要 + 按严重等级分组,
// 每条含类别/状态/所属任务/证据/详细报告)。
func FindingsMarkdown(fs []*db.DBFinding, generatedAt time.Time) string {
	items := append([]*db.DBFinding(nil), fs...)
	sortFindingsForExport(items)

	var b strings.Builder
	b.WriteString("# 漏洞发现汇总报告\n\n")
	fmt.Fprintf(&b, "- **生成时间**：%s\n", generatedAt.Format("2006-01-02 15:04:05"))
	fmt.Fprintf(&b, "- **发现总数**：%d 个\n\n", len(items))

	// 摘要:各严重等级计数。
	counts := map[string]int{}
	for _, f := range items {
		counts[strings.ToLower(strings.TrimSpace(f.Severity))]++
	}
	b.WriteString("## 摘要\n\n")
	b.WriteString("| 严重等级 | 数量 |\n| --- | --- |\n")
	for _, s := range []struct{ key, label string }{
		{"critical", "严重"}, {"high", "高危"}, {"medium", "中危"}, {"low", "低危"},
	} {
		fmt.Fprintf(&b, "| %s | %d |\n", s.label, counts[s.key])
	}
	other := len(items) - counts["critical"] - counts["high"] - counts["medium"] - counts["low"]
	if other > 0 {
		fmt.Fprintf(&b, "| 信息 / 未分类 | %d |\n", other)
	}
	b.WriteString("\n")

	if len(items) == 0 {
		b.WriteString("_无匹配的漏洞。_\n")
		return b.String()
	}

	b.WriteString("## 漏洞明细\n\n")
	for i, f := range items {
		fmt.Fprintf(&b, "### %d. [%s] %s\n\n", i+1, strings.ToUpper(nz(f.Severity, "info")), findingTitle(f))
		if f.VulnClass != "" {
			fmt.Fprintf(&b, "- **类别**：%s\n", f.VulnClass)
		}
		fmt.Fprintf(&b, "- **状态**：%s\n", nz(f.Status, "pending"))
		if desc := strings.TrimSpace(f.TaskDescription); desc != "" {
			fmt.Fprintf(&b, "- **所属任务**：%s\n", desc)
		}
		fmt.Fprintf(&b, "- **发现时间**：%s\n\n", f.CreatedAt.Format("2006-01-02 15:04:05"))
		if s := strings.TrimSpace(f.Summary); s != "" {
			fmt.Fprintf(&b, "%s\n\n", s)
		}
		if e := strings.TrimSpace(f.Evidence); e != "" {
			b.WriteString("**证据：**\n\n")
			b.WriteString(evidenceBlock(e))
		}
		if rep := strings.TrimSpace(f.Report); rep != "" {
			b.WriteString("**详细报告：**\n\n")
			b.WriteString(rep)
			b.WriteString("\n\n")
		}
		b.WriteString(findingRetestsMarkdown(f, "####"))
		b.WriteString(findingTrafficMarkdown(f, false))
		b.WriteString("---\n\n")
	}
	return b.String()
}

// SingleFindingMarkdown 渲染单条漏洞为一份独立 Markdown(用于「一漏洞一文件」打包)。
func SingleFindingMarkdown(f *db.DBFinding, generatedAt time.Time) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# [%s] %s\n\n", strings.ToUpper(nz(f.Severity, "info")), findingTitle(f))
	if f.VulnClass != "" {
		fmt.Fprintf(&b, "- **类别**：%s\n", f.VulnClass)
	}
	fmt.Fprintf(&b, "- **严重等级**：%s\n", nz(f.Severity, "info"))
	fmt.Fprintf(&b, "- **状态**：%s\n", nz(f.Status, "pending"))
	if desc := strings.TrimSpace(f.TaskDescription); desc != "" {
		fmt.Fprintf(&b, "- **所属任务**：%s\n", desc)
	}
	fmt.Fprintf(&b, "- **发现时间**：%s\n", f.CreatedAt.Format("2006-01-02 15:04:05"))
	fmt.Fprintf(&b, "- **生成时间**：%s\n\n", generatedAt.Format("2006-01-02 15:04:05"))
	if s := strings.TrimSpace(f.Summary); s != "" {
		fmt.Fprintf(&b, "## 概述\n\n%s\n\n", s)
	}
	if e := strings.TrimSpace(f.Evidence); e != "" {
		b.WriteString("## 证据\n\n")
		b.WriteString(evidenceBlock(e))
	}
	if rep := strings.TrimSpace(f.Report); rep != "" {
		b.WriteString("## 详细报告\n\n")
		b.WriteString(rep)
		b.WriteString("\n")
	}
	b.WriteString(findingRetestsMarkdown(f, "##"))
	b.WriteString(findingTrafficMarkdown(f, true))
	return b.String()
}

var unsafeFilenameChars = regexp.MustCompile(`[^\p{Han}\p{L}\p{N}._-]+`)

// FindingFilename 为「一漏洞一文件」生成安全的 .md 文件名,形如
// `critical_SQL注入_123.md`。去掉路径分隔符与控制字符,避免 zip 内非法路径。
func FindingFilename(f *db.DBFinding) string {
	sev := nz(f.Severity, "info")
	title := findingTitle(f)
	name := unsafeFilenameChars.ReplaceAllString(sev+"_"+title, "_")
	name = strings.Trim(path.Base(name), "._")
	if name == "" {
		name = "finding"
	}
	// Keep the unique ID outside the truncated title and preserve UTF-8.
	suffix := fmt.Sprintf("_%d", f.ID)
	limit := 120 - len(suffix)
	if len(name) > limit {
		name = name[:limit]
		for !utf8.ValidString(name) {
			name = name[:len(name)-1]
		}
	}
	name += suffix
	return name + ".md"
}

// FindingsCSV 把一批 findings 渲染成 CSV(带 UTF-8 BOM,便于 Excel 正确识别中文)。
// 不含大段 report/evidence 全文,只放摘要类字段;需要全文用 Markdown/JSON 导出。
func FindingsCSV(fs []*db.DBFinding) []byte {
	items := append([]*db.DBFinding(nil), fs...)
	sortFindingsForExport(items)

	var buf bytes.Buffer
	buf.WriteString("\xEF\xBB\xBF") // UTF-8 BOM
	w := csv.NewWriter(&buf)
	_ = w.Write([]string{"ID", "名称", "类别", "严重等级", "状态", "所属任务", "发现时间", "概述", "流量证据数量", "流量证据ID", "复测次数", "最近复测状态", "最近复测结论"})
	for _, f := range items {
		latestStatus, latestVerdict := "", ""
		if len(f.Retests) > 0 {
			latestStatus = f.Retests[0].Status
			if latestStatus == "completed" {
				latestVerdict = f.Retests[0].Verdict
			}
		}
		row := []string{
			fmt.Sprintf("%d", f.ID),
			findingTitle(f),
			f.VulnClass,
			nz(f.Severity, "info"),
			nz(f.Status, "pending"),
			f.TaskDescription,
			f.CreatedAt.Format("2006-01-02 15:04:05"),
			f.Summary,
			fmt.Sprint(len(f.TrafficBindings)), findingTrafficIDs(f),
			fmt.Sprint(len(f.Retests)), latestStatus, latestVerdict,
		}
		for i, value := range row {
			row[i] = spreadsheetCell(value)
		}
		_ = w.Write(row)
	}
	w.Flush()
	return buf.Bytes()
}

func findingTrafficIDs(f *db.DBFinding) string {
	ids := make([]string, 0, len(f.TrafficBindings))
	for _, b := range f.TrafficBindings {
		ids = append(ids, fmt.Sprint(b.ID))
	}
	return strings.Join(ids, ",")
}

func findingTrafficMarkdown(f *db.DBFinding, attachments bool) string {
	stale := f.Report != "" && f.EvidenceVersion != f.ReportEvidenceVersion
	if len(f.TrafficBindings) == 0 && !stale {
		return ""
	}
	var out strings.Builder
	out.WriteString("\n## 关联流量证据\n\n")
	fmt.Fprintf(&out, "证据版本：%d；绑定数量：%d。\n\n", f.EvidenceVersion, len(f.TrafficBindings))
	if stale {
		out.WriteString("证据已变更，详细报告待更新。\n\n")
	}
	for i, b := range f.TrafficBindings {
		fmt.Fprintf(&out, "%d. **证据 #%d · %s** — `%s %s`，状态码 %d\n", i+1, b.ID, b.Role, b.Snapshot.Method, strings.ReplaceAll(b.Snapshot.URL, "`", "%60"), b.Snapshot.Status)
		if b.Note != "" {
			fmt.Fprintf(&out, "   %s\n", strings.ReplaceAll(b.Note, "\n", "\n   "))
		}
		if attachments {
			fmt.Fprintf(&out, "   [请求报文](evidence/%d/%d/request.http) · [响应报文](evidence/%d/%d/response.http)\n", f.ID, b.ID, f.ID, b.ID)
		}
	}
	out.WriteString("\n")
	return out.String()
}

// Neutralize formulas even when hidden behind leading whitespace/control bytes.
func spreadsheetCell(value string) string {
	trimmed := strings.TrimLeftFunc(value, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) })
	if strings.HasPrefix(value, "\t") || strings.HasPrefix(value, "\r") || strings.HasPrefix(value, "\n") ||
		(len(trimmed) > 0 && strings.ContainsRune("=+-@", rune(trimmed[0]))) {
		return "'" + value
	}
	return value
}

func findingRetestsMarkdown(f *db.DBFinding, heading string) string {
	if len(f.Retests) == 0 {
		return ""
	}
	var b strings.Builder
	fmt.Fprintf(&b, "\n%s 复测历史\n\n", heading)
	for _, r := range f.Retests {
		fmt.Fprintf(&b, "- **复测 #%d**：状态 `%s`；创建时间 %s\n", r.ID, r.Status, r.CreatedAt.Format("2006-01-02 15:04:05"))
		if r.FinishedAt != nil {
			fmt.Fprintf(&b, "  - 结束时间：%s\n", r.FinishedAt.Format("2006-01-02 15:04:05"))
		}
		if r.ConversationID != nil {
			fmt.Fprintf(&b, "  - 会话 ID：%d\n", *r.ConversationID)
		}
		if r.Verdict != "" {
			label := "暂存结论（未成功完成，不作为修复依据）"
			if r.Status == "completed" {
				label = "结论"
			}
			fmt.Fprintf(&b, "  - %s：%s\n", label, retestVerdictLabel(r.Verdict))
		}
		b.WriteString("\n")
		for _, field := range []struct{ label, value string }{
			{"复测条件 / 备注", r.Notes}, {"复测摘要", r.Summary}, {"复测证据", r.Evidence}, {"中断 / 错误原因", r.Error},
		} {
			if strings.TrimSpace(field.value) != "" {
				fmt.Fprintf(&b, "**%s：**\n\n", field.label)
				b.WriteString(evidenceBlock(field.value))
			}
		}
	}
	return b.String()
}

func retestVerdictLabel(verdict string) string {
	switch verdict {
	case "fixed":
		return "已修复"
	case "reproduced":
		return "仍可复现"
	case "inconclusive":
		return "无法确认"
	default:
		return verdict
	}
}
