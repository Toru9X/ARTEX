package db

import (
	"strconv"
	"strings"
)

// SimilarFinding is an earlier finding that shares a vulnerability class and at
// least one asset with a new one: a likely duplicate, in this task or another
// task that tested the same assets (the asset graph is shared across tasks).
type SimilarFinding struct {
	ID     int64  `json:"finding_id"`
	NodeID int64  `json:"node_id"`
	TaskID int64  `json:"task_id"`
	Name   string `json:"name"`
	Status string `json:"status"`
}

// SimilarFindings returns up to 5 findings other than excludeID with the same
// vulnerability class (case-insensitive) and an overlapping asset, newest first.
// Findings already ruled false positive are left out.
func (s *ExplorationStore) SimilarFindings(vulnClass string, assetIDs []int64, excludeID int64) ([]SimilarFinding, error) {
	vulnClass = strings.TrimSpace(vulnClass)
	if vulnClass == "" || len(assetIDs) == 0 {
		return nil, nil
	}
	rows, err := s.db.Query(`
SELECT id, COALESCE(node_id,0), COALESCE(task_id,0), name, status FROM findings
WHERE id <> $1 AND lower(vulnclass) = lower($2) AND status <> $4
  AND EXISTS (SELECT 1 FROM jsonb_array_elements_text(asset_ids) e WHERE e::bigint = ANY($3::bigint[]))
ORDER BY id DESC LIMIT 5`, excludeID, vulnClass, int64ArrayLiteral(assetIDs), FindingFalsePositive)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SimilarFinding
	for rows.Next() {
		var f SimilarFinding
		if err := rows.Scan(&f.ID, &f.NodeID, &f.TaskID, &f.Name, &f.Status); err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// int64ArrayLiteral renders ids as a Postgres array literal ({1,2,3}).
func int64ArrayLiteral(ids []int64) string {
	parts := make([]string, len(ids))
	for i, id := range ids {
		parts[i] = strconv.FormatInt(id, 10)
	}
	return "{" + strings.Join(parts, ",") + "}"
}
