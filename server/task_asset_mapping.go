package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	"github.com/Autumn-27/artex/db"
)

// taskAssetMapping starts a visible topology-mapping conversation for the task.
// The asset relationship graph still comes straight from the database and does
// not depend on this conversation; the conversation is the audit trail for the
// two human-readable reports (asset relationships + network topology).
func (s *Server) taskAssetMapping(w http.ResponseWriter, r *http.Request) {
	t, ok := s.m.Task(r.PathValue("id"))
	if !ok {
		writeErr(w, http.StatusNotFound, "task not found")
		return
	}
	if s.m.pg == nil || s.chatAgentRef() == nil {
		writeErr(w, http.StatusServiceUnavailable, s.chatUnavailableReason())
		return
	}
	if agentInfo, err := s.m.pg.GetAgentByKey("asset_mapper"); err != nil || agentInfo == nil || !agentInfo.Enabled {
		writeErr(w, http.StatusServiceUnavailable, "the asset mapping agent is disabled")
		return
	}
	taskID, _ := strconv.ParseInt(t.ID, 10, 64)
	message := fmt.Sprintf(`Map the network topology of task #%d again and produce two separate results in this one session.

The three zones are a hard constraint on this task's topology, not a formatting suggestion:
- internet: public root domains, subdomains, public IPs and external entry points.
- boundary: services, gateways, web applications or endpoints exposed outwards; only put something here when there is evidence of a public host or URL.
- internal: private IPs, loopback and link-local addresses, and the applications, endpoints and databases behind them.
The zone/zone_reason in a node summary is the authoritative classification the backend computed from real addresses and asset evidence; never rewrite a zone from the asset kind alone. Where a zone is missing or the evidence is thin, mark it "unconfirmed" rather than inventing a cross-zone connection.

Use exactly these two top-level headings and do not merge them into one:
## Asset relationships
- Use only the real asset data of this task and the tasks it directly inherits from, keeping the hierarchy and ownership recorded in the inventory.
- This section explains the asset relationship graph. Do not claim this run changed any relationship, and do not add assets the summary does not contain.

## Network topology
- Cover only the three layers (internet entry, boundary service, internal business) and say which zone each node belongs to.
- Show only connections backed by real asset evidence, and label a database node with its recognisable database type.

Both results may use only the real asset data of this task and the tasks it directly inherits from. Do not probe the target, do not modify the inventory, and do not describe an unevidenced connection as a verified path.`, taskID)
	if as := s.m.Assets(); as != nil {
		if graph, err := as.BuildCoverageGraph(taskID, t.ExpID); err == nil {
			type nodeSample struct {
				Key, Kind, Label, Domain, IP, Zone, ZoneReason string
				Port                                           int
				Tested, InScope                                bool
			}
			counts := map[string]int{}
			sample := make([]nodeSample, 0, 60)
			for _, node := range graph.Nodes {
				counts[node.Kind]++
				if len(sample) < 60 {
					sample = append(sample, nodeSample{
						Key: node.Key, Kind: node.Kind, Label: node.Label, Domain: node.Domain,
						IP: node.IP, Port: node.Port, Tested: node.Tested, InScope: node.InScope,
						Zone: node.Zone, ZoneReason: node.ZoneReason,
					})
				}
			}
			edges := graph.Edges
			truncatedEdges := len(edges) > 80
			if truncatedEdges {
				edges = edges[:80]
			}
			snapshot, _ := json.Marshal(map[string]any{
				"nodes_total": len(graph.Nodes), "edges_total": len(graph.Edges),
				"counts_by_kind": counts, "node_sample": sample, "edge_sample": edges,
				"truncated": len(graph.Nodes) > len(sample) || truncatedEdges,
			})
			message += "\n\nA real summary of the task's asset graph, just read by the page, follows. Explain only from this summary and the task scope, so global assets are not mistaken for this task's; do not write out the nodes it omits one by one:\n" + string(snapshot)
		}
	}
	title := fmt.Sprintf("asset and network mapping · task #%d", taskID)
	conversation, err := s.m.pg.CreateConversation("asset_mapper", title, nil)
	if err != nil || conversation == nil {
		writeErr(w, http.StatusInternalServerError, "could not create the mapping conversation")
		return
	}
	if _, err := s.m.pg.AppendConvActivity(conversation.ID, db.Activity{
		Worker: "asset_mapper", Kind: "user", Summary: title, Detail: message,
	}); err != nil {
		writeErr(w, http.StatusInternalServerError, "could not write to the mapping conversation")
		return
	}
	busyKey := s.convBusyKey(conversation.ID)
	s.chatMu.Lock()
	s.chatBusy[busyKey] = true
	s.chatMu.Unlock()
	s.runConversation(conversation, message, busyKey, message)
	writeJSON(w, http.StatusAccepted, map[string]any{
		"status": "accepted", "agent_key": "asset_mapper", "conversation_id": conversation.ID,
	})
}

func (s *Server) taskAssetMappingStatus(w http.ResponseWriter, r *http.Request) {
	t, ok := s.m.Task(r.PathValue("id"))
	if !ok {
		writeErr(w, http.StatusNotFound, "task not found")
		return
	}
	conversations, err := s.m.pg.ListConversations()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	title := fmt.Sprintf("asset and network mapping · task #%s", t.ID)
	for _, conversation := range conversations {
		if conversation.AgentKey != "asset_mapper" || conversation.Title != title {
			continue
		}
		busyKey := s.convBusyKey(conversation.ID)
		s.chatMu.Lock()
		running := s.chatBusy[busyKey]
		s.chatMu.Unlock()
		// A finished conversation is historical evidence, not an active run. Keep
		// looking so an older one does not hide a newer run, and so the client does
		// not poll a finished conversation after a page reload.
		if running {
			writeJSON(w, http.StatusOK, map[string]any{"running": true, "conversation_id": conversation.ID})
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"running": false})
}
