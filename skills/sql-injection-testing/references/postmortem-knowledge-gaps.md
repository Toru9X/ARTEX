# Appendix B: What Our Existing Knowledge Base Already Had (But We Ignored)

| Source | What It Contained | How It Would Have Helped |
|--------|-------------------|--------------------------|
| `payload-packs.json` line 164 | `0'XOR(if(now()=sysdate(),sleep(5),0))XOR'Z` | Direct XOR payload template |
| `shared attack patterns` line 1014-1017 | "NULL Propagation XOR Oracle" pattern | Explicit instruction to use XOR |
| `waf-generic-evasion.md` #22 | Scientific notation bypass | Alternative boolean payloads |
| `waf-generic-evasion.md` #21 | SQL function alternatives table | MID/ORD instead of blocked SUBSTR |
| `waf-generic-evasion.md` #25 | Iterative regex blacklist reversal | Step-by-step WAF defeat process |
| `hidden-param-discovery.md` | Full param discovery methodology | Would have found colour parameter |
| `deep-dive checklist` #1.6 | "Inline scripts trong HTML" checkbox | Would have triggered HTML source analysis |
| `MEMORY.md` feedback_deep_fuzz_gaps | "Self-assessment 3/10 fuzz, 4/10 SQLi" | Should have triggered extra diligence |

---

