# Superseded work

Kept because the write-up refers to these as rejected or replaced designs, and a
rejected experiment that explains a design decision is worth being able to read.
Nothing here is run by `run_all.sh` and nothing here contributes a number to the
final results.

| path | what it was | why it was replaced |
|---|---|---|
| `case1_scripts/model.py` | one synthetic vtable, every slot landing on a generic returning stub | slot +0x108 is `NameValueCollection::Add` on one type, `TextWriter::WriteLine` on another and `IntPtr::op_Explicit` on a third *in this image*; a shared vtable therefore runs the wrong method whenever the receiver is not the type the slot was measured on. Replaced by per-call-site resolution (`tools/callsite_map.py` + `tools/managed_call_explorer.py`). |
| `case1_scripts/guided_explorer.py` | `LossAvoidingExplorer`: ranked the frontier away from blocks that had destroyed states | measured against the default with everything else held constant it changed no behavioural outcome — same APIs, same handlers, fewer blocks. It steers around a loss it cannot repair. Replaced by repairing the loss. |
| `tools/managed_explorer.py` | `ManagedDispatchExplorer`: novelty-ranked search that also recovered `unconstrained` states by pinning the program counter to in-image addresses | the pin is unsound. On 18 of 18 states examined the program counter was wholly free (`pc == 0xdeadbeef` satisfiable), so pinning invents control flow rather than recovering it. |

Earlier write-up drafts are not kept here: they quote figures from before the correctness pass and would be read as results. The document is rebuilt from current evidence by `tools/make_paper.py`.
