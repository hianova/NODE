/-
  NODE v1.0.0 — Pure Deterministic Systems Schema ABI Compiler
  ============================================================
  Consumes domain-free `../FLOW/{core,sdk}` (`Flow.Schema`) to configure the 256-slot
  `16,384B` `nodeArenaSchema` and emit zero-`memcpy` `build/node_schema_abi.h`.
  ZERO local definitions of theorems, lemmas, or axioms.
-/
import Flow.Schema

namespace Node

open Flow.Schema

def hdrLayout : CellLayout64 :=
  CellLayout64.stdHeader64 "hdr" "NodeHeader64" "node_flags"
    ["epoch", "tick", "state_hash", "merkle_root"]

def vmMetaLayout : CellLayout64 :=
  CellLayout64.packed64 "vm_meta" "NodeVmMeta64" "vm_meta"
    [ ("pc", .u64, 1)
    , ("fuel_budget", .u64, 1)
    , ("fuel_used", .u64, 1)
    , ("caps_mask", .u64, 1)
    , ("fault_code", .u64, 1)
    , ("reg_hash", .u64, 1)
    , ("snap_count", .u64, 1)
    , ("replay_ok", .u64, 1)
    ]

def dbspMetaLayout : CellLayout64 :=
  CellLayout64.packed64 "dbsp_meta" "NodeDbspMeta64" "dbsp_meta"
    [ ("epoch", .u64, 1)
    , ("base_rows", .u64, 1)
    , ("delta_rows", .u64, 1)
    , ("inc_ops", .u64, 1)
    , ("full_ops", .u64, 1)
    , ("wcoj_triangles", .u64, 1)
    , ("exact_match", .u64, 1)
    , ("state_root", .u64, 1)
    ]

def walMetaLayout : CellLayout64 :=
  CellLayout64.packed64 "wal_meta" "NodeWalMeta64" "wal_meta"
    [ ("committed_lsn", .u64, 1)
    , ("torn_cuts_tested", .u64, 1)
    , ("recoveries_ok", .u64, 1)
    , ("bitrot_detected", .u64, 1)
    , ("pages_live", .u64, 1)
    , ("merkle_root", .u64, 1)
    , ("last_crc", .u64, 1)
    , ("clean_flag", .u64, 1)
    ]

def consensusMetaLayout : CellLayout64 :=
  CellLayout64.packed64 "consensus_meta" "NodeConsensusMeta64" "consensus_meta"
    [ ("nodes", .u64, 1)
    , ("faulty_f", .u64, 1)
    , ("quorum_q", .u64, 1)
    , ("rounds", .u64, 1)
    , ("commits", .u64, 1)
    , ("safety_violations", .u64, 1)
    , ("crdt_converged", .u64, 1)
    , ("state_root", .u64, 1)
    ]

def dstMetaLayout : CellLayout64 :=
  CellLayout64.packed64 "dst_meta" "NodeDstMeta64" "dst_meta"
    [ ("seed", .u64, 1)
    , ("universes", .u64, 1)
    , ("ticks_total", .u64, 1)
    , ("faults_injected", .u64, 1)
    , ("partitions", .u64, 1)
    , ("crashes", .u64, 1)
    , ("violations_found", .u64, 1)
    , ("min_witness_tick", .u64, 1)
    ]

def nodeArenaSchema : ArenaSpec where
  cPrefix         := "node_schema"
  headerGuard     := "NODE_SCHEMA_ABI_H"
  totalCells      := 256
  cCellUnionName  := "NodeCell64"
  cArenaMapName   := "NodeArenaMap"
  cArenaUnionName := "NodeArena"
  regions :=
    [ { name := "hdr"
      , baseSlot := 0
      , count := 1
      , cSlotMacro := "NODE_SLOT_HDR"
      , mapDecl := "NodeHeader64 hdr;"
      }
    , { name := "vm_meta"
      , baseSlot := 1
      , count := 1
      , cSlotMacro := "NODE_SLOT_VM_META"
      , mapDecl := "NodeVmMeta64 vm_meta;"
      }
    , { name := "dbsp_meta"
      , baseSlot := 2
      , count := 4
      , cSlotMacro := "NODE_SLOT_DBSP_META_BASE"
      , cCountMacro := "NODE_COUNT_DBSP_META"
      , mapDecl := "NodeDbspMeta64 dbsp_meta[NODE_COUNT_DBSP_META];"
      }
    , { name := "wal_meta"
      , baseSlot := 6
      , count := 4
      , cSlotMacro := "NODE_SLOT_WAL_META_BASE"
      , cCountMacro := "NODE_COUNT_WAL_META"
      , mapDecl := "NodeWalMeta64 wal_meta[NODE_COUNT_WAL_META];"
      }
    , { name := "consensus_meta"
      , baseSlot := 10
      , count := 8
      , cSlotMacro := "NODE_SLOT_CONSENSUS_META_BASE"
      , cCountMacro := "NODE_COUNT_CONSENSUS_META"
      , mapDecl := "NodeConsensusMeta64 consensus_meta[NODE_COUNT_CONSENSUS_META];"
      }
    , { name := "dst_meta"
      , baseSlot := 18
      , count := 8
      , cSlotMacro := "NODE_SLOT_DST_META_BASE"
      , cCountMacro := "NODE_COUNT_DST_META"
      , mapDecl := "NodeDstMeta64 dst_meta[NODE_COUNT_DST_META];"
      }
    , { name := "aux"
      , baseSlot := 26
      , count := 230
      , cSlotMacro := "NODE_SLOT_AUX_BASE"
      , cCountMacro := "NODE_MAX_AUX"
      , mapDecl := "uint64_t aux[NODE_MAX_AUX][8];"
      }
    ]
  layouts :=
    [ hdrLayout
    , vmMetaLayout
    , dbspMetaLayout
    , walMetaLayout
    , consensusMetaLayout
    , dstMetaLayout
    ]

def emitSchemaOnly (outPath : System.FilePath) : IO Unit := do
  let ok ← ArenaSpec.emitC17HeaderChecked outPath nodeArenaSchema
  if !ok then
    throw <| IO.userError s!"Node: ArenaSpec verification failed emitting {outPath}"

end Node

def main (args : List String) : IO Unit := do
  match args with
  | ["emit-schema", outPath] => Node.emitSchemaOnly outPath
  | _ => Node.emitSchemaOnly "build/node_schema_abi.h"
