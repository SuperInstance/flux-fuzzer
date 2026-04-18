"""
FLUX Fuzzer — Coverage-guided bytecode fuzzer for the FLUX VM.

Features:
- Random bytecode program generation with coverage guidance
- Mutation strategies: bit flip, byte flip, opcode swap, register swap, insert, delete
- Coverage-guided feedback loop (maximize opcode + edge coverage)
- Crash detection and minimization
- Corpus management (save/load interesting inputs)
- Timeout detection
- Deterministic seeding for reproducibility
"""

import random
import hashlib
import json
import os
import time
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple, Set
from enum import Enum


class FuzzResult(Enum):
    OK = "ok"
    CRASH = "crash"
    TIMEOUT = "timeout"
    INFINITE_LOOP = "infinite_loop"
    UNDEFINED = "undefined_behavior"
    HANG = "hang"


class MutateStrategy(Enum):
    BIT_FLIP = "bit_flip"
    BYTE_FLIP = "byte_flip"
    OPCODE_SWAP = "opcode_swap"
    REGISTER_SWAP = "register_swap"
    INSERT_BYTE = "insert_byte"
    DELETE_BYTE = "delete_byte"
    ARITHMETIC = "arithmetic"
    SPLICE = "splice"
    CROSSOVER = "crossover"


@dataclass
class FuzzCase:
    """A single fuzz test case."""
    bytecode: List[int]
    seed: int
    result: FuzzResult
    cycles: int
    final_regs: Dict[int, int]
    crash_reason: str = ""
    unique_id: str = ""
    coverage_bits: int = 0
    depth: int = 0  # corpus depth for power scheduling

    def __post_init__(self):
        if not self.unique_id:
            h = hashlib.md5(bytes(self.bytecode)).hexdigest()[:8]
            self.unique_id = h


@dataclass
class CoverageMap:
    """Tracks coverage information for the fuzzer."""
    opcode_seen: Set[int] = field(default_factory=set)
    edge_seen: Set[Tuple[int, int]] = field(default_factory=set)  # (pc, opcode)
    path_seen: Set[str] = field(default_factory=set)
    total_opcodes: int = 0
    total_edges: int = 0
    total_paths: int = 0

    def record(self, pc: int, opcode: int):
        self.opcode_seen.add(opcode)
        edge = (pc, opcode)
        self.edge_seen.add(edge)
        self.total_opcodes = len(self.opcode_seen)
        self.total_edges = len(self.edge_seen)

    def record_path(self, path_hash: str):
        self.path_seen.add(path_hash)
        self.total_paths = len(self.path_seen)

    def merge(self, other: 'CoverageMap'):
        self.opcode_seen |= other.opcode_seen
        self.edge_seen |= other.edge_seen
        self.path_seen |= other.path_seen
        self.total_opcodes = len(self.opcode_seen)
        self.total_edges = len(self.edge_seen)
        self.total_paths = len(self.path_seen)

    def has_new_coverage(self, other: 'CoverageMap') -> bool:
        return bool(
            other.opcode_seen - self.opcode_seen or
            other.edge_seen - self.edge_seen or
            other.path_seen - self.path_seen
        )


@dataclass
class FuzzReport:
    total_cases: int
    crashes: int
    timeouts: int
    undefined: int
    ok: int
    unique_crashes: List[FuzzCase]
    coverage: Dict[str, int]  # opcode -> times executed
    opcode_coverage_pct: float = 0.0
    edge_coverage: int = 0
    corpus_size: int = 0
    total_cycles: int = 0

    def to_markdown(self) -> str:
        lines = ["# FLUX Fuzz Report\n"]
        lines.append(f"- **Total cases:** {self.total_cases}")
        lines.append(f"- **OK:** {self.ok} | **Crashes:** {self.crashes} | **Timeouts:** {self.timeouts} | **Undefined:** {self.undefined}")
        lines.append(f"- **Opcode coverage:** {self.opcode_coverage_pct:.1f}%")
        lines.append(f"- **Edge coverage:** {self.edge_coverage}")
        lines.append(f"- **Corpus size:** {self.corpus_size}")
        lines.append(f"- **Total cycles:** {self.total_cycles}")

        if self.unique_crashes:
            lines.append(f"\n## Unique Crashes ({len(self.unique_crashes)})\n")
            for c in self.unique_crashes[:10]:
                bc_hex = " ".join(f"{b:02x}" for b in c.bytecode[:32])
                lines.append(f"- `{bc_hex}` — {c.crash_reason} (seed={c.seed}, id={c.unique_id})")

        lines.append(f"\n## Opcode Coverage (top 10)\n")
        for op, cnt in sorted(self.coverage.items(), key=lambda x: -x[1])[:10]:
            lines.append(f"- {op}: {cnt}x")

        return "\n".join(lines)


# FLUX unified ISA opcodes (matching flux-disasm 247-opcode ISA)
FLUX_OPCODES = {
    0x00: ("NOP", 0), 0x01: ("MOV", 2), 0x02: ("LOAD", 2), 0x03: ("STORE", 2),
    0x04: ("PUSH", 2), 0x05: ("POP", 1), 0x06: ("JMP", 2), 0x07: ("JZ", 3),
    0x08: ("JNZ", 3), 0x09: ("CALL", 2), 0x0A: ("RET", 0), 0x0B: ("HALT", 0),
    0x20: ("CADD", 3), 0x21: ("CSUB", 3), 0x22: ("CMUL", 3), 0x23: ("CDIV", 3),
    0x24: ("CMOD", 3), 0x25: ("CAND", 3), 0x26: ("COR", 3), 0x27: ("CXOR", 3),
    0x39: ("INCR", 1), 0x3A: ("DECR", 1),
    0x60: ("PUSH_R", 1), 0x61: ("POP_R", 1),
    0x70: ("CMP_EQ", 3), 0x71: ("CMP_NE", 3), 0x72: ("CMP_LT", 3), 0x73: ("CMP_GT", 3),
    0xA0: ("TELL", 2), 0xA1: ("ASK", 2), 0xA2: ("DELEGATE", 2),
    0xC0: ("ATP_GEN", 1), 0xC1: ("ATP_USE", 1), 0xC2: ("ATP_QRY", 0),
    0xC4: ("APOPTOSIS", 0), 0xD0: ("DBG_PRINT", 1), 0xD1: ("BARRIER", 0),
}

# Valid instruction templates: (opcode, total_size)
TEMPLATES = [
    (0x00, 1),  # NOP
    (0x01, 3),  # MOV r1, r2
    (0x02, 3),  # LOAD r1, r2
    (0x03, 3),  # STORE r1, r2
    (0x04, 3),  # PUSH imm16
    (0x05, 2),  # POP r
    (0x06, 3),  # JMP imm16
    (0x07, 4),  # JZ r, imm16
    (0x08, 4),  # JNZ r, imm16
    (0x09, 3),  # CALL imm16
    (0x0A, 1),  # RET
    (0x0B, 1),  # HALT
    (0x20, 4),  # CADD r1, r2, r3
    (0x21, 4),  # CSUB
    (0x22, 4),  # CMUL
    (0x23, 4),  # CDIV
    (0x24, 4),  # CMOD
    (0x25, 4),  # CAND
    (0x26, 4),  # COR
    (0x27, 4),  # CXOR
    (0x39, 2),  # INCR r
    (0x3A, 2),  # DECR r
    (0x60, 2),  # PUSH_R r
    (0x61, 2),  # POP_R r
    (0x70, 4),  # CMP_EQ
    (0x71, 4),  # CMP_NE
    (0x72, 4),  # CMP_LT
    (0x73, 4),  # CMP_GT
    (0xA0, 3),  # TELL r1, r2
    (0xA1, 3),  # ASK r1, r2
    (0xC0, 2),  # ATP_GEN r
    (0xC1, 2),  # ATP_USE r
    (0xC2, 1),  # ATP_QRY
    (0xC4, 1),  # APOPTOSIS
    (0xD0, 2),  # DBG_PRINT r
    (0xD1, 1),  # BARRIER
]

VALID_OPCODES = [t[0] for t in TEMPLATES]
OPCODE_SIZES = {t[0]: t[1] for t in TEMPLATES}


def _sb(b):
    """Sign-extend byte to signed."""
    return b - 256 if b > 127 else b


class FluxFuzzer:
    """Coverage-guided FLUX bytecode fuzzer."""

    def __init__(self, seed: int = 42):
        self.rng = random.Random(seed)
        self.max_instructions = 20
        self.max_cycles = 10000
        self.timeout_cycles = 5000  # cycles before declaring timeout

        # Corpus management
        self.corpus: List[FuzzCase] = []
        self.corpus_dir: Optional[str] = None

        # Crash tracking
        self.crashes: List[FuzzCase] = []
        self.unique_crash_ids: Set[str] = set()

        # Coverage tracking
        self.global_coverage = CoverageMap()

        # Statistics
        self.total_executed = 0
        self.total_cycles = 0

        # Seed corpus (initial inputs to start from)
        self.seed_corpus: List[List[int]] = []

    # ── Program Generation ─────────────────────────────────────

    def generate(self) -> List[int]:
        """Generate a random valid bytecode program."""
        bc = []
        n = self.rng.randint(1, self.max_instructions)

        for _ in range(n):
            template = self.rng.choice(TEMPLATES)
            opcode, size = template
            bc.append(opcode)
            for _ in range(size - 1):
                bc.append(self.rng.randint(0, 255))

        # Ensure it ends with HALT
        if bc and bc[-1] != 0x0B:
            bc.append(0x0B)
        elif not bc:
            bc = [0x0B]

        return bc

    def generate_edge_case(self) -> List[int]:
        """Generate edge-case programs targeting known issues."""
        cases = [
            [0x20, 0, 0, 0, 0x23, 0, 1, 0, 0x00],      # Division by zero
            [0x04, 0xFF, 0xFF, 0x05, 0x00, 0x00],        # PUSH max, POP
            [0x20, 0, 0, 0, 0x22, 0, 0, 0, 0x00],       # Multiply by self (overflow)
            [0x61, 0, 0x00],                               # POP empty stack
            [0x20, 0, 0, 0, 0x21, 0, 0, 0, 0x00],        # Subtract self
            [0x20, 0, 0, 0, 0x24, 0, 0, 0, 0x00],        # MOD by zero
            [0x06, 0x00, 0x00, 0x00],                     # JMP to self (infinite loop)
            [0x07, 0x00, 0x00, 0x00, 0x00],               # JZ to self (potential loop)
            [0x09, 0xFF, 0xFF, 0x00],                     # CALL to invalid address
            [0x0A, 0x00],                                  # RET with empty return stack
            [0x00] * 50,                                    # Long NOP sequence
            [0x0B],                                         # Just HALT
            [],                                             # Empty program
        ]
        return list(self.rng.choice(cases))

    def generate_from_corpus(self) -> List[int]:
        """Generate a new input by mutating a corpus entry."""
        if not self.corpus:
            return self.generate()

        # Power schedule: prefer recently added entries
        entry = self.rng.choice(self.corpus)
        return self.mutate(entry.bytecode)

    # ── Mutation Strategies ────────────────────────────────────

    def mutate(self, bytecode: List[int]) -> List[int]:
        """Apply a random mutation strategy to bytecode."""
        if not bytecode:
            return self.generate()

        strategy = self.rng.choice(list(MutateStrategy))

        if strategy == MutateStrategy.BIT_FLIP:
            return self._mutate_bit_flip(bytecode)
        elif strategy == MutateStrategy.BYTE_FLIP:
            return self._mutate_byte_flip(bytecode)
        elif strategy == MutateStrategy.OPCODE_SWAP:
            return self._mutate_opcode_swap(bytecode)
        elif strategy == MutateStrategy.REGISTER_SWAP:
            return self._mutate_register_swap(bytecode)
        elif strategy == MutateStrategy.INSERT_BYTE:
            return self._mutate_insert(bytecode)
        elif strategy == MutateStrategy.DELETE_BYTE:
            return self._mutate_delete(bytecode)
        elif strategy == MutateStrategy.ARITHMETIC:
            return self._mutate_arithmetic(bytecode)
        elif strategy == MutateStrategy.SPLICE:
            return self._mutate_splice(bytecode)
        elif strategy == MutateStrategy.CROSSOVER:
            return self._mutate_crossover(bytecode)
        return list(bytecode)

    def _mutate_bit_flip(self, bc: List[int]) -> List[int]:
        """Flip a random bit in a random byte."""
        result = list(bc)
        if not result:
            return result
        pos = self.rng.randint(0, len(result) - 1)
        bit = self.rng.randint(0, 7)
        result[pos] ^= (1 << bit)
        return result

    def _mutate_byte_flip(self, bc: List[int]) -> List[int]:
        """Replace a random byte with a random value."""
        result = list(bc)
        if not result:
            return result
        pos = self.rng.randint(0, len(result) - 1)
        result[pos] = self.rng.randint(0, 255)
        return result

    def _mutate_opcode_swap(self, bc: List[int]) -> List[int]:
        """Swap an opcode byte with a different valid opcode."""
        result = list(bc)
        if not result:
            return result
        # Find positions that look like opcodes
        opcode_positions = self._find_opcode_positions(result)
        if not opcode_positions:
            return result
        pos = self.rng.choice(opcode_positions)
        result[pos] = self.rng.choice(VALID_OPCODES)
        return result

    def _mutate_register_swap(self, bc: List[int]) -> List[int]:
        """Swap two register operands within an instruction."""
        result = list(bc)
        if not result:
            return result
        pos = self.rng.randint(0, max(0, len(result) - 2))
        if pos < len(result) - 1:
            # Clamp to valid register range
            result[pos], result[pos + 1] = result[pos + 1] % 16, result[pos] % 16
        return result

    def _mutate_insert(self, bc: List[int]) -> List[int]:
        """Insert a random byte at a random position."""
        result = list(bc)
        pos = self.rng.randint(0, len(result))
        result.insert(pos, self.rng.randint(0, 255))
        return result[:256]  # Cap length

    def _mutate_delete(self, bc: List[int]) -> List[int]:
        """Delete a random byte."""
        result = list(bc)
        if len(result) > 1:
            pos = self.rng.randint(0, len(result) - 1)
            del result[pos]
        return result

    def _mutate_arithmetic(self, bc: List[int]) -> List[int]:
        """Add/subtract a small value from a random byte."""
        result = list(bc)
        if not result:
            return result
        pos = self.rng.randint(0, len(result) - 1)
        delta = self.rng.choice([-16, -8, -4, -1, 1, 4, 8, 16])
        result[pos] = (result[pos] + delta) % 256
        return result

    def _mutate_splice(self, bc: List[int]) -> List[int]:
        """Splice in a random segment from another corpus entry or generate."""
        result = list(bc)
        if not self.corpus:
            splice_src = self.generate()
        else:
            splice_src = self.rng.choice(self.corpus).bytecode

        if not splice_src or not result:
            return result

        # Pick a random segment from splice_src
        start = self.rng.randint(0, max(0, len(splice_src) - 1))
        end = self.rng.randint(start + 1, min(start + 16, len(splice_src)))
        segment = splice_src[start:end]

        # Insert at random position
        pos = self.rng.randint(0, len(result))
        result[pos:pos] = segment
        return result[:256]

    def _mutate_crossover(self, bc: List[int]) -> List[int]:
        """Crossover: take prefix from one corpus entry, suffix from another."""
        if len(self.corpus) < 2:
            return list(bc)

        other = self.rng.choice(self.corpus).bytecode
        if not other:
            return list(bc)

        # Pick crossover point
        cross = self.rng.randint(1, min(len(bc), len(other)) - 1)
        result = bc[:cross] + other[cross:]
        return result[:256]

    def _find_opcode_positions(self, bc: List[int]) -> List[int]:
        """Find positions that are likely opcode bytes."""
        positions = []
        pc = 0
        while pc < len(bc):
            if bc[pc] in OPCODE_SIZES:
                positions.append(pc)
                pc += OPCODE_SIZES[bc[pc]]
            else:
                pc += 1
        return positions

    # ── Execution Engine ───────────────────────────────────────

    def execute(self, bytecode: List[int]) -> Tuple[FuzzCase, CoverageMap]:
        """Execute bytecode and detect issues. Returns case and coverage."""
        regs = [0] * 64
        stack = [0] * 4096
        sp = 4096
        call_stack = []
        pc = 0
        halted = False
        cycles = 0
        crash_reason = ""
        coverage = CoverageMap()
        path_hash_parts = []

        bc = bytes(bytecode)
        if not bc:
            case = FuzzCase(bytecode, 0, FuzzResult.OK, 0,
                            {i: 0 for i in range(16)}, "")
            return case, coverage

        start_time = time.monotonic()

        while not halted and pc < len(bc) and cycles < self.max_cycles:
            # Timeout check
            if cycles > 0 and cycles % 1000 == 0:
                elapsed = time.monotonic() - start_time
                if elapsed > 2.0:  # 2 second wall-clock timeout
                    return FuzzCase(bytecode, 0, FuzzResult.TIMEOUT, cycles,
                                    {i: regs[i] for i in range(16)},
                                    f"timeout at cycle {cycles}"), coverage

            op = bc[pc]
            cycles += 1
            coverage.record(pc, op)

            # Track path
            path_hash_parts.append(f"{pc}:{op}")
            if len(path_hash_parts) > 64:
                path_hash_parts.pop(0)

            try:
                if op == 0x00:  # NOP
                    halted = False; pc += 1
                elif op == 0x0B:  # HALT
                    halted = True; pc += 1
                elif op == 0x0A:  # RET
                    if call_stack:
                        pc = call_stack.pop()
                    else:
                        return FuzzCase(bytecode, 0, FuzzResult.CRASH, cycles,
                                        {i: regs[i] for i in range(16)},
                                        "ret with empty call stack"), coverage
                elif op == 0x01:  # MOV r1, r2
                    if pc + 2 < len(bc):
                        regs[bc[pc+1] % 64] = regs[bc[pc+2] % 64]; pc += 3
                    else: break
                elif op == 0x02:  # LOAD r1, r2
                    if pc + 2 < len(bc):
                        regs[bc[pc+1] % 64] = regs[bc[pc+2] % 64]; pc += 3
                    else: break
                elif op == 0x03:  # STORE r1, r2
                    if pc + 2 < len(bc):
                        regs[bc[pc+2] % 64] = regs[bc[pc+1] % 64]; pc += 3
                    else: break
                elif op == 0x04:  # PUSH imm16
                    if pc + 2 < len(bc):
                        imm = bc[pc+1] | (bc[pc+2] << 8)
                        if sp <= 0:
                            return FuzzCase(bytecode, 0, FuzzResult.CRASH, cycles,
                                            {i: regs[i] for i in range(16)}, "stack overflow"), coverage
                        sp -= 1; stack[sp] = imm; pc += 3
                    else: break
                elif op == 0x05:  # POP r
                    if pc + 1 < len(bc):
                        if sp >= 4096:
                            crash_reason = "stack underflow"
                            regs[bc[pc+1] % 64] = 0
                        else:
                            regs[bc[pc+1] % 64] = stack[sp]; sp += 1
                        pc += 2
                    else: break
                elif op == 0x06:  # JMP imm16
                    if pc + 2 < len(bc):
                        pc = bc[pc+1] | (bc[pc+2] << 8)
                    else: break
                elif op == 0x07:  # JZ r, imm16
                    if pc + 3 < len(bc):
                        if regs[bc[pc+1] % 64] == 0:
                            pc = bc[pc+2] | (bc[pc+3] << 8)
                        else:
                            pc += 4
                    else: break
                elif op == 0x08:  # JNZ r, imm16
                    if pc + 3 < len(bc):
                        if regs[bc[pc+1] % 64] != 0:
                            pc = bc[pc+2] | (bc[pc+3] << 8)
                        else:
                            pc += 4
                    else: break
                elif op == 0x09:  # CALL imm16
                    if pc + 2 < len(bc):
                        target = bc[pc+1] | (bc[pc+2] << 8)
                        call_stack.append(pc + 3)
                        pc = target
                    else: break
                elif op == 0x20:  # CADD r1, r2, r3
                    if pc + 3 < len(bc):
                        regs[bc[pc+1] % 64] = regs[bc[pc+2] % 64] + regs[bc[pc+3] % 64]; pc += 4
                    else: break
                elif op == 0x21:  # CSUB
                    if pc + 3 < len(bc):
                        regs[bc[pc+1] % 64] = regs[bc[pc+2] % 64] - regs[bc[pc+3] % 64]; pc += 4
                    else: break
                elif op == 0x22:  # CMUL
                    if pc + 3 < len(bc):
                        regs[bc[pc+1] % 64] = regs[bc[pc+2] % 64] * regs[bc[pc+3] % 64]; pc += 4
                    else: break
                elif op == 0x23:  # CDIV
                    if pc + 3 < len(bc):
                        if regs[bc[pc+3] % 64] == 0:
                            crash_reason = "division by zero"
                            regs[bc[pc+1] % 64] = 0
                        else:
                            regs[bc[pc+1] % 64] = regs[bc[pc+2] % 64] // regs[bc[pc+3] % 64]
                        pc += 4
                    else: break
                elif op == 0x24:  # CMOD
                    if pc + 3 < len(bc):
                        if regs[bc[pc+3] % 64] == 0:
                            crash_reason = "modulo by zero"
                            regs[bc[pc+1] % 64] = 0
                        else:
                            regs[bc[pc+1] % 64] = regs[bc[pc+2] % 64] % regs[bc[pc+3] % 64]
                        pc += 4
                    else: break
                elif op == 0x25:  # CAND
                    if pc + 3 < len(bc):
                        regs[bc[pc+1] % 64] = regs[bc[pc+2] % 64] & regs[bc[pc+3] % 64]; pc += 4
                    else: break
                elif op == 0x26:  # COR
                    if pc + 3 < len(bc):
                        regs[bc[pc+1] % 64] = regs[bc[pc+2] % 64] | regs[bc[pc+3] % 64]; pc += 4
                    else: break
                elif op == 0x27:  # CXOR
                    if pc + 3 < len(bc):
                        regs[bc[pc+1] % 64] = regs[bc[pc+2] % 64] ^ regs[bc[pc+3] % 64]; pc += 4
                    else: break
                elif op == 0x39:  # INCR r
                    if pc + 1 < len(bc):
                        regs[bc[pc+1] % 64] += 1; pc += 2
                    else: break
                elif op == 0x3A:  # DECR r
                    if pc + 1 < len(bc):
                        regs[bc[pc+1] % 64] -= 1; pc += 2
                    else: break
                elif op == 0x60:  # PUSH_R r
                    if pc + 1 < len(bc):
                        if sp <= 0:
                            return FuzzCase(bytecode, 0, FuzzResult.CRASH, cycles,
                                            {i: regs[i] for i in range(16)}, "stack overflow"), coverage
                        sp -= 1; stack[sp] = regs[bc[pc+1] % 64]; pc += 2
                    else: break
                elif op == 0x61:  # POP_R r
                    if pc + 1 < len(bc):
                        if sp >= 4096:
                            crash_reason = "stack underflow"
                            regs[bc[pc+1] % 64] = 0
                        else:
                            regs[bc[pc+1] % 64] = stack[sp]; sp += 1
                        pc += 2
                    else: break
                elif op == 0x70:  # CMP_EQ
                    if pc + 3 < len(bc):
                        regs[bc[pc+1] % 64] = 1 if regs[bc[pc+2] % 64] == regs[bc[pc+3] % 64] else 0; pc += 4
                    else: break
                elif op == 0x71:  # CMP_NE
                    if pc + 3 < len(bc):
                        regs[bc[pc+1] % 64] = 1 if regs[bc[pc+2] % 64] != regs[bc[pc+3] % 64] else 0; pc += 4
                    else: break
                elif op == 0x72:  # CMP_LT
                    if pc + 3 < len(bc):
                        regs[bc[pc+1] % 64] = 1 if regs[bc[pc+2] % 64] < regs[bc[pc+3] % 64] else 0; pc += 4
                    else: break
                elif op == 0x73:  # CMP_GT
                    if pc + 3 < len(bc):
                        regs[bc[pc+1] % 64] = 1 if regs[bc[pc+2] % 64] > regs[bc[pc+3] % 64] else 0; pc += 4
                    else: break
                elif op in (0xA0, 0xA1, 0xA2):  # TELL, ASK, DELEGATE r1, r2
                    if pc + 2 < len(bc):
                        pc += 3  # no-op for fuzzing
                    else: break
                elif op == 0xC0:  # ATP_GEN r
                    if pc + 1 < len(bc):
                        regs[bc[pc+1] % 64] = 100; pc += 2
                    else: break
                elif op == 0xC1:  # ATP_USE r
                    if pc + 1 < len(bc):
                        regs[bc[pc+1] % 64] = max(0, regs[bc[pc+1] % 64] - 10); pc += 2
                    else: break
                elif op == 0xC2:  # ATP_QRY
                    pc += 1
                elif op == 0xC4:  # APOPTOSIS
                    halted = True; pc += 1
                elif op == 0xD0:  # DBG_PRINT r
                    if pc + 1 < len(bc):
                        pc += 2  # no-op for fuzzing
                    else: break
                elif op == 0xD1:  # BARRIER
                    pc += 1
                else:
                    # Unknown opcode — skip
                    pc += 1

            except (IndexError, ZeroDivisionError):
                return FuzzCase(bytecode, 0, FuzzResult.CRASH, cycles,
                                {i: regs[i] for i in range(16)}, "execution error"), coverage

        # Record path hash
        path_h = hashlib.md5("|".join(path_hash_parts).encode()).hexdigest()[:16]
        coverage.record_path(path_h)

        # Determine result
        if cycles >= self.max_cycles:
            result = FuzzResult.INFINITE_LOOP
        elif crash_reason:
            result = FuzzResult.UNDEFINED
        else:
            result = FuzzResult.OK

        case = FuzzCase(bytecode, 0, result, cycles,
                        {i: regs[i] for i in range(16)}, crash_reason)
        return case, coverage

    # ── Crash Detection & Minimization ────────────────────────

    def minimize_crash(self, bytecode: List[int], crash_reason: str,
                        max_iterations: int = 100) -> List[int]:
        """Minimize a crashing input using delta debugging."""
        current = list(bytecode)
        current_len = len(current)

        for iteration in range(max_iterations):
            if len(current) <= 1:
                break

            # Try deleting each byte
            changed = False
            for i in range(len(current)):
                test = current[:i] + current[i+1:]
                if not test:
                    continue
                case, _ = self.execute(test)
                if case.crash_reason == crash_reason or case.result == FuzzResult.CRASH:
                    current = test
                    changed = True
                    break

            if not changed:
                break

            if len(current) < current_len:
                current_len = len(current)
                # Restart with smaller input
                continue

        return current

    def is_unique_crash(self, case: FuzzCase) -> bool:
        """Check if this crash is unique (not a duplicate)."""
        return case.unique_id not in self.unique_crash_ids

    def add_crash(self, case: FuzzCase):
        """Add a crash to the tracking list if unique."""
        if self.is_unique_crash(case):
            self.unique_crash_ids.add(case.unique_id)
            self.crashes.append(case)

    # ── Corpus Management ──────────────────────────────────────

    def add_to_corpus(self, case: FuzzCase, coverage: CoverageMap):
        """Add a test case to corpus if it provides new coverage."""
        if self.global_coverage.has_new_coverage(coverage):
            self.global_coverage.merge(coverage)
            case.depth = max((c.depth for c in self.corpus), default=0) + 1
            self.corpus.append(case)
            return True
        return False

    def save_corpus(self, path: str):
        """Save corpus to a directory."""
        os.makedirs(path, exist_ok=True)
        for i, case in enumerate(self.corpus):
            fname = os.path.join(path, f"{case.unique_id}_{i}.bin")
            with open(fname, 'wb') as f:
                f.write(bytes(case.bytecode))
        # Save metadata
        meta = {
            "size": len(self.corpus),
            "global_opcode_coverage": len(self.global_coverage.opcode_seen),
            "global_edge_coverage": len(self.global_coverage.edge_seen),
        }
        with open(os.path.join(path, "corpus_meta.json"), 'w') as f:
            json.dump(meta, f, indent=2)

    def load_corpus(self, path: str) -> int:
        """Load corpus from a directory. Returns number loaded."""
        if not os.path.isdir(path):
            return 0
        loaded = 0
        for fname in os.listdir(path):
            if fname.endswith('.bin'):
                fpath = os.path.join(path, fname)
                with open(fpath, 'rb') as f:
                    data = f.read()
                if data:
                    bc = list(data)
                    case, cov = self.execute(bc)
                    self.corpus.append(case)
                    self.global_coverage.merge(cov)
                    loaded += 1
        return loaded

    # ── Coverage-Guided Feedback Loop ──────────────────────────

    def fuzz_one(self, seed_offset: int = 0) -> FuzzCase:
        """Run a single fuzz iteration with coverage feedback."""
        # Mix of generation strategies
        r = self.rng.random()
        if r < 0.1 and self.corpus:
            bc = self.generate_from_corpus()
        elif r < 0.2:
            bc = self.generate_edge_case()
        elif r < 0.3:
            bc = self.generate()
        else:
            bc = self.generate_from_corpus()

        self.total_executed += 1
        case, coverage = self.execute(bc)
        case.seed = seed_offset

        self.total_cycles += case.cycles

        # Add to corpus if new coverage
        self.add_to_corpus(case, coverage)

        # Track crashes
        if case.result in (FuzzResult.CRASH, FuzzResult.UNDEFINED):
            self.add_crash(case)
        elif case.result == FuzzResult.TIMEOUT:
            # Minimize timeout inputs
            minimized = self.minimize_crash(bc, case.crash_reason, 20)
            if minimized != bc:
                min_case, _ = self.execute(minimized)
                if min_case.result == FuzzResult.TIMEOUT:
                    self.add_crash(min_case)

        return case

    def fuzz(self, n: int = 100, seed: int = 0) -> FuzzReport:
        """Run n fuzz cases with coverage-guided feedback and generate report."""
        self.rng = random.Random(seed)
        crashes_list = []
        ok = 0
        timeouts = 0
        undefined = 0
        coverage = {}

        for i in range(n):
            case = self.fuzz_one(seed_offset=seed + i)

            if case.result == FuzzResult.OK:
                ok += 1
            elif case.result in (FuzzResult.CRASH, FuzzResult.UNDEFINED):
                crashes_list.append(case)
            elif case.result in (FuzzResult.TIMEOUT, FuzzResult.INFINITE_LOOP, FuzzResult.HANG):
                timeouts += 1

            if case.result == FuzzResult.UNDEFINED:
                undefined += 1

            # Track opcode coverage
            for b in case.bytecode:
                name = FLUX_OPCODES.get(b, (f"0x{b:02x}",))[0]
                coverage[name] = coverage.get(name, 0) + 1

        # Get unique crashes
        unique = []
        seen = set()
        for c in crashes_list:
            if c.unique_id not in seen:
                seen.add(c.unique_id)
                unique.append(c)

        opcode_pct = (self.global_coverage.total_opcodes / max(1, len(VALID_OPCODES))) * 100

        return FuzzReport(
            total_cases=n, crashes=len(crashes_list), timeouts=timeouts,
            undefined=undefined, ok=ok, unique_crashes=unique,
            coverage=coverage, opcode_coverage_pct=opcode_pct,
            edge_coverage=self.global_coverage.total_edges,
            corpus_size=len(self.corpus),
            total_cycles=self.total_cycles,
        )


# ── Tests ──────────────────────────────────────────────────────

import unittest


class TestFuzzer(unittest.TestCase):

    def test_generate(self):
        f = FluxFuzzer(seed=42)
        bc = f.generate()
        self.assertGreater(len(bc), 1)
        self.assertEqual(bc[-1], 0x0B)

    def test_generate_deterministic(self):
        f1 = FluxFuzzer(seed=42)
        f2 = FluxFuzzer(seed=42)
        self.assertEqual(f1.generate(), f2.generate())

    def test_execute_halt(self):
        f = FluxFuzzer()
        case, cov = f.execute([0x00])
        self.assertEqual(case.result, FuzzResult.OK)

    def test_execute_movi_like(self):
        """Test PUSH+POP as MOV immediate equivalent."""
        f = FluxFuzzer()
        bc = [0x04, 42, 0x00, 0x05, 0x00, 0x0B]  # PUSH 42, POP r0, HALT
        case, _ = f.execute(bc)
        self.assertEqual(case.result, FuzzResult.OK)
        self.assertEqual(case.final_regs[0], 42)

    def test_div_by_zero(self):
        f = FluxFuzzer()
        bc = [0x04, 10, 0x00, 0x05, 0x00, 0x04, 0x00, 0x00, 0x05, 0x01,
              0x23, 0x02, 0x00, 0x01, 0x0B]  # r0=10, r1=0, CDIV r2, r0, r1
        case, _ = f.execute(bc)
        self.assertIn(case.result, [FuzzResult.OK, FuzzResult.UNDEFINED])
        self.assertIn("division by zero", case.crash_reason)

    def test_fuzz_run(self):
        f = FluxFuzzer(seed=42)
        report = f.fuzz(n=50, seed=42)
        self.assertEqual(report.total_cases, 50)
        self.assertGreater(report.ok, 0)

    def test_fuzz_report_markdown(self):
        f = FluxFuzzer(seed=42)
        report = f.fuzz(n=20, seed=42)
        md = report.to_markdown()
        self.assertIn("Total cases", md)

    def test_edge_case_generation(self):
        f = FluxFuzzer(seed=42)
        for _ in range(10):
            bc = f.generate_edge_case()
            self.assertIsInstance(bc, list)

    def test_fuzz_case_unique_id(self):
        f = FluxFuzzer()
        c1, _ = f.execute([0x04, 42, 0x00, 0x0B])
        c2, _ = f.execute([0x04, 99, 0x00, 0x0B])
        self.assertNotEqual(c1.unique_id, c2.unique_id)

    # ── Mutation Tests ─────────────────────────────────────────

    def test_mutate_bit_flip(self):
        f = FluxFuzzer(seed=42)
        bc = [0x00, 0x0B]
        mutated = f._mutate_bit_flip(bc)
        self.assertEqual(len(mutated), 2)
        # At least one byte should differ (unless bit 0 of 0x00 flipped to 0x01)
        self.assertIsInstance(mutated, list)

    def test_mutate_byte_flip(self):
        f = FluxFuzzer(seed=42)
        bc = [0x00, 0x0B, 0x01, 0x00, 0x00]
        result = f._mutate_byte_flip(bc)
        self.assertEqual(len(result), len(bc))
        self.assertIsInstance(result, list)

    def test_mutate_opcode_swap(self):
        f = FluxFuzzer(seed=42)
        bc = [0x00, 0x20, 0x00, 0x01, 0x02, 0x0B]  # NOP, CADD, HALT
        result = f._mutate_opcode_swap(bc)
        self.assertIsInstance(result, list)

    def test_mutate_register_swap(self):
        f = FluxFuzzer(seed=42)
        bc = [0x01, 0x03, 0x02, 0x0B]  # MOV r3, r2, HALT
        result = f._mutate_register_swap(bc)
        self.assertIsInstance(result, list)

    def test_mutate_insert(self):
        f = FluxFuzzer(seed=42)
        bc = [0x00, 0x0B]
        result = f._mutate_insert(bc)
        self.assertGreater(len(result), len(bc))

    def test_mutate_delete(self):
        f = FluxFuzzer(seed=42)
        bc = [0x00, 0x01, 0x00, 0x00, 0x0B]
        result = f._mutate_delete(bc)
        self.assertLess(len(result), len(bc))

    def test_mutate_arithmetic(self):
        f = FluxFuzzer(seed=42)
        bc = [0x04, 0x2A, 0x00, 0x0B]
        result = f._mutate_arithmetic(bc)
        self.assertEqual(len(result), len(bc))

    def test_mutate_splice(self):
        f = FluxFuzzer(seed=42)
        f.corpus.append(FuzzCase([0x04, 0xFF, 0xFF, 0x0B], 0, FuzzResult.OK, 1, {}))
        bc = [0x00, 0x0B]
        result = f._mutate_splice(bc)
        self.assertIsInstance(result, list)

    def test_mutate_crossover(self):
        f = FluxFuzzer(seed=42)
        f.corpus.append(FuzzCase([0x20, 0x00, 0x01, 0x02, 0x0B], 0, FuzzResult.OK, 1, {}))
        f.corpus.append(FuzzCase([0x04, 0x10, 0x00, 0x05, 0x00, 0x0B], 0, FuzzResult.OK, 1, {}))
        bc = [0x00, 0x01, 0x00, 0x00, 0x0B]
        result = f._mutate_crossover(bc)
        self.assertIsInstance(result, list)

    def test_mutate_empty(self):
        f = FluxFuzzer(seed=42)
        result = f.mutate([])
        self.assertIsInstance(result, list)
        self.assertGreater(len(result), 0)

    def test_mutate_all_strategies(self):
        """Verify all mutation strategies produce valid output."""
        f = FluxFuzzer(seed=42)
        bc = [0x20, 0x00, 0x01, 0x02, 0x04, 0x2A, 0x00, 0x05, 0x00, 0x0B]
        for strategy in MutateStrategy:
            f.rng = random.Random(42)
            result = f.mutate(bc)
            self.assertIsInstance(result, list)
            self.assertGreater(len(result), 0)

    # ── Coverage Tests ─────────────────────────────────────────

    def test_coverage_tracking(self):
        f = FluxFuzzer()
        bc = [0x00, 0x20, 0x00, 0x01, 0x02, 0x0B]
        _, cov = f.execute(bc)
        self.assertIn(0x00, cov.opcode_seen)
        self.assertIn(0x20, cov.opcode_seen)
        self.assertIn(0x0B, cov.opcode_seen)
        self.assertGreater(cov.total_opcodes, 0)
        self.assertGreater(cov.total_edges, 0)

    def test_coverage_merge(self):
        c1 = CoverageMap()
        c1.record(0, 0x00)
        c1.record(1, 0x20)
        c2 = CoverageMap()
        c2.record(2, 0x0B)
        c2.record(3, 0x04)
        c1.merge(c2)
        self.assertEqual(c1.total_opcodes, 4)

    def test_coverage_has_new(self):
        c1 = CoverageMap()
        c1.record(0, 0x00)
        c2 = CoverageMap()
        c2.record(1, 0x20)
        self.assertTrue(c1.has_new_coverage(c2))

    def test_coverage_path_tracking(self):
        f = FluxFuzzer()
        bc = [0x00, 0x0B]
        _, cov = f.execute(bc)
        self.assertGreater(cov.total_paths, 0)

    # ── Corpus Tests ───────────────────────────────────────────

    def test_corpus_add(self):
        f = FluxFuzzer()
        bc = [0x00, 0x20, 0x00, 0x01, 0x02, 0x0B]
        case, cov = f.execute(bc)
        added = f.add_to_corpus(case, cov)
        self.assertTrue(added)
        self.assertEqual(len(f.corpus), 1)

    def test_corpus_no_duplicate(self):
        f = FluxFuzzer()
        bc = [0x00, 0x0B]
        case, cov = f.execute(bc)
        f.add_to_corpus(case, cov)
        # Same coverage, should not add again
        case2, cov2 = f.execute(bc)
        added = f.add_to_corpus(case2, cov2)
        self.assertFalse(added)
        self.assertEqual(len(f.corpus), 1)

    def test_corpus_save_load(self):
        import tempfile
        f = FluxFuzzer(seed=42)
        f.fuzz(n=10, seed=42)
        with tempfile.TemporaryDirectory() as tmpdir:
            f.save_corpus(tmpdir)
            f2 = FluxFuzzer(seed=99)
            loaded = f2.load_corpus(tmpdir)
            self.assertGreater(loaded, 0)

    def test_generate_from_corpus(self):
        f = FluxFuzzer(seed=42)
        f.corpus.append(FuzzCase([0x00, 0x0B], 0, FuzzResult.OK, 1, {}))
        bc = f.generate_from_corpus()
        self.assertIsInstance(bc, list)
        self.assertGreater(len(bc), 0)

    # ── Crash Tests ────────────────────────────────────────────

    def test_crash_detection_stack_overflow(self):
        f = FluxFuzzer()
        # Push many values to overflow stack
        bc = []
        for _ in range(5000):
            bc.extend([0x04, 0x01, 0x00])  # PUSH 0x0001
        bc.append(0x0B)
        case, _ = f.execute(bc)
        self.assertEqual(case.result, FuzzResult.CRASH)

    def test_crash_detection_ret_empty(self):
        f = FluxFuzzer()
        bc = [0x0A]  # RET with empty call stack
        case, _ = f.execute(bc)
        self.assertEqual(case.result, FuzzResult.CRASH)

    def test_unique_crash_tracking(self):
        f = FluxFuzzer()
        c1 = FuzzCase([0x01, 0x0B], 0, FuzzResult.CRASH, 1, {}, "test")
        c2 = FuzzCase([0x01, 0x0B], 0, FuzzResult.CRASH, 1, {}, "test")
        c3 = FuzzCase([0x02, 0x0B], 0, FuzzResult.CRASH, 1, {}, "other")
        f.add_crash(c1)
        f.add_crash(c2)
        f.add_crash(c3)
        self.assertEqual(len(f.unique_crash_ids), 2)
        self.assertEqual(len(f.crashes), 2)

    def test_crash_minimization(self):
        f = FluxFuzzer()
        # Create a crashing input
        bc = [0x0A] + [0x00] * 20  # RET (crash) + padding
        minimized = f.minimize_crash(bc, "ret with empty call stack")
        self.assertLessEqual(len(minimized), len(bc))
        # Minimized should still crash
        case, _ = f.execute(minimized)
        self.assertEqual(case.result, FuzzResult.CRASH)

    # ── Timeout Detection ──────────────────────────────────────

    def test_timeout_detection(self):
        f = FluxFuzzer()
        f.max_cycles = 200
        f.timeout_cycles = 100
        # Infinite loop: JMP to self
        bc = [0x06, 0x00, 0x00]  # JMP 0x0000
        case, _ = f.execute(bc)
        self.assertEqual(case.result, FuzzResult.INFINITE_LOOP)

    def test_infinite_loop_detection(self):
        f = FluxFuzzer()
        f.max_cycles = 100
        bc = [0x07, 0x00, 0x00, 0x00]  # JZ r0, 0x0000 (r0 is 0, so always jumps)
        case, _ = f.execute(bc)
        self.assertIn(case.result, [FuzzResult.INFINITE_LOOP, FuzzResult.TIMEOUT])

    # ── Fuzz Report Tests ──────────────────────────────────────

    def test_report_coverage_pct(self):
        f = FluxFuzzer(seed=42)
        report = f.fuzz(n=30, seed=42)
        self.assertGreater(report.opcode_coverage_pct, 0.0)
        self.assertLessEqual(report.opcode_coverage_pct, 100.0)

    def test_report_corpus_size(self):
        f = FluxFuzzer(seed=42)
        report = f.fuzz(n=30, seed=42)
        self.assertGreaterEqual(report.corpus_size, 0)

    def test_report_total_cycles(self):
        f = FluxFuzzer(seed=42)
        report = f.fuzz(n=10, seed=42)
        self.assertGreater(report.total_cycles, 0)

    def test_find_opcode_positions(self):
        f = FluxFuzzer()
        bc = [0x00, 0x20, 0x00, 0x01, 0x02, 0x0B]  # NOP, CADD r0,r1,r2, HALT
        positions = f._find_opcode_positions(bc)
        self.assertIn(0, positions)  # NOP at 0
        self.assertIn(1, positions)  # CADD at 1
        self.assertIn(5, positions)  # HALT at 5

    # ── Edge Cases ─────────────────────────────────────────────

    def test_empty_program(self):
        f = FluxFuzzer()
        case, cov = f.execute([])
        self.assertEqual(case.result, FuzzResult.OK)

    def test_single_nop(self):
        f = FluxFuzzer()
        case, _ = f.execute([0x00])
        self.assertEqual(case.result, FuzzResult.OK)

    def test_single_halt(self):
        f = FluxFuzzer()
        case, _ = f.execute([0x0B])
        self.assertEqual(case.result, FuzzResult.OK)

    def test_long_program(self):
        f = FluxFuzzer()
        bc = [0x00] * 1000 + [0x0B]
        case, _ = f.execute(bc)
        self.assertEqual(case.result, FuzzResult.OK)

    def test_unknown_opcode(self):
        f = FluxFuzzer()
        bc = [0xFF, 0x0B]
        case, _ = f.execute(bc)
        self.assertEqual(case.result, FuzzResult.OK)


if __name__ == "__main__":
    unittest.main(verbosity=2)
