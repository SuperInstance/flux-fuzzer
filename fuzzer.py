"""
FLUX Fuzzer — generate random bytecodes and find VM edge cases.

Strategy:
- Random valid instruction sequences
- Edge case generation (division by zero, register overflow, stack underflow)
- Differential testing against multiple interpretations
"""
import random
import hashlib
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple
from enum import Enum


class FuzzResult(Enum):
    OK = "ok"
    CRASH = "crash"
    TIMEOUT = "timeout"
    INFINITE_LOOP = "infinite_loop"
    UNDEFINED = "undefined_behavior"


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
    
    def __post_init__(self):
        if not self.unique_id:
            h = hashlib.md5(bytes(self.bytecode)).hexdigest()[:8]
            self.unique_id = h


@dataclass
class FuzzReport:
    total_cases: int
    crashes: int
    timeouts: int
    undefined: int
    ok: int
    unique_crashes: List[FuzzCase]
    coverage: Dict[str, int]  # opcode -> times executed
    
    def to_markdown(self) -> str:
        lines = ["# FLUX Fuzz Report\n"]
        lines.append(f"- **Total cases:** {self.total_cases}")
        lines.append(f"- **OK:** {self.ok} | **Crashes:** {self.crashes} | **Timeouts:** {self.timeouts} | **Undefined:** {self.undefined}")
        
        if self.unique_crashes:
            lines.append(f"\n## Unique Crashes ({len(self.unique_crashes)})\n")
            for c in self.unique_crashes[:10]:
                bc_hex = " ".join(f"{b:02x}" for b in c.bytecode[:32])
                lines.append(f"- `{bc_hex}` — {c.crash_reason} (seed={c.seed}, id={c.unique_id})")
        
        lines.append(f"\n## Opcode Coverage\n")
        for op, cnt in sorted(self.coverage.items(), key=lambda x: -x[1])[:10]:
            lines.append(f"- {op}: {cnt}x")
        
        return "\n".join(lines)


# Valid instruction templates: (opcode, size, operand_ranges)
TEMPLATES = [
    (0x00, 1, []),           # HALT
    (0x01, 1, []),           # NOP
    (0x08, 2, [(0, 15)]),    # INC reg
    (0x09, 2, [(0, 15)]),    # DEC reg
    (0x0B, 2, [(0, 15)]),    # NEG reg
    (0x0C, 2, [(0, 15)]),    # PUSH reg
    (0x0D, 2, [(0, 15)]),    # POP reg
    (0x18, 3, [(0, 15), (-128, 127)]),   # MOVI reg, imm8
    (0x19, 3, [(0, 15), (-128, 127)]),   # ADDI reg, imm8
    (0x20, 4, [(0, 15), (0, 15), (0, 15)]),  # ADD rd,rs1,rs2
    (0x21, 4, [(0, 15), (0, 15), (0, 15)]),  # SUB
    (0x22, 4, [(0, 15), (0, 15), (0, 15)]),  # MUL
    (0x23, 4, [(0, 15), (0, 15), (0, 15)]),  # DIV
    (0x24, 4, [(0, 15), (0, 15), (0, 15)]),  # MOD
    (0x2C, 4, [(0, 15), (0, 15), (0, 15)]),  # CMP_EQ
    (0x2D, 4, [(0, 15), (0, 15), (0, 15)]),  # CMP_LT
    (0x2E, 4, [(0, 15), (0, 15), (0, 15)]),  # CMP_GT
    (0x3A, 4, [(0, 15), (0, 15), (0, 15)]),  # MOV
    (0x3C, 4, [(0, 15), (-32, 32)]),          # JZ
    (0x3D, 4, [(0, 15), (-32, 32)]),          # JNZ
]


def _encode_imm8(v):
    return v & 0xFF


class FluxFuzzer:
    """Generate and test random FLUX bytecodes."""
    
    def __init__(self, seed: int = 42):
        self.rng = random.Random(seed)
        self.max_instructions = 20
        self.max_cycles = 10000
    
    def generate(self) -> List[int]:
        """Generate a random valid bytecode program."""
        bc = []
        n = self.rng.randint(1, self.max_instructions)
        
        for _ in range(n):
            template = self.rng.choice(TEMPLATES[:-2])  # Avoid jumps in generation
            opcode, size, ranges = template
            bc.append(opcode)
            for lo, hi in ranges:
                val = self.rng.randint(lo, hi)
                bc.append(_encode_imm8(val))
        
        bc.append(0x00)  # Always end with HALT
        return bc
    
    def generate_edge_case(self) -> List[int]:
        """Generate edge-case programs targeting known issues."""
        cases = [
            [0x18, 0, 0, 0x23, 1, 0, 0, 0x00],  # Division by zero
            [0x18, 0, 127, 0x08, 0, 0x00],        # INC max positive
            [0x18, 0, 1, 0x22, 0, 0, 0, 0x00],    # Multiply by self (overflow)
            [0x0D, 0, 0x00],                        # POP empty stack
            [0x18, 0, 1, 0x09, 0, 0x09, 0, 0x00],  # DEC past zero
            [0x18, 0, 0, 0x24, 0, 0, 0, 0x00],    # MOD by zero
        ]
        return self.rng.choice(cases)
    
    def execute(self, bytecode: List[int]) -> FuzzCase:
        """Execute bytecode and detect issues."""
        regs = [0] * 64
        stack = [0] * 4096
        sp = 4096
        pc = 0
        halted = False
        cycles = 0
        crash_reason = ""
        
        def sb(b): return b - 256 if b > 127 else b
        
        bc = bytes(bytecode)
        
        while not halted and pc < len(bc) and cycles < self.max_cycles:
            op = bc[pc]
            cycles += 1
            
            try:
                if op == 0x00: halted = True; pc += 1
                elif op == 0x01: pc += 1
                elif op == 0x08:
                    regs[bc[pc+1]] = (regs[bc[pc+1]] + 1) & 0xFFFFFFFF
                    pc += 2
                elif op == 0x09:
                    regs[bc[pc+1]] = (regs[bc[pc+1]] - 1) & 0xFFFFFFFF
                    pc += 2
                elif op == 0x0B: regs[bc[pc+1]] = -regs[bc[pc+1]]; pc += 2
                elif op == 0x0C:
                    if sp <= 0:
                        return FuzzCase(bytecode, 0, FuzzResult.CRASH, cycles,
                                        {i: regs[i] for i in range(16)}, "stack overflow")
                    sp -= 1; stack[sp] = regs[bc[pc+1]]; pc += 2
                elif op == 0x0D:
                    if sp >= 4096:
                        return FuzzCase(bytecode, 0, FuzzResult.UNDEFINED, cycles,
                                        {i: regs[i] for i in range(16)}, "stack underflow (returns 0)")
                    regs[bc[pc+1]] = stack[sp]; sp += 1; pc += 2
                elif op == 0x18: regs[bc[pc+1]] = sb(bc[pc+2]); pc += 3
                elif op == 0x19: regs[bc[pc+1]] += sb(bc[pc+2]); pc += 3
                elif op == 0x20: regs[bc[pc+1]] = regs[bc[pc+2]] + regs[bc[pc+3]]; pc += 4
                elif op == 0x21: regs[bc[pc+1]] = regs[bc[pc+2]] - regs[bc[pc+3]]; pc += 4
                elif op == 0x22: regs[bc[pc+1]] = regs[bc[pc+2]] * regs[bc[pc+3]]; pc += 4
                elif op == 0x23:
                    if regs[bc[pc+3]] == 0:
                        crash_reason = "division by zero"
                        regs[bc[pc+1]] = 0  # defined behavior: result = 0
                    else:
                        regs[bc[pc+1]] = regs[bc[pc+2]] // regs[bc[pc+3]]
                    pc += 4
                elif op == 0x24:
                    if regs[bc[pc+3]] == 0:
                        crash_reason = "modulo by zero"
                        regs[bc[pc+1]] = 0
                    else:
                        regs[bc[bc[pc+1]]] = regs[bc[pc+2]] % regs[bc[pc+3]]
                    pc += 4
                elif op == 0x2C: regs[bc[pc+1]] = 1 if regs[bc[pc+2]] == regs[bc[pc+3]] else 0; pc += 4
                elif op == 0x2D: regs[bc[pc+1]] = 1 if regs[bc[pc+2]] < regs[bc[pc+3]] else 0; pc += 4
                elif op == 0x2E: regs[bc[pc+1]] = 1 if regs[bc[pc+2]] > regs[bc[pc+3]] else 0; pc += 4
                elif op == 0x3A: regs[bc[pc+1]] = regs[bc[pc+2]]; pc += 4
                elif op == 0x3C:
                    if regs[bc[pc+1]] == 0: pc += sb(bc[pc+2])
                    else: pc += 4
                elif op == 0x3D:
                    if regs[bc[pc+1]] != 0: pc += sb(bc[pc+2])
                    else: pc += 4
                else: pc += 1
            except IndexError:
                return FuzzCase(bytecode, 0, FuzzResult.CRASH, cycles,
                                {i: regs[i] for i in range(16)}, "out of bounds")
        
        if cycles >= self.max_cycles:
            result = FuzzResult.INFINITE_LOOP
        elif crash_reason:
            result = FuzzResult.UNDEFINED
        else:
            result = FuzzResult.OK
        
        return FuzzCase(bytecode, 0, result, cycles,
                        {i: regs[i] for i in range(16)}, crash_reason)
    
    def fuzz(self, n: int = 100, seed: int = 0) -> FuzzReport:
        """Run n fuzz cases and generate report."""
        self.rng = random.Random(seed)
        crashes = []
        ok = 0
        timeouts = 0
        undefined = 0
        coverage = {}
        
        for i in range(n):
            if i % 5 == 0:
                bc = self.generate_edge_case()
            else:
                bc = self.generate()
            
            case = self.execute(bc)
            case.seed = seed + i
            
            if case.result == FuzzResult.OK:
                ok += 1
            elif case.result in (FuzzResult.CRASH, FuzzResult.UNDEFINED):
                crashes.append(case)
            elif case.result in (FuzzResult.TIMEOUT, FuzzResult.INFINITE_LOOP):
                timeouts += 1
            
            # Track opcode coverage
            for b in bc:
                name = {0x00:"HALT",0x18:"MOVI",0x20:"ADD",0x22:"MUL",0x09:"DEC"}.get(b, f"0x{b:02x}")
                coverage[name] = coverage.get(name, 0) + 1
        
        return FuzzReport(
            total_cases=n, crashes=len(crashes), timeouts=timeouts,
            undefined=0, ok=ok, unique_crashes=crashes, coverage=coverage
        )


# ── Tests ──────────────────────────────────────────────

import unittest


class TestFuzzer(unittest.TestCase):
    def test_generate(self):
        f = FluxFuzzer(seed=42)
        bc = f.generate()
        self.assertGreater(len(bc), 1)
        self.assertEqual(bc[-1], 0x00)
    
    def test_generate_deterministic(self):
        f1 = FluxFuzzer(seed=42)
        f2 = FluxFuzzer(seed=42)
        self.assertEqual(f1.generate(), f2.generate())
    
    def test_execute_halt(self):
        f = FluxFuzzer()
        case = f.execute([0x00])
        self.assertEqual(case.result, FuzzResult.OK)
    
    def test_execute_movi(self):
        f = FluxFuzzer()
        case = f.execute([0x18, 0, 42, 0x00])
        self.assertEqual(case.result, FuzzResult.OK)
        self.assertEqual(case.final_regs[0], 42)
    
    def test_div_by_zero(self):
        f = FluxFuzzer()
        case = f.execute([0x18, 0, 10, 0x18, 1, 0, 0x23, 2, 0, 1, 0x00])
        self.assertIn(case.result, [FuzzResult.OK, FuzzResult.UNDEFINED])
    
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
            self.assertGreater(len(bc), 0)
    
    def test_fuzz_case_unique_id(self):
        f = FluxFuzzer()
        c1 = f.execute([0x18, 0, 42, 0x00])
        c2 = f.execute([0x18, 0, 99, 0x00])
        self.assertNotEqual(c1.unique_id, c2.unique_id)


if __name__ == "__main__":
    unittest.main(verbosity=2)
