"""Pytest test suite for flux-fuzzer."""
import pytest
from fuzzer import (
    FluxFuzzer, FuzzCase, FuzzResult, FuzzReport, TEMPLATES, _encode_imm8
)


# ── Fixtures ──

@pytest.fixture
def fuzzer():
    return FluxFuzzer(seed=42)

@pytest.fixture
def fresh_fuzzer():
    return FluxFuzzer(seed=0)


# ── FuzzResult enum ──

class TestFuzzResult:
    def test_all_results_defined(self):
        expected = {"ok", "crash", "timeout", "infinite_loop", "undefined_behavior"}
        actual = {r.value for r in FuzzResult}
        assert expected.issubset(actual)

    def test_result_values_are_strings(self):
        for r in FuzzResult:
            assert isinstance(r.value, str)


# ── FuzzCase ──

class TestFuzzCase:
    def test_unique_id_auto_generated(self):
        c = FuzzCase(bytecode=[0x18, 0, 42, 0x00], seed=0, result=FuzzResult.OK,
                     cycles=2, final_regs={0: 42})
        assert len(c.unique_id) == 8

    def test_unique_id_different_for_different_bytecode(self):
        c1 = FuzzCase(bytecode=[0x18, 0, 42, 0x00], seed=0, result=FuzzResult.OK,
                      cycles=2, final_regs={0: 42})
        c2 = FuzzCase(bytecode=[0x18, 0, 99, 0x00], seed=0, result=FuzzResult.OK,
                      cycles=2, final_regs={0: 99})
        assert c1.unique_id != c2.unique_id

    def test_unique_id_same_for_same_bytecode(self):
        c1 = FuzzCase(bytecode=[0x18, 0, 42, 0x00], seed=0, result=FuzzResult.OK,
                      cycles=2, final_regs={0: 42})
        c2 = FuzzCase(bytecode=[0x18, 0, 42, 0x00], seed=1, result=FuzzResult.OK,
                      cycles=2, final_regs={0: 42})
        assert c1.unique_id == c2.unique_id

    def test_crash_reason_default_empty(self):
        c = FuzzCase(bytecode=[0x00], seed=0, result=FuzzResult.OK,
                     cycles=1, final_regs={})
        assert c.crash_reason == ""


# ── FuzzReport ──

class TestFuzzReport:
    def test_to_markdown_structure(self):
        report = FuzzReport(
            total_cases=10, crashes=2, timeouts=1, undefined=0, ok=7,
            unique_crashes=[], coverage={"HALT": 10, "MOVI": 5}
        )
        md = report.to_markdown()
        assert "Total cases" in md
        assert "OK" in md
        assert "Crashes" in md
        assert "Opcode Coverage" in md

    def test_to_markdown_includes_crash_details(self):
        crash = FuzzCase(
            bytecode=[0x18, 0, 0, 0x23, 1, 0, 0, 0x00],
            seed=42, result=FuzzResult.CRASH, cycles=3,
            final_regs={}, crash_reason="division by zero"
        )
        report = FuzzReport(
            total_cases=1, crashes=1, timeouts=0, undefined=0, ok=0,
            unique_crashes=[crash], coverage={}
        )
        md = report.to_markdown()
        assert "division by zero" in md
        assert "42" in md


# ── Generate ──

class TestGenerate:
    def test_generate_returns_bytecode(self, fuzzer):
        bc = fuzzer.generate()
        assert isinstance(bc, list)
        assert len(bc) > 0

    def test_generate_ends_with_halt(self, fuzzer):
        bc = fuzzer.generate()
        assert bc[-1] == 0x00

    def test_generate_deterministic(self):
        f1 = FluxFuzzer(seed=42)
        f2 = FluxFuzzer(seed=42)
        assert f1.generate() == f2.generate()

    def test_generate_different_seeds(self):
        f1 = FluxFuzzer(seed=1)
        f2 = FluxFuzzer(seed=2)
        # Very unlikely to be equal
        assert f1.generate() != f2.generate()

    def test_generate_multiple_runs(self, fuzzer):
        bcs = [fuzzer.generate() for _ in range(5)]
        # All should be valid and end with HALT
        for bc in bcs:
            assert bc[-1] == 0x00

    def test_generate_respects_max_instructions(self):
        fuzzer_small = FluxFuzzer(seed=42)
        fuzzer_small.max_instructions = 3
        bc = fuzzer_small.generate()
        # With max_instructions=3 and no jumps, we get at most 3*4 + 1 = 13 bytes
        assert len(bc) <= 13


# ── Edge case generation ──

class TestEdgeCaseGeneration:
    def test_generate_edge_case_returns_bytecode(self, fuzzer):
        bc = fuzzer.generate_edge_case()
        assert isinstance(bc, list)
        assert len(bc) > 0

    def test_edge_case_division_by_zero(self):
        """One edge case should be div by zero."""
        f = FluxFuzzer(seed=0)
        seen_div_zero = False
        for _ in range(20):
            bc = f.generate_edge_case()
            case = f.execute(bc)
            if "division by zero" in case.crash_reason:
                seen_div_zero = True
                break
        assert seen_div_zero

    def test_edge_cases_all_execute_without_exception(self, fuzzer):
        """All edge cases should be executable."""
        for _ in range(10):
            bc = fuzzer.generate_edge_case()
            case = fuzzer.execute(bc)
            assert isinstance(case, FuzzCase)


# ── Execute ──

class TestExecute:
    def test_halt_only(self, fresh_fuzzer):
        case = fresh_fuzzer.execute([0x00])
        assert case.result == FuzzResult.OK
        assert case.cycles == 1

    def test_movi(self, fresh_fuzzer):
        case = fresh_fuzzer.execute([0x18, 0, 42, 0x00])
        assert case.result == FuzzResult.OK
        assert case.final_regs[0] == 42

    def test_add(self, fresh_fuzzer):
        bc = [0x18, 0, 10, 0x18, 1, 20, 0x20, 2, 0, 1, 0x00]
        case = fresh_fuzzer.execute(bc)
        assert case.result == FuzzResult.OK
        assert case.final_regs[2] == 30

    def test_sub(self, fresh_fuzzer):
        bc = [0x18, 0, 20, 0x18, 1, 8, 0x21, 2, 0, 1, 0x00]
        case = fresh_fuzzer.execute(bc)
        assert case.result == FuzzResult.OK
        assert case.final_regs[2] == 12

    def test_mul(self, fresh_fuzzer):
        bc = [0x18, 0, 6, 0x18, 1, 7, 0x22, 2, 0, 1, 0x00]
        case = fresh_fuzzer.execute(bc)
        assert case.result == FuzzResult.OK
        assert case.final_regs[2] == 42

    def test_div_by_zero(self, fresh_fuzzer):
        bc = [0x18, 0, 10, 0x18, 1, 0, 0x23, 2, 0, 1, 0x00]
        case = fresh_fuzzer.execute(bc)
        assert case.result in (FuzzResult.OK, FuzzResult.UNDEFINED)
        assert "division by zero" in case.crash_reason

    def test_mod_by_zero(self, fresh_fuzzer):
        bc = [0x18, 0, 10, 0x18, 1, 0, 0x24, 2, 0, 1, 0x00]
        case = fresh_fuzzer.execute(bc)
        assert "modulo by zero" in case.crash_reason

    def test_neg(self, fresh_fuzzer):
        case = fresh_fuzzer.execute([0x18, 0, 42, 0x0B, 0, 0x00])
        assert case.result == FuzzResult.OK
        assert case.final_regs[0] == -42

    def test_inc(self, fresh_fuzzer):
        case = fresh_fuzzer.execute([0x18, 0, 5, 0x08, 0, 0x00])
        assert case.result == FuzzResult.OK
        assert case.final_regs[0] == 6

    def test_dec(self, fresh_fuzzer):
        case = fresh_fuzzer.execute([0x18, 0, 5, 0x09, 0, 0x00])
        assert case.result == FuzzResult.OK
        assert case.final_regs[0] == 4

    def test_push_pop(self, fresh_fuzzer):
        bc = [0x18, 0, 10, 0x18, 1, 20, 0x0C, 0, 0x0C, 1, 0x0D, 0, 0x0D, 1, 0x00]
        case = fresh_fuzzer.execute(bc)
        assert case.result == FuzzResult.OK
        assert case.final_regs[0] == 20
        assert case.final_regs[1] == 10

    def test_cmp_eq_true(self, fresh_fuzzer):
        bc = [0x18, 0, 42, 0x18, 1, 42, 0x2C, 2, 0, 1, 0x00]
        case = fresh_fuzzer.execute(bc)
        assert case.final_regs[2] == 1

    def test_cmp_eq_false(self, fresh_fuzzer):
        bc = [0x18, 0, 42, 0x18, 1, 99, 0x2C, 2, 0, 1, 0x00]
        case = fresh_fuzzer.execute(bc)
        assert case.final_regs[2] == 0

    def test_cmp_lt(self, fresh_fuzzer):
        bc = [0x18, 0, 5, 0x18, 1, 10, 0x2D, 2, 0, 1, 0x00]
        case = fresh_fuzzer.execute(bc)
        assert case.final_regs[2] == 1

    def test_cmp_gt(self, fresh_fuzzer):
        bc = [0x18, 0, 10, 0x18, 1, 5, 0x2E, 2, 0, 1, 0x00]
        case = fresh_fuzzer.execute(bc)
        assert case.final_regs[2] == 1

    def test_mov(self, fresh_fuzzer):
        case = fresh_fuzzer.execute([0x18, 0, 42, 0x3A, 1, 0, 0, 0x00])
        assert case.final_regs[1] == 42

    def test_empty_bytecode(self, fresh_fuzzer):
        case = fresh_fuzzer.execute([])
        assert case.result == FuzzResult.OK

    def test_cycles_count(self, fresh_fuzzer):
        case = fresh_fuzzer.execute([0x01, 0x01, 0x00])  # NOP, NOP, HALT
        assert case.cycles == 3


# ── Fuzz run ──

class TestFuzzRun:
    def test_fuzz_returns_report(self, fuzzer):
        report = fuzzer.fuzz(n=20, seed=42)
        assert isinstance(report, FuzzReport)
        assert report.total_cases == 20

    def test_fuzz_has_ok_cases(self, fuzzer):
        report = fuzzer.fuzz(n=50, seed=42)
        assert report.ok > 0

    def test_fuzz_report_total(self, fuzzer):
        report = fuzzer.fuzz(n=30, seed=42)
        assert report.ok + report.crashes + report.timeouts == report.total_cases

    def test_fuzz_coverage(self, fuzzer):
        report = fuzzer.fuzz(n=50, seed=42)
        assert len(report.coverage) > 0

    def test_fuzz_deterministic(self):
        r1 = FluxFuzzer(seed=99).fuzz(n=10, seed=99)
        r2 = FluxFuzzer(seed=99).fuzz(n=10, seed=99)
        assert r1.total_cases == r2.total_cases
        assert r1.ok == r2.ok


# ── Templates ──

class TestTemplates:
    def test_templates_not_empty(self):
        assert len(TEMPLATES) > 0

    def test_all_templates_have_3_elements(self):
        for t in TEMPLATES:
            assert len(t) == 3

    def test_halt_in_templates(self):
        halt_templates = [t for t in TEMPLATES if t[0] == 0x00]
        assert len(halt_templates) == 1

    def test_template_sizes_valid(self):
        """Template sizes should be reasonable (1-4 bytes)."""
        for opcode, size, ranges in TEMPLATES:
            assert 1 <= size <= 4


# ── Encode helper ──

class TestEncodeImm8:
    @pytest.mark.parametrize("value", [0, 1, 127, -1, -128])
    def test_encode_imm8(self, value):
        result = _encode_imm8(value)
        assert isinstance(result, int)
        assert 0 <= result <= 255

    @pytest.mark.parametrize("value,expected", [
        (0, 0), (127, 127), (-1, 255), (-128, 128)
    ])
    def test_encode_known_values(self, value, expected):
        assert _encode_imm8(value) == expected
