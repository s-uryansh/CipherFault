"""Binary scanner orchestration."""

from pathlib import Path
import struct

from .rules import (
    Finding,
    ecb_mode_finding,
    hardcoded_key_finding,
    known_weak_algorithm_finding,
    numeric_parameter_finding,
    operand_origin_finding,
    parameter_set_finding,
    static_iv_finding,
    weak_randomness_finding,
)
from .ghidra import analyzed_program
from .indicators import (
    repeated_operand_indicators,
    rng_quality_indicator,
    verification_outcome_indicators,
)
from .report import AnalysisReport, Diagnostic, PrimitiveEvidence, target_sha256
from .taint.anchors import (
    FINGERPRINT_NAMES,
    build_fingerprint_catalog,
    callee_name,
    find_anchors,
    resolved_fingerprint_names,
)
from .taint.tracer import (
    constant_buffer_reaching_pointer,
    copied_source_reaching_pointer,
    rng_source_reaching_pointer,
    trace_operand,
    weak_source_reaching_pointer,
)


def scan_binary(binary_path: str | Path, fingerprint_reference: str | Path | None = None) -> AnalysisReport:
    binary_path = Path(binary_path)
    if not binary_path.exists():
        raise FileNotFoundError(binary_path)
    target_arch = _validate_target(binary_path)

    findings: list[Finding] = []
    primitives: dict[tuple[str, str], PrimitiveEvidence] = {}
    diagnostics: list[Diagnostic] = []
    indicators = []
    fingerprint_catalog = {}

    if fingerprint_reference is not None:
        fingerprint_reference = Path(fingerprint_reference)
        _validate_target(fingerprint_reference)
        with analyzed_program(fingerprint_reference) as (reference, _):
            fingerprint_catalog = build_fingerprint_catalog(
                reference,
                FINGERPRINT_NAMES,
            )
        if not fingerprint_catalog:
            raise ValueError("fingerprint reference contains no supported anchor symbols")

    with analyzed_program(binary_path) as (program, monitor):
        from ghidra.app.decompiler import DecompInterface

        decomp = DecompInterface()
        decomp.openProgram(program)

        anchors = find_anchors(program, decomp, monitor, fingerprint_catalog=fingerprint_catalog)
        indicators.extend(verification_outcome_indicators(
            program,
            decomp,
            monitor,
            resolved_fingerprint_names(program, fingerprint_catalog),
        ))
        for anchor in anchors:
            if anchor.primitive in {"ML-KEM", "ML-DSA", "SLH-DSA"}:
                primitives[(anchor.primitive, anchor.call_addr)] = PrimitiveEvidence(
                    primitive=anchor.primitive,
                    address=anchor.call_addr,
                    method=anchor.resolution_method,
                    confidence=1.0,
                    variant=anchor.variant,
                )
                if anchor.variant:
                    findings.append(parameter_set_finding(
                        anchor, anchor.variant, primitive=anchor.primitive
                    ))
                randomness = anchor.operands.get("randomness")
                if randomness is not None:
                    rng_path = rng_source_reaching_pointer(
                        randomness,
                        anchor.high,
                        program,
                        anchor.resolved_names,
                        decomp,
                        monitor,
                        before_address=anchor.call_addr,
                    )
                    if rng_path is not None:
                        findings.append(operand_origin_finding(
                            anchor, rng_path, primitive=anchor.primitive, operand="randomness"
                        ))
                        indicators.append(rng_quality_indicator(anchor, rng_path, "randomness"))
                    weak_path = weak_source_reaching_pointer(
                        randomness,
                        anchor.high,
                        program,
                        anchor.resolved_names,
                        decomp,
                        monitor,
                        before_address=anchor.call_addr,
                    )
                    if weak_path is not None:
                        findings.append(weak_randomness_finding(
                            anchor,
                            weak_path,
                            primitive=anchor.primitive,
                            operand="randomness",
                        ))
                continue

            if anchor.primitive == "DIGEST":
                selector = anchor.operands.get("algorithm")
                selector_name = (
                    cipher_selector_name(program, selector, anchor.resolved_names)
                    if selector is not None
                    else None
                )
                primitive = digest_primitive_from_selector(selector_name)
                if primitive is None:
                    diagnostics.append(Diagnostic(
                        code="UNRESOLVED_DIGEST_PRIMITIVE",
                        message=f"digest selector is unknown: {selector_name or 'unknown'}",
                        address=anchor.call_addr,
                    ))
                    continue
                primitives[(primitive, anchor.call_addr)] = PrimitiveEvidence(
                    primitive=primitive,
                    address=anchor.call_addr,
                    method=anchor.resolution_method,
                    confidence=1.0,
                )
                finding = known_weak_algorithm_finding(anchor, primitive, selector_name)
                if finding is not None:
                    findings.append(finding)
                continue

            if anchor.primitive == "RSA":
                primitives[("RSA", anchor.call_addr)] = PrimitiveEvidence(
                    primitive="RSA",
                    address=anchor.call_addr,
                    method=anchor.resolution_method,
                    confidence=1.0,
                )
                bits = anchor.operands.get("bits")
                if bits is not None:
                    path = trace_operand(bits, anchor.high, program, decomp, monitor)
                    finding = numeric_parameter_finding(
                        anchor, path, primitive="RSA", fact_type="key_size", operand="bits"
                    )
                    if finding is not None:
                        findings.append(finding)
                continue

            if anchor.primitive == "ECC":
                primitives[("ECC", anchor.call_addr)] = PrimitiveEvidence(
                    primitive="ECC",
                    address=anchor.call_addr,
                    method=anchor.resolution_method,
                    confidence=1.0,
                )
                curve = anchor.operands.get("curve")
                if curve is not None:
                    path = trace_operand(curve, anchor.high, program, decomp, monitor)
                    variant = curve_name_from_path(path)
                    if variant is not None:
                        findings.append(parameter_set_finding(
                            anchor,
                            variant,
                            primitive="ECC",
                            path=path,
                            operand="curve",
                        ))
                continue

            if anchor.primitive == "AES":
                primitive = "AES"
                cipher_name = anchor.callee
            else:
                cipher = anchor.operands.get("cipher")
                cipher_name = (
                    cipher_selector_name(program, cipher, anchor.resolved_names)
                    if cipher is not None
                    else None
                )
                primitive = primitive_from_cipher_selector(cipher_name)
                if primitive is None:
                    diagnostics.append(Diagnostic(
                        code="UNRESOLVED_CIPHER_PRIMITIVE",
                        message=f"cipher selector does not prove AES: {cipher_name or 'unknown'}",
                        address=anchor.call_addr,
                    ))
                    continue

            primitives[(primitive, anchor.call_addr)] = PrimitiveEvidence(
                primitive=primitive,
                address=anchor.call_addr,
                method=anchor.resolution_method,
                confidence=1.0,
                variant=anchor.variant,
            )
            finding = ecb_mode_finding(anchor, cipher_name, primitive=primitive)
            if finding is not None:
                findings.append(finding)

            iv = anchor.operands.get("iv")
            if iv is not None:
                rng_path = rng_source_reaching_pointer(
                    iv,
                    anchor.high,
                    program,
                    anchor.resolved_names,
                    decomp,
                    monitor,
                    before_address=anchor.call_addr,
                )
                if rng_path is not None:
                    findings.append(operand_origin_finding(anchor, rng_path, primitive, "iv"))
                    indicators.append(rng_quality_indicator(anchor, rng_path, "iv"))
                path = constant_buffer_reaching_pointer(
                    iv,
                    anchor.high,
                    program,
                    anchor.resolved_names,
                    anchor.call_addr,
                ) or copied_source_reaching_pointer(
                    iv,
                    anchor.high,
                    program,
                    decomp,
                    monitor,
                    anchor.resolved_names,
                    anchor.call_addr,
                ) or trace_operand(iv, anchor.high, program, decomp, monitor)
                section = memory_block_name(program, path.origin)
                finding = static_iv_finding(anchor, path, primitive=primitive, section=section)
                if finding is not None:
                    findings.append(finding)

            key = anchor.operands.get("key")
            if key is None:
                continue

            weak_path = weak_source_reaching_pointer(
                key,
                anchor.high,
                program,
                anchor.resolved_names,
                decomp,
                monitor,
                before_address=anchor.call_addr,
            )
            if weak_path is not None:
                finding = weak_randomness_finding(anchor, weak_path, primitive=primitive)
                if finding is not None:
                    findings.append(finding)

            rng_path = rng_source_reaching_pointer(
                key,
                anchor.high,
                program,
                anchor.resolved_names,
                decomp,
                monitor,
                before_address=anchor.call_addr,
            )
            if rng_path is not None:
                findings.append(operand_origin_finding(anchor, rng_path, primitive, "key"))
                indicators.append(rng_quality_indicator(anchor, rng_path, "key"))

            path = constant_buffer_reaching_pointer(
                key,
                anchor.high,
                program,
                anchor.resolved_names,
                anchor.call_addr,
            ) or copied_source_reaching_pointer(
                key,
                anchor.high,
                program,
                decomp,
                monitor,
                anchor.resolved_names,
                anchor.call_addr,
            ) or trace_operand(key, anchor.high, program, decomp, monitor)
            section = memory_block_name(program, path.origin)
            finding = hardcoded_key_finding(anchor, path, primitive=primitive, section=section)
            if finding is not None:
                findings.append(finding)

            elif path.terminal not in {"CONST", "ADDR"}:
                diagnostics.append(Diagnostic(
                    code="UNRESOLVED_KEY_PROVENANCE",
                    message=f"key origin ended at {path.terminal or 'unknown'}",
                    address=anchor.call_addr,
                ))

    recognition_candidates = []
    try:
        from .recognizer.runtime import recognize_binary

        recognized, recognition_candidates = recognize_binary(binary_path)
        for evidence in recognized:
            primitives[(evidence.primitive, evidence.address)] = evidence
    except (ImportError, ModuleNotFoundError):
        diagnostics.append(Diagnostic(
            code="RECOGNIZER_DEPENDENCIES_UNAVAILABLE",
            message="install the recognizer extra to enable learned region recognition",
        ))
    except Exception as exc:
        diagnostics.append(Diagnostic(
            code="RECOGNIZER_FAILED",
            message=f"learned recognition failed closed: {exc}",
        ))

    unique = {finding.id: finding for finding in findings}
    return AnalysisReport(
        target=str(binary_path),
        target_sha256=target_sha256(binary_path),
        target_arch=target_arch,
        primitives=list(primitives.values()),
        recognition_candidates=recognition_candidates,
        verified_facts=list(unique.values()),
        indicators=[*indicators, *repeated_operand_indicators(anchors)],
        diagnostics=diagnostics,
    )


def findings_as_dicts(findings: list[Finding]) -> list[dict]:
    return [finding.to_dict() for finding in findings]


def primitive_from_cipher_selector(cipher_name: str | None) -> str | None:
    return "AES" if cipher_name and cipher_name.lower().startswith("evp_aes_") else None


def digest_primitive_from_selector(selector_name: str | None) -> str | None:
    return {
        "evp_md5": "MD5",
        "evp_sha1": "SHA-1",
        "evp_sha224": "SHA-224",
        "evp_sha256": "SHA-256",
        "evp_sha384": "SHA-384",
        "evp_sha512": "SHA-512",
    }.get((selector_name or "").lower())


def curve_name_from_path(path) -> str | None:
    if getattr(path, "terminal", None) != "CONST":
        return None
    return {
        415: "P-256",
        715: "P-384",
        716: "P-521",
        714: "secp256k1",
    }.get(int(str(path.origin), 0))


def _validate_target(path: Path) -> str:
    with path.open("rb") as stream:
        header = stream.read(20)
    if len(header) < 20 or header[:5] != b"\x7fELF\x02" or header[5] != 1:
        raise ValueError("unsupported input: expected a 64-bit little-endian ELF binary")
    machine = struct.unpack_from("<H", header, 18)[0]
    if machine not in {62, 183}:
        raise ValueError("unsupported input: expected an x86_64 or AArch64 ELF binary")
    return {62: "x86_64", 183: "AArch64"}[machine]

def cipher_selector_name(program, vn, resolved_names=None) -> str | None:
    direct = callee_name(program, vn, resolved_names)
    if direct is not None:
        return direct
    d = vn.getDef()
    if d is None or d.getMnemonic() != "CALL" or d.getNumInputs() == 0:
        return None
    return callee_name(program, d.getInput(0), resolved_names)

def memory_block_name(program, origin: str | None) -> str | None:
    if origin is None or str(origin).startswith("-"):
        return None

    text = str(origin)
    if text.startswith("0x"):
        text = text[2:]

    try:
        addr = program.getAddressFactory().getDefaultAddressSpace().getAddress(text)
    except Exception:
        return None

    block = program.getMemory().getBlock(addr)
    return str(block.getName()) if block else None
