#!/usr/bin/env python3
"""Static inspection of the ChatGPT Android APK release asset."""
from pathlib import Path
import hashlib, json, zipfile

ZIP = Path("work/ChatGPT_APK.zip")
OUT = Path("analysis")
EXPECTED_SIZE = 65134217
EXPECTED_SHA256 = "513131d742a8e724a1efbb030497390cdfe60234af468bfd2b3de08c6f10f6a5"
NEEDLES = (
    "mcp", "android-executor", "39801", "deviceexecutor",
    "localfunctionexecutor", "tool_call", "tool_result",
    "Mcp-Session-Id", "tools/list", "tools/call",
    "RmcpHttp2Server", "requiresLocalExecutor", "executorRegistrationId",
    "use_handle_rmcp", "x-codex-rmcp-grant", "RMCP provider disconnected",
    "noise_hybrid_ik_v1", "RMCP handshake grant rejected", "Missing Noise handshake",
    "HTTP/2 connection closed", "RMCP provider disconnected", "RmcpHttp2Server$Frame",
    "x-codex-rmcp-grant", "handshake grant", "noise", "rmcp server",
)

def write(name, data):
    (OUT / name).write_text(data, encoding="utf-8")

def main():
    OUT.mkdir(parents=True, exist_ok=True)
    raw = ZIP.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    if len(raw) != EXPECTED_SIZE or digest != EXPECTED_SHA256:
        raise SystemExit(f"Release asset mismatch: size={len(raw)} sha256={digest}")
    with zipfile.ZipFile(ZIP) as z:
        names = z.namelist()
        write("zip_contents.txt", "\n".join(names) + "\n")
        z.extractall("work/extracted")
    apk_paths = sorted(Path("work/extracted").rglob("*.apk"))
    if not apk_paths:
        raise SystemExit("No APK files found in release ZIP")
    from androguard.misc import AnalyzeAPK
    inventory = [f"ZIP size: {len(raw)}", f"ZIP SHA-256: {digest}", "APK files:"]
    manifests = []
    dex_lines = []
    method_lines = []
    disassembly = []
    full_target_methods = []
    server_reference_methods = []\n    handshake_callers = []
    selected_class_dump = []
    for apk_path in apk_paths:
        inventory.append(f"\n{apk_path} ({apk_path.stat().st_size} bytes)")
        try:
            a, dexes, analysis = AnalyzeAPK(str(apk_path))
            manifest = a.get_android_manifest_xml()
            if manifest is not None:
                from lxml import etree
                manifest_text = etree.tostring(manifest, encoding='unicode', pretty_print=True)
                manifest_name = apk_path.stem + ".manifest.xml"
                write(manifest_name, manifest_text)
                manifests.append(manifest_name)
            for dex_index, dex in enumerate(dexes):
                strings = list(dex.get_strings())
                hits = [(s, [n for n in NEEDLES if n.lower() in s.lower()]) for s in strings]
                hits = [(s, n) for s, n in hits if n]
                for value, tags in hits:
                    dex_lines.append(f"{apk_path.name}\tclasses{dex_index+1}.dex\t{','.join(tags)}\t{value}")
                for cls in dex.get_classes():
                    clsdesc = cls.get_name()
                    rmcp_class_names = ("Lfwr0;", "Lb940;", "RmcpHttp2Server", "ExecutorEnrollment", "LocalFunctionExecutorImpl", "Lwfz;", "Lbc30;", "DeviceExecutor", "Lxb30;", "Lc0z0;", "Ls18;", "Ls5f0;", "Lqwx;")
                    rmcp_tokens = ("x-codex-rmcp-grant", "noise_hybrid_ik_v1", "RMCP handshake grant rejected", "Missing Noise handshake", "connection_protocol", "executor_registration_id", "HTTP/2 connection closed", "RMCP provider disconnected", "RmcpHttp2Server$Frame", "RmcpHttp2Server", "onFrame(Lcom/openai/feature/deviceexecutor/impl/RmcpHttp2Server$Frame;)V")
                    class_has_rmcp_token = any(
                        any(token.lower() in ins.get_output().lower() for token in rmcp_tokens)
                        for cm in cls.get_methods() if cm.get_code() is not None
                        for ins in cm.get_code().get_bc().get_instructions()
                    )
                    if any(x.lower() in clsdesc.lower() for x in rmcp_class_names) or class_has_rmcp_token:
                        selected_class_dump.append(f"\n### CLASS {apk_path.name} classes{dex_index+1}.dex {clsdesc}")
                        for cm in cls.get_methods():
                            selected_class_dump.append(f"\n## METHOD {cm.get_class_name()}->{cm.get_name()}{cm.get_descriptor()}")
                            ccode = cm.get_code()
                            if ccode is not None:
                                selected_class_dump.extend(f"  {i.get_name()} {i.get_output()}" for i in ccode.get_bc().get_instructions())
                    for method in cls.get_methods():
                        code = method.get_code()
                        if code is None:
                            continue
                        insns = list(code.get_bc().get_instructions())
                        descriptor = f"{method.get_class_name()}->{method.get_name()}{method.get_descriptor()}"
                        server_refs = [ins.get_output() for ins in insns if "RmcpHttp2Server" in ins.get_output()]\n                        handshake_refs = [ins.get_output() for ins in insns if "Ls5f0;->t(" in ins.get_output()]
                        if handshake_refs:\n                            handshake_callers.append(f"\\n### {apk_path.name} classes{dex_index+1}.dex {descriptor}")\n                            handshake_callers.extend(f"  {ins.get_name()} {ins.get_output()}" for ins in insns)\n                        if server_refs or "RmcpHttp2Server" in descriptor:
                            server_reference_methods.append(f"\n### {apk_path.name} classes{dex_index+1}.dex {descriptor}")
                            server_reference_methods.extend(f"  {ins.get_name()} {ins.get_output()}" for ins in insns)
                        matching = []
                        for ins in insns:
                            output = ins.get_output()
                            if any(n.lower() in output.lower() for n in NEEDLES):
                                matching.append((ins.get_name(), output))
                        descriptor = f"{method.get_class_name()}->{method.get_name()}{method.get_descriptor()}"
                        name_hit = any(n.lower() in descriptor.lower() for n in NEEDLES)
                        if matching or name_hit:
                            method_lines.append(f"{apk_path.name}\tclasses{dex_index+1}.dex\t{descriptor}\tmatched_instructions={len(matching)}")
                            disassembly.append(f"\n### {apk_path.name} classes{dex_index+1}.dex {descriptor}")
                            for op, output in matching:
                                disassembly.append(f"  {op} {output}")
                        target_tokens = ("39801", "android-executor", "Mcp-Session-Id", "executorRegistrationId", "x-codex-rmcp-grant", "noise_hybrid_ik_v1")
                        if any(t.lower() in descriptor.lower() for t in target_tokens) or any(t.lower() in ins.get_output().lower() for t in target_tokens for ins in insns):
                            full_target_methods.append(f"\n### {apk_path.name} classes{dex_index+1}.dex {descriptor}")
                            full_target_methods.extend(f"  {ins.get_name()} {ins.get_output()}" for ins in insns)
        except Exception as exc:
            inventory.append(f"ANALYSIS ERROR for {apk_path.name}: {type(exc).__name__}: {exc}")
    write("apk_inventory.txt", "\n".join(inventory) + "\n")
    write("manifest_index.txt", "\n".join(manifests) + "\n")
    write("mcp_executor_strings.txt", "\n".join(sorted(set(dex_lines))) + "\n")
    write("mcp_executor_methods_index.txt", "\n".join(sorted(set(method_lines))) + "\n")
    write("mcp_executor_methods_disassembly.txt", "\n".join(disassembly) + "\n")
    write("target_method_full.txt", "\n".join(full_target_methods) + "\n")
    write("selected_classes_full.txt", "\n".join(selected_class_dump) + "\n")
    write("server_reference_methods.txt", "\n".join(server_reference_methods) + "\n")
    print(f"Inspected {len(apk_paths)} APK(s); string hits={len(dex_lines)}; methods={len(method_lines)}")

if __name__ == "__main__":
    main()
