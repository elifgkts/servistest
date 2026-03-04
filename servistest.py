import json
import re
import hashlib
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

import pandas as pd
import streamlit as st


# -----------------------------
# Models
# -----------------------------
@dataclass
class PMRequest:
    collection_name: str
    folder_path: str           # e.g. "SendMessage/Tek Takipçiye Mesaj"
    request_name: str
    method: str
    url_raw: str
    headers: List[Dict[str, Any]]
    body_raw: str
    auth_type: Optional[str]   # e.g. "basic", "bearer", None


# -----------------------------
# Helpers
# -----------------------------
def sanitize_text(s: str) -> str:
    """Mask secrets & PII-like data."""
    if not s:
        return ""

    # Mask Authorization headers
    s = re.sub(
        r"(Authorization:\s*)(Basic|Bearer)\s+[A-Za-z0-9\-\._~\+/=]+", r"\1\2 <REDACTED>", s, flags=re.I)

    # Mask inline "Basic xxx" anywhere
    s = re.sub(r"\bBasic\s+[A-Za-z0-9+/=]+\b",
               "Basic <REDACTED>", s, flags=re.I)
    s = re.sub(r"\bBearer\s+[A-Za-z0-9\-\._~\+/=]+\b",
               "Bearer <REDACTED>", s, flags=re.I)

    # Mask phone-like sequences 10-13 digits
    s = re.sub(r"\b\d{10,13}\b", "<MSISDN>", s)

    # Mask common Postman vars
    s = s.replace("{{$randomUUID}}", "<UUID>")

    # Mask passwords if obvious
    s = re.sub(r'("password"\s*:\s*)".*?"', r'\1"<PASSWORD>"', s, flags=re.I)
    s = re.sub(r"(password:\s*).+", r"\1<PASSWORD>", s, flags=re.I)

    return s


def get_url_raw(req: Dict[str, Any]) -> str:
    url = req.get("url")
    if isinstance(url, str):
        return url
    if isinstance(url, dict):
        return url.get("raw", "") or ""
    return ""


def pretty_json(raw: str) -> str:
    if not raw:
        return ""
    try:
        obj = json.loads(raw)
        return json.dumps(obj, ensure_ascii=False, indent=2)
    except Exception:
        # try normalizing newlines
        try:
            obj = json.loads(raw.replace("\r\n", "\n"))
            return json.dumps(obj, ensure_ascii=False, indent=2)
        except Exception:
            return raw.replace("\r\n", "\n")


def endpoint_path(url_raw: str) -> str:
    """Return path part like '/tes/rest/spi/sendmsgserv'."""
    if not url_raw:
        return ""
    try:
        u = urlparse(url_raw)
        return u.path or ""
    except Exception:
        # fallback: remove protocol/host roughly
        url_raw = re.sub(r"^https?://", "", url_raw)
        parts = url_raw.split("/", 1)
        return "/" + parts[1] if len(parts) > 1 else ""


def request_data_block(pm: PMRequest, mask_secrets: bool = True) -> str:
    hdr_lines = []
    for h in (pm.headers or []):
        k = str(h.get("key", "")).strip()
        v = str(h.get("value", "")).strip()
        if k.lower() == "authorization":
            v = "<REDACTED>"
        if k:
            hdr_lines.append(f"{k}: {v}")

    txt = f"Method: {pm.method}\nURL: {pm.url_raw}\n"
    txt += "Headers:\n" + \
        ("\n".join([f"- {x}" for x in hdr_lines])
         if hdr_lines else "- (none)") + "\n"

    if pm.body_raw:
        txt += "Body:\n" + pretty_json(pm.body_raw)

    return sanitize_text(txt) if mask_secrets else txt


def parse_postman_collection(content: Dict[str, Any], fallback_name: str) -> List[PMRequest]:
    collection_name = (content.get("info", {}) or {}
                       ).get("name") or fallback_name
    items = content.get("item", []) or []

    out: List[PMRequest] = []

    def walk(nodes: List[Dict[str, Any]], parents: List[str]):
        for node in nodes:
            name = node.get("name", "") or ""
            # folder
            if "item" in node and isinstance(node.get("item"), list):
                walk(node["item"], parents + ([name] if name else []))
                continue

            # request leaf
            req = node.get("request")
            if isinstance(req, dict):
                method = (req.get("method") or "").upper()
                url_raw = get_url_raw(req)
                headers = req.get("header", []) or []
                body_raw = ""
                body = req.get("body")
                if isinstance(body, dict) and body.get("mode") == "raw":
                    body_raw = body.get("raw", "") or ""

                auth = req.get("auth", {}) or {}
                auth_type = auth.get("type")

                folder_path = "/".join([p for p in parents if p]
                                       ) if parents else "Root"

                out.append(
                    PMRequest(
                        collection_name=collection_name,
                        folder_path=folder_path,
                        request_name=name or "(unnamed request)",
                        method=method or "GET",
                        url_raw=url_raw,
                        headers=headers,
                        body_raw=body_raw,
                        auth_type=auth_type,
                    )
                )

    walk(items, [])
    return out


# -----------------------------
# Test generation
# -----------------------------
def make_steps_base(req_data: str, positive: bool) -> List[Dict[str, str]]:
    steps = [
        {
            "Step": "Prepare request parameters and build the request for the relevant endpoint.",
            "Data": req_data,
            "Expected Result": "The request is prepared for the correct endpoint and in the correct format.",
        },
        {"Step": "Send the request.", "Data": "",
            "Expected Result": "The request is delivered to the server."},
    ]

    if positive:
        last = (
            "HTTP 200 (or the success status defined in the API spec) should be returned; "
            "the response should include a success indicator (e.g., resultCode=0 / success=true)."
        )
    else:
        last = (
            "The API should reject invalid/missing fields appropriately: return HTTP 4xx/5xx or an error result "
            "in the response (e.g., resultCode!=0) with a descriptive message."
        )

    steps.append({"Step": "Validate the response.",
                 "Data": "", "Expected Result": last})
    return steps


def is_negative_by_name(name: str) -> bool:
    if not name:
        return False
    # common pattern in your collections: "No header", "No description", etc.
    return bool(re.search(r"\bNo\b", name, flags=re.IGNORECASE))


def try_parse_json_body(body_raw: str) -> Optional[Any]:
    if not body_raw:
        return None
    try:
        return json.loads(body_raw)
    except Exception:
        try:
            return json.loads(body_raw.replace("\r\n", "\n"))
        except Exception:
            return None


def mutate_json_remove_key(obj: Any, key: str) -> Any:
    if not isinstance(obj, dict):
        return obj
    cloned = dict(obj)
    cloned.pop(key, None)
    return cloned


def build_repo_path(root_repo: str, endpoint: str, folder_path: str) -> str:
    # Keep hierarchy under BE
    # Example: BE/SAAC/tes/rest/spi/sendmsgserv/SendMessage/Tek Takipçiye Mesaj
    ep = endpoint.strip("/")
    ep_part = ep.replace("/", "/") if ep else "unknown-endpoint"
    fp = folder_path if folder_path else "Root"
    return f"{root_repo}/SAAC/{ep_part}/{fp}".replace("//", "/")


def make_case_id(prefix: str, summary: str, index: int) -> str:
    # readable & stable enough; also avoids collisions if needed
    # Example: SAAC-TC-0001
    return f"{prefix}-{index:04d}"


def generate_cases(
    requests: List[PMRequest],
    root_repo: str = "BE",
    test_set_key: str = "QABR-45225",
    id_prefix: str = "SAAC-TC",
    include_generated_negatives: bool = True,
    mask_secrets: bool = True,
    max_extra_cases_per_request: int = 10,
) -> pd.DataFrame:
    cases: List[Dict[str, Any]] = []
    case_counter = 0

    for pm in requests:
        ep = endpoint_path(pm.url_raw)

        base_summary = f"{pm.method} | {ep} | {pm.folder_path} | {pm.request_name}"
        base_description = (
            f"Source: Postman Collection '{pm.collection_name}'\n"
            f"Folder: {pm.folder_path}\n"
            f"Request name: {pm.request_name}\n"
            f"Endpoint: {ep}\n"
            f"Method: {pm.method}"
        )
        precondition = (
            "The test environment is accessible. Valid credentials are available. "
            "Required test users and test data (e.g., MSISDNs, ids, tokens) are prepared."
        )

        repo_path = build_repo_path(root_repo, ep, pm.folder_path)
        req_data = request_data_block(pm, mask_secrets=mask_secrets)

        positive = not is_negative_by_name(pm.request_name)
        steps = make_steps_base(req_data, positive=positive)

        case_counter += 1
        case_id = make_case_id(id_prefix, base_summary, case_counter)

        scenario_expected = steps[-1]["Expected Result"]

        # Flatten steps into rows
        for i, stp in enumerate(steps, start=1):
            cases.append(
                {
                    "Test Case ID": case_id,
                    "Test Summary": base_summary,
                    "Test Description": base_description,
                    "Precondition": precondition,
                    "Priority": "High" if positive else "Medium",
                    "Test Repository Path": repo_path,
                    "Step": f"{i}. {stp['Step']}",
                    "Data": stp["Data"],
                    "Expected Result": stp["Expected Result"],
                    "Scenario Expected Result": scenario_expected,
                    "test set": test_set_key,
                }
            )

        if not include_generated_negatives:
            continue

        # ---------- Generated negative/validation cases ----------
        extra_added = 0

        # Missing Authorization (if any auth/header exists)
        has_auth_header = any(str(h.get("key", "")).lower(
        ) == "authorization" for h in (pm.headers or []))
        if has_auth_header or pm.auth_type:
            case_counter += 1
            cid = make_case_id(id_prefix, base_summary +
                               "|Missing Auth", case_counter)

            headers_no_auth = [h for h in (pm.headers or []) if str(
                h.get("key", "")).lower() != "authorization"]
            pm_no_auth = PMRequest(
                **{**pm.__dict__, "headers": headers_no_auth, "request_name": pm.request_name + " | Missing Authorization"}
            )
            req_data2 = request_data_block(
                pm_no_auth, mask_secrets=mask_secrets)
            steps2 = make_steps_base(req_data2, positive=False)
            scenario_expected2 = steps2[-1]["Expected Result"]

            for i, stp in enumerate(steps2, start=1):
                cases.append(
                    {
                        "Test Case ID": cid,
                        "Test Summary": f"{pm.method} | {ep} | {pm.folder_path} | Missing Authorization",
                        "Test Description": base_description + "\n\nVariant: Missing Authorization header.",
                        "Precondition": precondition,
                        "Priority": "High",
                        "Test Repository Path": repo_path,
                        "Step": f"{i}. {stp['Step']}",
                        "Data": stp["Data"],
                        "Expected Result": stp["Expected Result"],
                        "Scenario Expected Result": scenario_expected2,
                        "test set": test_set_key,
                    }
                )
            extra_added += 1

        if extra_added >= max_extra_cases_per_request:
            continue

        # Missing Content-Type when body exists
        if pm.body_raw:
            case_counter += 1
            cid = make_case_id(id_prefix, base_summary +
                               "|Missing Content-Type", case_counter)

            headers_no_ct = [h for h in (pm.headers or []) if str(
                h.get("key", "")).lower() != "content-type"]
            pm_no_ct = PMRequest(
                **{**pm.__dict__, "headers": headers_no_ct, "request_name": pm.request_name + " | Missing Content-Type"}
            )
            req_data2 = request_data_block(pm_no_ct, mask_secrets=mask_secrets)
            steps2 = make_steps_base(req_data2, positive=False)
            scenario_expected2 = steps2[-1]["Expected Result"]

            for i, stp in enumerate(steps2, start=1):
                cases.append(
                    {
                        "Test Case ID": cid,
                        "Test Summary": f"{pm.method} | {ep} | {pm.folder_path} | Missing Content-Type",
                        "Test Description": base_description + "\n\nVariant: Missing Content-Type header.",
                        "Precondition": precondition,
                        "Priority": "Medium",
                        "Test Repository Path": repo_path,
                        "Step": f"{i}. {stp['Step']}",
                        "Data": stp["Data"],
                        "Expected Result": stp["Expected Result"],
                        "Scenario Expected Result": scenario_expected2,
                        "test set": test_set_key,
                    }
                )
            extra_added += 1

        if extra_added >= max_extra_cases_per_request:
            continue

        # Invalid JSON (only if body looks JSON)
        body_obj = try_parse_json_body(pm.body_raw)
        if pm.body_raw and body_obj is None:
            # already invalid; don't generate another invalid JSON case
            pass
        elif pm.body_raw and body_obj is not None:
            case_counter += 1
            cid = make_case_id(id_prefix, base_summary +
                               "|Invalid JSON", case_counter)

            bad_body = '{"broken": "json" '  # missing closing brace
            pm_bad = PMRequest(**{**pm.__dict__, "body_raw": bad_body,
                               "request_name": pm.request_name + " | Invalid JSON"})
            req_data2 = request_data_block(pm_bad, mask_secrets=mask_secrets)
            steps2 = make_steps_base(req_data2, positive=False)
            scenario_expected2 = steps2[-1]["Expected Result"]

            for i, stp in enumerate(steps2, start=1):
                cases.append(
                    {
                        "Test Case ID": cid,
                        "Test Summary": f"{pm.method} | {ep} | {pm.folder_path} | Invalid JSON",
                        "Test Description": base_description + "\n\nVariant: Invalid JSON body.",
                        "Precondition": precondition,
                        "Priority": "Medium",
                        "Test Repository Path": repo_path,
                        "Step": f"{i}. {stp['Step']}",
                        "Data": stp["Data"],
                        "Expected Result": stp["Expected Result"],
                        "Scenario Expected Result": scenario_expected2,
                        "test set": test_set_key,
                    }
                )
            extra_added += 1

        if extra_added >= max_extra_cases_per_request:
            continue

        # Missing required keys (heuristic: top-level keys)
        if isinstance(body_obj, dict):
            keys = list(body_obj.keys())
            # limit to avoid explosion
            for k in keys[: max(0, max_extra_cases_per_request - extra_added)]:
                mutated = mutate_json_remove_key(body_obj, k)
                case_counter += 1
                cid = make_case_id(id_prefix, base_summary +
                                   f"|Missing {k}", case_counter)

                pm_mut = PMRequest(
                    **{
                        **pm.__dict__,
                        "body_raw": json.dumps(mutated, ensure_ascii=False, indent=2),
                        "request_name": pm.request_name + f" | Missing field: {k}",
                    }
                )
                req_data2 = request_data_block(
                    pm_mut, mask_secrets=mask_secrets)
                steps2 = make_steps_base(req_data2, positive=False)
                scenario_expected2 = steps2[-1]["Expected Result"]

                for i, stp in enumerate(steps2, start=1):
                    cases.append(
                        {
                            "Test Case ID": cid,
                            "Test Summary": f"{pm.method} | {ep} | {pm.folder_path} | Missing field: {k}",
                            "Test Description": base_description + f"\n\nVariant: Missing top-level field '{k}'.",
                            "Precondition": precondition,
                            "Priority": "High",
                            "Test Repository Path": repo_path,
                            "Step": f"{i}. {stp['Step']}",
                            "Data": stp["Data"],
                            "Expected Result": stp["Expected Result"],
                            "Scenario Expected Result": scenario_expected2,
                            "test set": test_set_key,
                        }
                    )
                extra_added += 1
                if extra_added >= max_extra_cases_per_request:
                    break

    return pd.DataFrame(cases)


# -----------------------------
# Streamlit UI
# -----------------------------
st.set_page_config(
    page_title="Postman → Xray Manual Test Generator", layout="wide")

st.title("Postman → Xray Manual Test Case Generator")
st.caption(
    "Upload Postman collections and export an Xray-importable ';' CSV (English).")

with st.sidebar:
    st.header("Options")
    root_repo = st.text_input("Repository root", value="BE")
    test_set_key = st.text_input("Test set key", value="QABR-45225")
    id_prefix = st.text_input("Test Case ID prefix", value="SAAC-TC")

    include_neg = st.checkbox(
        "Generate extra negative/validation cases", value=True)
    max_extra = st.slider("Max extra cases per request",
                          min_value=0, max_value=30, value=10, step=1)

    mask_secrets = st.checkbox("Mask secrets (recommended)", value=True)

uploaded = st.file_uploader(
    "Upload Postman collection JSON file(s)",
    type=["json"],
    accept_multiple_files=True,
)

colA, colB = st.columns([1, 1])

if uploaded:
    all_requests: List[PMRequest] = []
    for f in uploaded:
        try:
            content = json.loads(f.getvalue().decode("utf-8"))
        except Exception:
            # fallback: try latin-1
            content = json.loads(f.getvalue().decode("latin-1"))
        all_requests.extend(parse_postman_collection(
            content, fallback_name=f.name))

    with colA:
        st.subheader("Parsed Requests")
        st.write(f"Collections uploaded: **{len(uploaded)}**")
        st.write(f"Requests found: **{len(all_requests)}**")

        # quick preview table
        preview = pd.DataFrame(
            [
                {
                    "Collection": r.collection_name,
                    "Folder": r.folder_path,
                    "Name": r.request_name,
                    "Method": r.method,
                    "Endpoint": endpoint_path(r.url_raw),
                }
                for r in all_requests[:200]
            ]
        )
        st.dataframe(preview, use_container_width=True, height=360)

    with colB:
        st.subheader("Generate")
        if st.button("Generate Xray CSV", type="primary", use_container_width=True):
            df = generate_cases(
                requests=all_requests,
                root_repo=root_repo.strip() or "BE",
                test_set_key=test_set_key.strip() or "QABR-45225",
                id_prefix=id_prefix.strip() or "SAAC-TC",
                include_generated_negatives=include_neg,
                mask_secrets=mask_secrets,
                max_extra_cases_per_request=max_extra,
            )

            st.success(
                f"Generated rows (steps): {len(df)} | Unique test cases: {df['Test Case ID'].nunique()}")

            st.subheader("Output Preview")
            st.dataframe(df.head(200), use_container_width=True, height=360)

            csv_bytes = df.to_csv(index=False, sep=";",
                                  encoding="utf-8-sig").encode("utf-8-sig")
            st.download_button(
                label="Download Xray CSV (;)",
                data=csv_bytes,
                file_name="xray_manual_tests.csv",
                mime="text/csv",
                use_container_width=True,
            )
else:
    st.info("Upload one or more Postman collection JSON files to start.")
