import json
import os
import html

def load_json(path):
    if not os.path.exists(path):
        return None
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def escape_html(text):
    """Escape HTML special characters to prevent XSS and display issues."""
    if text is None:
        return ""
    return html.escape(str(text))

def build_table(data, columns):
    if not data:
        return "<div class='no-data'>هیچ داده‌ای موجود نیست.</div>"
    
    table = "<div class='table-container'><table>"
    
    # Table header
    table += "<thead><tr>"
    for col in columns:
        table += f"<th>{escape_html(col)}</th>"
    table += "</tr></thead>"
    
    # Table body
    table += "<tbody>"
    for row in data:
        table += "<tr>"
        for col in columns:
            cell_value = row.get(col, '')
            table += f"<td>{escape_html(cell_value)}</td>"
        table += "</tr>"
    table += "</tbody></table></div>"
    return table

def build():
    os.makedirs("results", exist_ok=True)

    # Load all JSON data
    stats = load_json("results/stats.json")
    http_data = load_json("results/http_analysis.json")
    dns_data = load_json("results/dns_analysis.json")
    tls_data = load_json("results/tls_analysis.json")
    arp_data = load_json("results/arp_analysis.json")
    security_data = load_json("results/security_analysis.json")

    # ====== Summary Table ======
    summary_table = []
    if stats:
        for k,v in stats.items():
            summary_table.append({"Metric": k, "Value": str(v)})
    summary_table_html = build_table(summary_table, ["Metric", "Value"]) if summary_table else "<p>هیچ داده‌ای موجود نیست.</p>"

    # ====== HTTP Table ======
    http_table_rows = []
    if http_data and "http_events" in http_data:
        for e in http_data["http_events"]:
            parsed = e.get("parsed", {})
            line = parsed.get("line", "")
            path = parsed.get("path", "")
            host = parsed.get("headers", {}).get("Host", "")
            http_table_rows.append({
                "Timestamp": e.get("timestamp", ""),
                "Source": e.get("src", ""),
                "Destination": e.get("dst", ""),
                "Host": host,
                "Path": path
            })
    http_table_html = build_table(http_table_rows, ["Timestamp", "Source", "Destination", "Host", "Path"])

    # ====== DNS Table ======
    dns_table_rows = []
    if dns_data and "dns_events" in dns_data:
        for e in dns_data["dns_events"]:
            dns_table_rows.append({
                "Timestamp": e.get("timestamp", ""),
                "Query": e.get("query", ""),
                "Response": e.get("response", ""),
                "Type": e.get("type", "")
            })
    dns_table_html = build_table(dns_table_rows, ["Timestamp", "Query", "Response", "Type"])

    # ====== TLS Table ======
    tls_table_rows = []
    if tls_data and "tls_events" in tls_data:
        for e in tls_data["tls_events"]:
            tls_table_rows.append({
                "Timestamp": e.get("timestamp", ""),
                "Source": e.get("src", ""),
                "Destination": e.get("dst", ""),
                "SNI": e.get("sni", "")
            })
    tls_table_html = build_table(tls_table_rows, ["Timestamp", "Source", "Destination", "SNI"])

    # ====== ARP Table ======
    arp_table_rows = []
    if arp_data and "arp_events" in arp_data:
        for e in arp_data["arp_events"]:
            arp_table_rows.append({
                "Timestamp": e.get("timestamp", ""),
                "Source": e.get("src", ""),
                "Destination": e.get("dst", ""),
                "MAC_Source": e.get("mac_src", ""),
                "MAC_Destination": e.get("mac_dst", "")
            })
    arp_table_html = build_table(arp_table_rows, ["Timestamp", "Source", "Destination", "MAC_Source", "MAC_Destination"])

    # ====== ATTACK / Security Table ======
    attack_table_rows = []
    if security_data and "attacks" in security_data:
        for e in security_data["attacks"]:
            attack_table_rows.append({
                "Timestamp": e.get("timestamp", ""),
                "Type": e.get("type", ""),
                "Source": e.get("src", ""),
                "Destination": e.get("dst", ""),
                "Info": e.get("info", "")
            })
    attack_table_html = build_table(attack_table_rows, ["Timestamp", "Type", "Source", "Destination", "Info"])

    # ====== Save JSON Combined ======
    combined_report = {
        "summary": stats,
        "http": http_data,
        "dns": dns_data,
        "tls": tls_data,
        "arp": arp_data,
        "attacks": security_data
    }
    with open("results/report.json", "w", encoding="utf-8") as f:
        json.dump(combined_report, f, indent=2, ensure_ascii=False)

    # ====== Build HTML ======
    tpl_path = "templates/report_template.html"
    if os.path.exists(tpl_path):
        with open(tpl_path, "r", encoding="utf-8") as f:
            template = f.read()
    else:
        template = "<html><body><h1>Report</h1><pre>{{REPORT}}</pre></body></html>"

    # Debug: Print template placeholders
    print("Template placeholders found in the file:")
    import re
    placeholders = re.findall(r'\{\{.*?\}\}', template)
    print(placeholders)

    # Replace placeholders with actual content
    replacements = {
        "{{summary_table}}": summary_table_html,
        "{{http_table}}": http_table_html,
        "{{dns_table}}": dns_table_html,
        "{{tls_table}}": tls_table_html,
        "{{arp_table}}": arp_table_html,
        "{{attack_table}}": attack_table_html
    }
    
    # Debug: Print replacements
    print("\nReplacing placeholders with content:")
    for placeholder, content in replacements.items():
        print(f"- {placeholder}: {bool(content)} (length: {len(str(content))} chars)")
    
    # Perform all replacements
    html_content = template
    for placeholder, content in replacements.items():
        replacement = content if content else "<div class='no-data'>هیچ داده‌ای موجود نیست.</div>"
        html_content = html_content.replace(placeholder, replacement)
    
    # Debug: Check if replacements were made
    missing_placeholders = [p for p in placeholders if p not in replacements]
    if missing_placeholders:
        print("\nWarning: The following placeholders were not replaced:", missing_placeholders)

    with open("results/report.html", "w", encoding="utf-8") as f:
        f.write(html_content)

    print("Report generated successfully: results/report.json and results/report.html")

if __name__ == "__main__":
    build()
