import java.io.FileWriter;
import java.io.PrintWriter;
import java.math.BigDecimal;
import java.math.RoundingMode;
import java.security.MessageDigest;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;

public class TreasurySoxAndFraudEngine {

    private static final String DB_URL = "jdbc:sqlite:treasury_sentinel.db";

    private static String sha256(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(input.getBytes("UTF-8"));
            StringBuilder hex = new StringBuilder();
            for (byte b : hash) {
                String h = Integer.toHexString(0xff & b);
                if (h.length() == 1) hex.append('0');
                hex.append(h);
            }
            return hex.toString();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static void main(String[] args) {
        System.out.println("Running wire audit & compliance checks...");

        try {
            Class.forName("org.sqlite.JDBC");
            Connection conn = DriverManager.getConnection(DB_URL);
            Statement stmt = conn.createStatement();

            // 1. Check audit log hashes
            ResultSet rsLedger = stmt.executeQuery(
                "SELECT ledger_seq, event_timestamp, event_category, reference_id, amount_usd, actor_id, prev_hash, curr_hash FROM sox_immutable_ledger ORDER BY ledger_seq ASC"
            );

            String expectedPrev = "0000000000000000000000000000000000000000000000000000000000000000";
            boolean hashMismatch = false;
            int blockCount = 0;
            StringBuilder jsLedger = new StringBuilder("[");

            while (rsLedger.next()) {
                blockCount++;
                int seq = rsLedger.getInt("ledger_seq");
                String ts = rsLedger.getString("event_timestamp");
                String cat = rsLedger.getString("event_category");
                String ref = rsLedger.getString("reference_id");
                BigDecimal amt = rsLedger.getBigDecimal("amount_usd");
                String actor = rsLedger.getString("actor_id");
                String dbPrev = rsLedger.getString("prev_hash");
                String dbCurr = rsLedger.getString("curr_hash");

                String payload = String.format("%s|%s|%s|%.2f|%s|%s", ts, cat, ref, amt.doubleValue(), actor, dbPrev);
                String calcHash = sha256(payload);

                if (!dbPrev.equals(expectedPrev) || !calcHash.equals(dbCurr)) {
                    hashMismatch = true;
                }
                expectedPrev = dbCurr;

                jsLedger.append(String.format(
                    "{seq:%d, ts:'%s', cat:'%s', ref:'%s', amt:%.2f, actor:'%s', origHash:'%s'},",
                    seq, ts, cat, ref, amt.doubleValue(), actor, dbCurr
                ));
            }
            if (jsLedger.length() > 1) jsLedger.setLength(jsLedger.length() - 1);
            jsLedger.append("]");
            rsLedger.close();

            // 2. Check wire transfers
            ResultSet rsSurv = stmt.executeQuery("SELECT * FROM v_treasury_wire_surveillance");

            BigDecimal flaggedTotal = BigDecimal.ZERO;
            int flaggedCount = 0;
            int digitFourCount = 0;
            int totalWires = 0;

            PrintWriter csv = new PrintWriter(new FileWriter("sample_data/credit_surveillance_output.csv"));
            csv.println("wire_id,vendor_id,vendor_name,sector,request_timestamp,amount_usd,approval_limit,routing_status,vendor_24h_total,flagged_domain,rule_triggered,status");

            StringBuilder wireRowsHtml = new StringBuilder();

            while (rsSurv.next()) {
                totalWires++;
                String wireId = rsSurv.getString("wire_id");
                String vendorName = rsSurv.getString("vendor_name");
                BigDecimal amount = rsSurv.getBigDecimal("amount_usd");
                BigDecimal limit = rsSurv.getBigDecimal("sox_dual_auth_limit");
                String routingStatus = rsSurv.getString("routing_integrity_status");
                String approver = rsSurv.getString("approver_id");
                BigDecimal vendorTotal = rsSurv.getBigDecimal("cumulative_vendor_wire_usd");
                String becDomain = rsSurv.getString("active_bec_domain");
                String memo = rsSurv.getString("sanitized_payment_memo");

                if (amount.toPlainString().charAt(0) == '4') digitFourCount++;

                String status = "PASS";
                String reason = "None";
                boolean flagged = false;

                if (vendorTotal.compareTo(limit) > 0 && "NONE_SINGLE_AUTH".equals(approver) && rsSurv.getInt("vendor_wire_count") > 1) {
                    status = "HOLD";
                    reason = "Split wire pattern over $50k limit + routing mismatch";
                    flagged = true;
                } else if ("ROUTING_MISMATCH".equals(routingStatus)) {
                    status = "HOLD";
                    reason = "ABA routing number doesn't match vendor file";
                    flagged = true;
                } else if (amount.compareTo(limit) > 0 && "NONE_SINGLE_AUTH".equals(approver)) {
                    status = "HOLD";
                    reason = "Single auth over $50k threshold";
                    flagged = true;
                }

                if (flagged) {
                    flaggedCount++;
                    flaggedTotal = flaggedTotal.add(amount);
                }

                csv.println(String.format("%s,%s,%s,%s,%s,%.2f,%.2f,%s,%.2f,%s,%s,%s",
                    wireId, rsSurv.getString("vendor_id"), vendorName, rsSurv.getString("sector"),
                    rsSurv.getString("request_timestamp"), amount, limit, routingStatus,
                    vendorTotal, becDomain, reason, status
                ));

                String tag = flagged
                    ? "<span class='tag-hold'>[HOLD]</span>"
                    : "<span class='tag-pass'>[PASS]</span>";

                wireRowsHtml.append(String.format(
                    "<tr><td>%s</td><td>%s</td><td>$%,.2f</td><td>$%,.2f</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>",
                    wireId, vendorName, amount.doubleValue(), vendorTotal.doubleValue(),
                    routingStatus, becDomain, reason, memo, tag
                ));
            }
            rsSurv.close();
            csv.close();

            double digit4Pct = (digitFourCount * 100.0) / totalWires;

            // 3. Write HTML page
            PrintWriter html = new PrintWriter(new FileWriter("treasury_soc_report.html"));
            html.println("<!DOCTYPE html><html lang='en'><head><meta charset='UTF-8'><title>Corporate Treasury & Wire Settlement Integrity System</title>");
            html.println("<style>");
            html.println("body{font-family:'Courier New',Courier,monospace;background:#ffffff;color:#000000;margin:0;padding:20px;font-size:13px;line-height:1.4;}");
            html.println(".header{border-bottom:2px solid #000000;padding-bottom:10px;margin-bottom:20px;display:flex;justify-content:space-between;align-items:flex-end;}");
            html.println(".header h1{margin:0;font-size:16px;font-weight:bold;text-transform:uppercase;}");
            html.println(".header .links{font-size:12px;}");
            html.println(".header .links a{color:#000000;text-decoration:underline;margin-left:15px;}");
            html.println(".metrics-table{width:100%;border-collapse:collapse;margin-bottom:20px;border:1px solid #000000;}");
            html.println(".metrics-table td{border:1px solid #000000;padding:8px 12px;font-size:12px;}");
            html.println(".metrics-label{font-weight:bold;background:#f0f0f0;width:20%;}");
            html.println(".section-title{font-size:13px;font-weight:bold;text-transform:uppercase;margin:25px 0 8px 0;border-bottom:1px solid #000000;padding-bottom:3px;}");
            html.println(".grid-2{display:grid;grid-template-columns:1fr 1fr;gap:20px;margin-bottom:20px;}");
            html.println(".card{border:1px solid #000000;padding:12px 15px;}");
            html.println(".card h3{margin:0 0 5px 0;font-size:12.5px;text-transform:uppercase;font-weight:bold;}");
            html.println(".card p{margin:0 0 10px 0;font-size:11.5px;color:#333333;}");
            html.println("label{display:block;font-size:11px;font-weight:bold;margin:8px 0 2px 0;text-transform:uppercase;}");
            html.println("input,textarea{width:100%;box-sizing:border-box;background:#ffffff;color:#000000;border:1px solid #000000;padding:5px;font-family:'Courier New',Courier,monospace;font-size:12px;}");
            html.println(".output-pane{background:#f9f9f9;border:1px solid #000000;padding:8px;margin-top:8px;font-size:11.5px;white-space:pre-wrap;}");
            html.println("button{background:#000000;color:#ffffff;border:1px solid #000000;padding:5px 10px;font-family:'Courier New',Courier,monospace;font-size:11.5px;cursor:pointer;margin-top:6px;margin-right:5px;}");
            html.println("button.alt{background:#ffffff;color:#000000;}");
            html.println("table.data-table{width:100%;border-collapse:collapse;margin-top:5px;font-size:11.5px;}");
            html.println("table.data-table th, table.data-table td{border:1px solid #000000;padding:5px 7px;text-align:left;vertical-align:top;}");
            html.println("table.data-table th{background:#e0e0e0;font-weight:bold;}");
            html.println(".tag-hold{font-weight:bold;color:#cc0000;}");
            html.println(".tag-pass{font-weight:bold;color:#006600;}");
            html.println(".amt-input{width:90px;padding:2px;font-family:'Courier New',Courier,monospace;font-size:11.5px;}");
            html.println(".footer{margin-top:30px;border-top:1px solid #000000;padding-top:10px;font-size:11px;display:flex;justify-content:space-between;}");
            html.println("</style></head><body>");

            html.println("<div class='header'><div><h1>Corporate Treasury & Wire Settlement Integrity System</h1>");
            html.println("<div style='font-size:11.5px;margin-top:2px;'>SQLite DB | Python Telemetry Scraper | Java JDBC Compliance Engine</div></div>");
            html.println("<div class='links'><a href='https://github.com/coreyied' target='_blank'>GitHub: coreyied</a><a href='sample_data/credit_surveillance_output.csv' download>Export CSV</a></div></div>");

            html.println("<table class='metrics-table'>");
            html.println("<tr><td class='metrics-label'>Ledger Status</td><td id='kpi-ledger' style='color:#006600;font-weight:bold;'>OK (" + blockCount + " rows verified)</td>");
            html.println("<td class='metrics-label'>Held Wires</td><td style='color:#cc0000;font-weight:bold;'>" + flaggedCount + " of " + totalWires + " flagged</td></tr>");
            html.println("<tr><td class='metrics-label'>Held Amount</td><td>$" + String.format("%,.2f", flaggedTotal.doubleValue()) + "</td>");
            html.println("<td class='metrics-label'>Leading '4' Digit</td><td>" + String.format("%.1f%%", digit4Pct) + " (Benford avg: 9.7%)</td></tr>");
            html.println("</table>");

            // Interactive Modules
            html.println("<div class='section-title'>1. Validation Checks & Test Scanners</div>");
            html.println("<div class='grid-2'>");

            // Tool 1
            html.println("<div class='card'><h3>Vendor Domain & Routing Check</h3>");
            html.println("<p>Tests domain similarity (Levenshtein distance & entropy) against vendor records and validates 9-digit ABA routing numbers using Mod-10 weights.</p>");
            html.println("<label>Expected Vendor Domain</label><input id='offDom' value='vanguardmidstream.com' oninput='runBecLab()'>");
            html.println("<label>Incoming Invoice Domain</label><input id='atkDom' value='vanguardmidstrearn.com' oninput='runBecLab()'>");
            html.println("<label>9-Digit ABA Routing Number</label><input id='abaNum' value='021000021' maxlength='9' oninput='runBecLab()'>");
            html.println("<div class='output-pane' id='becOut'></div></div>");

            // Tool 2
            html.println("<div class='card'><h3>Payment Memo PII & Card Filter</h3>");
            html.println("<p>Scans text fields for credit card numbers, tax SSNs, and API keys. Validates card numbers via the Luhn check before tokenizing.</p>");
            html.println("<label>Sample Wire Memo Text</label>");
            html.println("<textarea id='dlpIn' rows='4' oninput='runDlpLab()'>Wire memo: Card 4532-0151-1283-0366, SSN 442-88-1920, token sk_live_9948102948102948abc</textarea>");
            html.println("<div class='output-pane' id='dlpOut'></div></div>");

            html.println("</div>");

            // Tool 3: Ledger Table
            html.println("<div class='section-title'>2. Audit Trail & Hash Chain (sox_immutable_ledger)</div>");
            html.println("<p style='font-size:11.5px;margin-bottom:8px;'>Change any dollar amount below to test if an unauthorized edit breaks the SHA-256 chain.</p>");
            html.println("<div style='margin-bottom:8px;'><button onclick='simulateAttack()'>Simulate $10k Edit on Row #2</button><button class='alt' onclick='resetLedger()'>Reset Values</button></div>");
            html.println("<div class='output-pane' id='tamperOut' style='margin-bottom:8px;'>Status: All row hashes match database state.</div>");
            html.println("<table class='data-table'><thead><tr><th>Row</th><th>Timestamp</th><th>Reference ID</th><th>Amount (Editable)</th><th>Actor</th><th>Previous Hash</th><th>Calculated SHA-256 Hash</th><th>Status</th></tr></thead>");
            html.println("<tbody id='ledgerBody'></tbody></table>");

            // Surveillance Table
            html.println("<div class='section-title'>3. Wire Transfer Surveillance View (v_treasury_wire_surveillance)</div>");
            html.println("<table class='data-table'><thead><tr><th>Wire ID</th><th>Vendor</th><th>Amount</th><th>24h Total</th><th>Routing</th><th>Domain Flag</th><th>Rule Triggered</th><th>Scrubbed Memo</th><th>Status</th></tr></thead><tbody>");
            html.println(wireRowsHtml.toString());
            html.println("</table>");

            html.println("<div class='footer'><div>Repository: <a href='https://github.com/coreyied' target='_blank'>github.com/coreyied</a></div><div>Corporate Treasury & Wire Settlement Integrity System</div></div>");

            // Scripts
            html.println("<script>");
            html.println("const origLedger = " + jsLedger.toString() + ";");
            html.println("let liveLedger = JSON.parse(JSON.stringify(origLedger));");

            html.println("function levenshtein(a,b){const m=Array.from({length:a.length+1},(_,i)=>[i]);for(let j=1;j<=b.length;j++)m[0][j]=j;for(let i=1;i<=a.length;i++)for(let j=1;j<=b.length;j++)m[i][j]=Math.min(m[i-1][j]+1,m[i][j-1]+1,m[i-1][j-1]+(a[i-1]!==b[j-1]?1:0));return m[a.length][b.length];}");
            html.println("function entropy(s){if(!s)return 0;const f={};for(let c of s)f[c]=(f[c]||0)+1;return Object.values(f).reduce((acc,v)=>{const p=v/s.length;return acc-p*Math.log2(p);},0);}");
            html.println("function checkAba(r){if(!/^\\d{9}$/.test(r))return false;const w=[3,7,1,3,7,1,3,7,1];let s=0;for(let i=0;i<9;i++)s+=parseInt(r[i])*w[i];return s%10===0;}");
            html.println("function runBecLab(){const o=document.getElementById('offDom').value.trim().split('.')[0];const a=document.getElementById('atkDom').value.trim().split('.')[0];const aba=document.getElementById('abaNum').value.trim();const d=levenshtein(o,a);const sim=Math.max(0,((1-d/Math.max(o.length,a.length,1))*100)).toFixed(1);const ent=entropy(a).toFixed(2);const abaOk=checkAba(aba);document.getElementById('becOut').innerHTML=`Edit distance: ${d} | Similarity: ${sim}% | Entropy: ${ent} bits\\nABA Mod-10 Checksum: ${abaOk?'VALID':'INVALID'}\\nStatus: ${(sim>=75&&d>0)?'FLAGGED (Potential Lookalike)':'NORMAL'}`;}");

            html.println("function luhn(num){const d=num.replace(/\\D/g,'').split('').reverse().map(Number);if(d.length<13||d.length>19)return false;const s=d.reduce((a,v,i)=>{if(i%2===1){v*=2;if(v>9)v-=9;}return a+v;},0);return s%10===0;}");
            html.println("function fnvHash(str){let h=2166136261;for(let i=0;i<str.length;i++){h^=str.charCodeAt(i);h=Math.imul(h,16777619);}return (h>>>0).toString(16).toUpperCase().padStart(8,'0');}");
            html.println("function runDlpLab(){let txt=document.getElementById('dlpIn').value;let hits=[];txt=txt.replace(/\\b(?:\\d{4}[-\\s]?){3}\\d{4}\\b/g,m=>{if(luhn(m)){const t=fnvHash(m)+'T';hits.push(`Card verified via Luhn -> Token: ${t}`);return `[REDACTED_CARD:${t}]`;}else{hits.push(`16-digit failed Luhn check`);return m;}});txt=txt.replace(/\\b\\d{3}-\\d{2}-\\d{4}\\b/g,m=>{const t=fnvHash(m)+'S';hits.push(`SSN matched -> Token: ${t}`);return `[REDACTED_SSN:${t}]`;});txt=txt.replace(/sk_live_[0-9a-zA-Z]{8,}/g,m=>{const t=fnvHash(m)+'K';hits.push(`API Key matched -> Token: ${t}`);return `[REDACTED_KEY:${t}]`;});document.getElementById('dlpOut').innerHTML=`Scrubbed Text:\\n${txt}\\n\\nFilter Log:\\n${hits.join('\\n')||'No matches.'}`;}");

            html.println("async function sha256(str){const buf=await crypto.subtle.digest('SHA-256',new TextEncoder().encode(str));return Array.from(new Uint8Array(buf)).map(b=>b.toString(16).padStart(2,'0')).join('');}");
            html.println("async function renderLedger(){let prev='0'.repeat(64);let html='';let broken=false;let firstBroken=null;for(let i=0;i<liveLedger.length;i++){const b=liveLedger[i];const payload=`${b.ts}|${b.cat}|${b.ref}|${Number(b.amt).toFixed(2)}|${b.actor}|${prev}`;const curr=await sha256(payload);const match=(curr===b.origHash)&&!broken;if(!match&&!broken){broken=true;firstBroken=b.seq;}const badge=match?'<span style=\"color:#006600;font-weight:bold;\">OK</span>':'<span style=\"color:#cc0000;font-weight:bold;\">MISMATCH</span>';html+=`<tr style=\"background:${match?'#ffffff':'#ffeeee'}\"><td>#${b.seq}</td><td>${b.ts}</td><td>${b.ref}</td><td><input type=\"number\" class=\"amt-input\" value=\"${b.amt}\" oninput=\"updateAmt(${i},this.value)\"></td><td>${b.actor}</td><td>${prev.substring(0,12)}...</td><td style=\"color:${match?'#000':'#cc0000'};font-weight:${match?'normal':'bold'}\">${curr.substring(0,14)}...</td><td>${badge}</td></tr>`;prev=curr;}document.getElementById('ledgerBody').innerHTML=html;const kpi=document.getElementById('kpi-ledger');const out=document.getElementById('tamperOut');if(broken){kpi.innerHTML='HASH MISMATCH (Row #'+firstBroken+')';kpi.style.color='#cc0000';out.innerHTML='<span style=\"color:#cc0000;font-weight:bold;\">TAMPER DETECTED:</span> Hash mismatch at Row #'+firstBroken+'. Subsequent chain is broken.';}else{kpi.innerHTML='OK ('+liveLedger.length+' rows verified)';kpi.style.color='#006600';out.innerHTML='Status: All row hashes match database state.';}}");
            html.println("function updateAmt(idx,val){liveLedger[idx].amt=parseFloat(val||0);renderLedger();}");
            html.println("function simulateAttack(){liveLedger[1].amt=152000.00;renderLedger();}");
            html.println("function resetLedger(){liveLedger=JSON.parse(JSON.stringify(origLedger));renderLedger();}");
            html.println("runBecLab();runDlpLab();renderLedger();");
            html.println("</script></body></html>");
            html.close();

            System.out.println("Saved CSV: sample_data/credit_surveillance_output.csv");
            System.out.println("Saved HTML: treasury_soc_report.html");
            conn.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
