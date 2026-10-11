For your thesis, “A Ransomware Detection System Using Machine Learning and Runtime Process Behavior,” I recommend narrowing the scope to suspicious file-operation behavior during ransomware execution.

Rather than monitoring everything a process can do—network connections, Windows API calls, registry changes, memory, persistence, and privilege escalation—focus on how a process interacts with files.

This is a strong scope because ransomware often needs to access and modify victims' files to encrypt them, and traditional endpoint security already uses file-system monitoring, behavioral rules, and ransomware protection mechanisms. That gives you a meaningful basis for comparing your LightGBM-based detector with traditional approaches.

The important distinction is that you're comparing detection approaches for the same behavior, not trying to compare your entire system against a complete commercial antivirus product.

## 1. Main behaviors to focus on

I would prioritize three behaviors and treat them as one combined detection problem.

[Arquivos Criptografados Automaticamente, Como Remover a Criptografia - EaseUS](https://images.openai.com/static-rsc-4/N-xcakT6x7AaNtqxe9VAPfSQJwdncL8HiEuhGYNYPLSkA-VEEi29_57IS-gumHnNuXtvDxiMyXZKiFrmoFN8mQpqkmXA9lMgHckbObgmsv02NXZhzyHyVkB9NbTPAky4uUPZgkYLgD1GXM4BQe03la3f4Qrrw7ss6Ed_QlInyI4?purpose=inline)

Behavior 1 — High-volume file modification

Highest priority

Measure how many distinct files a process modifies or writes within a short time window.

Example features

- `file_write_count`
- `unique_files_modified`
- `bytes_written_total`
- `modified_files_per_second`

Why it matters: File encryption commonly requires writing changed or encrypted data to many files. This gives you a direct signal of potential ransomware activity.

[How do I search for files by name? | Wisfile: AI-Powered File Renaming & Organizing Tool](https://images.openai.com/static-rsc-4/H1nOqz-OO28pLLjbWLFqdvwaYLTxl2qfpWoDj6ei28p9dTzSvfttCmY3e9FeliyyJcjR2nVWmPrlgY8ado6UdhmQaYFUoLu55lA0lTW4yEbROcosGjGK3kjo6AMUp9kzGe98pPV5c805DUVFfS13v1MuK7ibr97WH_DMSo-HWZM?purpose=inline)

Behavior 2 — Rapid file renaming and deletion

Measure whether one process renames or deletes many files in a short period.

Example features

- `file_rename_count`
- `file_delete_count`
- `unique_files_renamed`
- `rename_write_ratio`

Why it matters: Some ransomware renames encrypted files, deletes originals, or removes backups. These actions can strengthen the evidence when combined with rapid modification.

[Conti Ransomware v2 - Reverse engineering & exploit development - Romanian Security Team](https://images.openai.com/static-rsc-4/T7GO5h66aRNX7HUeJ4M_Yf1x_XkSIZwFZ4vuwC3on6BWHutW2IlhZDWNHih0K7wwgZIyaKS4SRv1RfgAP1chGdAEJwRzoTh09xJBf3KPbn2shm1LbAkKYNm283Eba5pKG5Zjhjv3tCmKeC6BemqCMcUR72W3TGGiGE9clXsBO6E?purpose=inline)

Behavior 3 — Rapid file discovery and access

Measure how many different files and directories a process touches before or during modification.

Example features

- `unique_files_accessed`
- `unique_directories_accessed`
- `file_read_count`
- `read_to_write_ratio`

Why it matters: Ransomware may enumerate folders and read files before encrypting them. However, file discovery alone is weak evidence because search tools, antivirus scanners, and backup applications also do it.

### How to combine the three

Don't build three separate ML models. Build one LightGBM classifier using features from all three behaviors, calculated over a consistent time window.

For example, the model could distinguish between:

- A backup utility that writes many files but rarely deletes or renames them.
- A document editor that modifies a few files.
- A suspicious process that rapidly reads, modifies, and renames hundreds of files.

These are hypothetical examples of patterns the model could learn, not guaranteed classifications.

I would initially leave network behavior, registry modifications, memory analysis, process injection, and API-call sequences outside your scope. They introduce additional data collection and interpretation work without being necessary for this focused file-behavior study.

## 2. Traditional security approaches and apps for each behavior

Here are the most relevant approaches for your comparison. One important caveat: not every tool that records file activity can detect ransomware by itself. Some tools only log changes; detection requires rules or additional analysis.

[Microsoft Defender for Office 365 (Plan 1)- Yearly Subscription - CFQ7TTC0LH04:0001](https://images.openai.com/static-rsc-4/HSiHnLq2O5whzMwTEZY0_c_UJTS8SoACUDVCT0WwWBVCpww9c7MyqJLJ9ZcSCKb2xAiBZrLIhox72SvcJLlSzDuY2-P7Z4YBYnAq1y1PDxPXcYhMGYrSATyEFg1KRasDzle5GzEb4qjv3JAsX3cW_wuAXPBVTrU_uAATNhZ9bSk?purpose=inline)

A. Microsoft Defender Antivirus — Controlled Folder Access

Prevention-based baseline

Best match: blocking suspicious file modifications

Controlled Folder Access allows trusted apps to modify protected folders while blocking untrusted apps from changing or deleting protected files. It is particularly relevant to ransomware protection.&#x20;

[image](https://www.google.com/s2/favicons?domain=https://learn.microsoft.com&sz=32)

Microsoft Learn

Comparison with your ML model: Your model predicts suspiciousness from file-operation patterns; Controlled Folder Access makes decisions based on trust and protected-folder policies. Both target the consequences of suspicious file modification, but they use different detection and prevention logic.

[Official documentation](https://learn.microsoft.com/en-us/defender-endpoint/controlled-folder-access-overview)

[Wazuh España: Implementación, ENS y Soporte | AI Security](https://images.openai.com/static-rsc-4/Jb67GDVRig_3x5Bp3udhLJvPL6SPaZTeiSCFrHtZ6sAJqNM2zh23qv12fQIC3AhlBmSpHJ6Zrp6lldjhBtwyBkF5G9CqdFE8eE9q1Y4suMScUcslv4cssUYtXtzFRmmcQ2_UECP166DZ1KS8RKW7uMhvSksAgLKppKi6Jpx_858?purpose=inline)

B. Wazuh — File Integrity Monitoring (FIM) and custom rules

Open-source baseline

Best match: file creation, modification, and deletion

Wazuh FIM establishes a baseline of file checksums and attributes, then alerts when monitored files change. You can add rules that look for suspicious combinations of file-change events. However, FIM alone is not a complete ransomware detector, and it does not automatically provide every per-process rate feature your model needs.&#x20;

[image](https://www.google.com/s2/favicons?domain=https://documentation.wazuh.com&sz=32)

Capabilities · Wazuh documentation

+2

Comparison with your ML model: Wazuh can detect changes to monitored files using integrity checks and configured rules; your model can classify a process using aggregated features across a time window.

[Official FIM documentation](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/)

[Sysmon | Sysmon Process Access | Logpresso Store](https://images.openai.com/static-rsc-4/hMxJhwUx0qS2WRpPoA7Rb6AjVbqnfX0pTs_R1CJGiAp79zyqvMQS4tVfYHl-miMqayTIfEh3rCNEvTZC-6WW5qIPRNMgaKn2uk8KO3JxxHisMplVDlngIZw1118Fac2_4Zf1wTKfzijeSTJMsC0L5S9R8ggb5565qGbq8VpRsqI?purpose=inline)

C. Microsoft Sysmon — Event logging for custom rule-based detection

Best match: collecting process and selected file-system events

Sysmon records system activity, including process creation and selected file events. Its events can be collected and analyzed by other tools, but Sysmon itself does not analyze events or classify ransomware. Its file event coverage is also not a complete stream of every read, write, and rename operation.&#x20;

[image](https://www.google.com/s2/favicons?domain=https://learn.microsoft.com&sz=32)

Microsoft Learn

+1

Comparison with your ML model: Sysmon can serve as a source of telemetry for a traditional rule-based detector, provided the required events are available. Your model needs a suitable data collection mechanism that captures the actual features you want to calculate.

[Official Sysmon documentation](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)

[How to Install YARA on Windows](https://images.openai.com/static-rsc-4/eYXXA3jrNHre9HhyhTczbdcYPd3rrzqYxNGYCpuKmHryryGHN3NKlkJt6Ok_edsmZ58BKAtnrKluWEEYnmvaDb5NeviR6_AqTGq7bZlLlDdg8Lo8GawYxyXo72feMywHLvVFH-OzQpo94TWSra6gM3g8f1nKkTaQZaHLe6Ae9Ho?purpose=inline)

D. YARA — Signature and pattern-based detection

Best match: identifying known suspicious file patterns

YARA matches files against rules describing textual or binary patterns. It is useful for identifying known malware artifacts, but it does not independently measure the runtime rate of file modification or rename operations. It can be integrated with Wazuh to scan files after relevant events.&#x20;

[image](https://www.google.com/s2/favicons?domain=https://documentation.wazuh.com&sz=32)

Malware detection

Comparison with your ML model: YARA looks for defined patterns in files; LightGBM learns patterns in numerical runtime-behavior features.

[Official YARA project](https://virustotal.github.io/yara/)

## 3. Which approach should you actually compare against?

My recommendation is to use two baselines, if your available time permits.

| Baseline                                    | Purpose                                                                         |
| ------------------------------------------- | ------------------------------------------------------------------------------- |
| Traditional threshold/rule-based detector   | Directly compares explicit file-activity rules with your ML classifier.         |
| Microsoft Defender Controlled Folder Access | Provides a practical example of an established ransomware prevention mechanism. |

The first is the more scientifically comparable baseline because both systems can receive the same feature data from the same test scenarios. For example, a rule-based detector might alert when a process exceeds defined file-modification and rename thresholds within a time window. Your LightGBM model would classify the same windows using learned relationships between features.

Controlled Folder Access is a useful real-world reference, but it is not an equivalent classifier: it uses a different protection mechanism and can block file changes before they complete.

If you want an open-source ecosystem for collecting and examining events, Wazuh is also worth studying, but don't assume its FIM module alone can supply all your required runtime features.

## 4. Recommended thesis scope

I would formalize the development scope as follows:

- Target threat: Ransomware that encrypts files on a Windows endpoint.
- Monitored behavior: Per-process file reads, writes/modifications, renames, and deletions.
- Feature extraction: Counts, distinct-file counts, rates, and selected ratios over fixed time windows.
- ML approach: A trained LightGBM binary classifier.
- Traditional baseline: A rule-based detector using the same extracted features.
- Evaluation: Detection rate, precision, false-positive rate, detection latency, and—if testing prevention—files affected before intervention.
- Excluded scope: Network-based detection, registry behavior, memory analysis, process injection, and a comprehensive replacement for commercial antivirus.

One technical point to settle early is how you will collect reliable per-process file events on Windows. Sysmon and Wazuh are useful for security telemetry, but neither should be assumed to provide every event your proposed features require. Verify that your chosen collection method can attribute file operations to individual processes and measure their frequency with acceptable overhead before committing to the final feature list.

This gives you a focused thesis with a clear comparison: Can a learned model identify ransomware-like file activity more effectively than explicit rules, under the same test conditions?
