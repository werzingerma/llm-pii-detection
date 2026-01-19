# PII Detection & Masking in LLMs

Projekt zur Erkennung und Maskierung personenbezogener Daten (PII) bei der Verwendung von Large Language Models.

## Projektstruktur

```
pii-detection-llm/
├── docs/
│   ├── LLM_PII_Presentation.pdf          # Präsentation
│   └── Seminararbeit_...pdf              # Seminararbeit
├── notebooks/
│   ├── 01_redaction_pii_script.ipynb     # Einführung & PII-Redaktion
│   ├── 02_bronze_recognition_masking.ipynb    # Regex vs. NER Vergleich
│   ├── 03_silver_analyse_fp_fn_with_examples.ipynb  # FP/FN Analyse
│   └── 04_gold_selective_demasking_with_audit_log.ipynb  # Demaskierung & Audit
├── src/
│   ├── __init__.py
│   ├── pii_redactor.py                   # Exportierbares PII-Redaktion-Modul
│   └── audit_logger.py                   # Audit-Logging & Zugriffskontrolle
├── exports/                              # Generierte Exports (JSON)
├── models/                               # Lokale LLM-Modelle (gitignored)
└── requirements.txt
```

## Installation

```bash
# Virtual Environment erstellen
python -m venv venv
source venv/bin/activate  # Linux/Mac
# oder: venv\Scripts\activate  # Windows

# Dependencies installieren
pip install -r requirements.txt

# SpaCy Modell herunterladen
python -m spacy download de_core_news_lg
```

## Notebooks

| # | Notebook | Inhalt |
|---|----------|--------|
| 1 | 01_redaction_pii_script | Einführung in PII-Problematik, Grundlagen der Maskierung, RAG-Beispiel |
| 2 | 02_bronze_recognition_masking | Vergleich Regex vs. NER, Performance-Analyse |
| 3 | 03_silver_analyse_fp_fn | False Positives/Negatives, Edge-Cases, Synthetischer Datensatz |
| 4 | 04_gold_selective_demasking | RBAC, Audit-Logging, DSGVO-Compliance |

## Verwendung des Moduls

```python
from src.pii_redactor import PIIRedactor
from src.audit_logger import AuditLogger, User, AccessLevel

# PII maskieren
redactor = PIIRedactor(use_ner=True)
result = redactor.redact("Kontakt: max@email.de, Tel: 0170-123456")
print(result.redacted_text)  # Kontakt: [EMAIL_1], Tel: [PHONE_1]

# Audit-Logging
logger = AuditLogger(require_reason=True)
user = User("u001", "admin", AccessLevel.ADMIN, "IT")
original, entry = logger.demask("[EMAIL_1]", user, reason="Audit-Anfrage")
```

## LLM-Integration

Das Projekt unterstützt lokale quantisierte Modelle (GGUF-Format):

```python
# Pfad zum Modell anpassen
MODEL_PATH = "models/llama-3.2-3b-q4km/llama-3.2-3b-instruct-q4_k_m.gguf"
```

## Dokumentation

- **Seminararbeit**: [docs/Seminararbeit_Personenbezogene_Daten_in_Large_Language_Models.pdf](docs/Seminararbeit_Personenbezogene_Daten_in_Large_Language_Models.pdf)
- **Präsentation**: [docs/LLM_PII_Presentation.pdf](docs/LLM_PII_Presentation.pdf)
