"""
PII Redactor Module
===================
Exportierbares Modul zur Erkennung und Maskierung personenbezogener Daten.
Unterstützt regel-basierte und NER-basierte Erkennung.

Autor: Student Project
Version: 1.0.0
"""

import re
import hashlib
import uuid
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple, Callable
from enum import Enum
import json


class PIIType(Enum):
    """Typen von personenbezogenen Daten"""
    EMAIL = "email"
    PHONE = "phone"
    NAME = "name"
    ADDRESS = "address"
    SSN = "ssn"  # Sozialversicherungsnummer
    CREDIT_CARD = "credit_card"
    IBAN = "iban"
    IP_ADDRESS = "ip_address"
    DATE_OF_BIRTH = "date_of_birth"
    ID_NUMBER = "id_number"
    CUSTOM = "custom"


@dataclass
class PIIMatch:
    """Repräsentiert einen gefundenen PII-Eintrag"""
    text: str
    pii_type: PIIType
    start: int
    end: int
    confidence: float
    method: str  # "regex" oder "ner"
    placeholder: str = ""
    original_hash: str = ""

    def to_dict(self) -> dict:
        return {
            "text": self.text,
            "pii_type": self.pii_type.value,
            "start": self.start,
            "end": self.end,
            "confidence": self.confidence,
            "method": self.method,
            "placeholder": self.placeholder,
            "original_hash": self.original_hash
        }


@dataclass
class RedactionResult:
    """Ergebnis einer Redaktion"""
    original_text: str
    redacted_text: str
    matches: List[PIIMatch]
    mapping: Dict[str, str]  # placeholder -> original (verschlüsselt)

    def to_dict(self) -> dict:
        return {
            "original_text": self.original_text,
            "redacted_text": self.redacted_text,
            "matches": [m.to_dict() for m in self.matches],
            "mapping": self.mapping,
            "pii_count": len(self.matches),
            "pii_types_found": list(set(m.pii_type.value for m in self.matches))
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)


class PIIRedactor:
    """
    Hauptklasse für PII-Erkennung und Maskierung.

    Unterstützt:
    - Regel-basierte Erkennung (Regex)
    - NER-basierte Erkennung (spaCy/Transformers)
    - Hybride Erkennung
    """

    # Standard Regex-Patterns für PII-Erkennung
    # Jedes Pattern ist dokumentiert für bessere Verständlichkeit
    DEFAULT_PATTERNS = {
        PIIType.EMAIL: {
            # Erkennt E-Mail-Adressen: user@domain.tld
            # [a-zA-Z0-9._%+-]+ = lokaler Teil (Buchstaben, Zahlen, Sonderzeichen)
            # @ = At-Zeichen
            # [a-zA-Z0-9.-]+ = Domain
            # \.[a-zA-Z]{2,} = TLD (min. 2 Buchstaben)
            "pattern": r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b',
            "confidence": 0.95
        },
        PIIType.PHONE: {
            # Deutsche Telefonnummern in verschiedenen Formaten
            # Optionales + am Anfang
            # Optionale Ländervorwahl (49)
            # Verschiedene Trennzeichen erlaubt: Leerzeichen, Bindestrich, Slash
            "pattern": r'\b(?:\+?49[-.\s]?)?(?:\(?\d{2,5}\)?[-.\s]?)?\d{3,}[-.\s]?\d{2,}\b',
            "confidence": 0.85
        },
        PIIType.IBAN: {
            # IBAN: 2 Buchstaben Ländercode + 2 Prüfziffern + bis zu 30 alphanumerische Zeichen
            # Erlaubt Leerzeichen zwischen 4er-Gruppen
            "pattern": r'\b[A-Z]{2}\d{2}(?:\s?\d{4}){4,7}\d{0,2}\b',
            "confidence": 0.95
        },
        PIIType.CREDIT_CARD: {
            # Kreditkartennummern: 13-19 Ziffern, optional mit Leerzeichen/Bindestrichen
            # Typische Formate: 4 x 4 Ziffern oder durchgehend
            "pattern": r'\b(?:\d{4}[-\s]?){3,4}\d{1,4}\b',
            "confidence": 0.80
        },
        PIIType.SSN: {
            # Deutsche Sozialversicherungsnummer: 12 Zeichen
            # 2 Ziffern + 6 Ziffern (Geburtsdatum) + 1 Buchstabe + 3 Ziffern
            "pattern": r'\b\d{2}\s?\d{6}\s?[A-Z]\s?\d{3}\b',
            "confidence": 0.90
        },
        PIIType.IP_ADDRESS: {
            # IPv4-Adressen: 4 Oktette (0-255) getrennt durch Punkte
            "pattern": r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b',
            "confidence": 0.95
        },
        PIIType.DATE_OF_BIRTH: {
            # Geburtsdaten in deutschen Formaten: DD.MM.YYYY oder DD/MM/YYYY
            # Tag: 01-31, Monat: 01-12, Jahr: 19xx oder 20xx
            "pattern": r'\b(?:0[1-9]|[12][0-9]|3[01])[./](?:0[1-9]|1[0-2])[./](?:19|20)\d{2}\b',
            "confidence": 0.85
        },
        PIIType.ID_NUMBER: {
            # Deutsche Personalausweisnummer/Reisepass: Spezifisches Format
            # Beginnt mit Buchstabe, gefolgt von alphanumerischen Zeichen
            # Beispiel: L0001234X oder C01X00001
            # Vermeidet False Positives bei normalen Wörtern wie "Bestellung"
            "pattern": r'\b[A-Z][A-Z0-9]{2}\d{5,7}[A-Z0-9]?\b',
            "confidence": 0.70
        }
    }

    def __init__(
        self,
        use_ner: bool = False,
        ner_model: str = "de_core_news_lg",
        custom_patterns: Optional[Dict[PIIType, dict]] = None,
        placeholder_format: str = "[{type}_{id}]",
        hash_originals: bool = True
    ):
        """
        Initialisiert den PIIRedactor.

        Args:
            use_ner: Ob NER-basierte Erkennung verwendet werden soll
            ner_model: spaCy-Modell für NER
            custom_patterns: Zusätzliche/überschreibende Regex-Patterns
            placeholder_format: Format für Platzhalter, z.B. "[EMAIL_1]"
            hash_originals: Ob Originale gehasht gespeichert werden sollen
        """
        self.use_ner = use_ner
        self.ner_model_name = ner_model
        self.placeholder_format = placeholder_format
        self.hash_originals = hash_originals
        self.nlp = None

        # Patterns zusammenführen
        self.patterns = self.DEFAULT_PATTERNS.copy()
        if custom_patterns:
            self.patterns.update(custom_patterns)

        # Kompilierte Regex-Patterns für Performance
        self._compiled_patterns = {
            pii_type: re.compile(info["pattern"], re.IGNORECASE if pii_type != PIIType.IBAN else 0)
            for pii_type, info in self.patterns.items()
        }

        # NER laden wenn gewünscht
        if use_ner:
            self._load_ner_model()

    def _load_ner_model(self):
        """Lädt das spaCy NER-Modell"""
        try:
            import spacy
            self.nlp = spacy.load(self.ner_model_name)
            print(f"NER-Modell '{self.ner_model_name}' erfolgreich geladen.")
        except OSError:
            print(f"Modell '{self.ner_model_name}' nicht gefunden. Lade herunter...")
            import spacy.cli
            spacy.cli.download(self.ner_model_name)
            import spacy
            self.nlp = spacy.load(self.ner_model_name)

    def _hash_text(self, text: str) -> str:
        """Erstellt einen SHA-256 Hash des Textes"""
        return hashlib.sha256(text.encode()).hexdigest()[:16]

    def _generate_placeholder(self, pii_type: PIIType, index: int) -> str:
        """Generiert einen Platzhalter für maskierten Text"""
        return self.placeholder_format.format(
            type=pii_type.value.upper(),
            id=index
        )

    def detect_regex(self, text: str) -> List[PIIMatch]:
        """
        Erkennt PII mittels Regex-Patterns.

        Args:
            text: Zu analysierender Text

        Returns:
            Liste von PIIMatch-Objekten
        """
        matches = []

        for pii_type, pattern in self._compiled_patterns.items():
            for match in pattern.finditer(text):
                pii_match = PIIMatch(
                    text=match.group(),
                    pii_type=pii_type,
                    start=match.start(),
                    end=match.end(),
                    confidence=self.patterns[pii_type]["confidence"],
                    method="regex"
                )
                matches.append(pii_match)

        return matches

    def detect_ner(self, text: str) -> List[PIIMatch]:
        """
        Erkennt PII mittels Named Entity Recognition.

        Args:
            text: Zu analysierender Text

        Returns:
            Liste von PIIMatch-Objekten
        """
        if not self.nlp:
            raise ValueError("NER-Modell nicht geladen. Initialisiere mit use_ner=True")

        matches = []
        doc = self.nlp(text)

        # Mapping von spaCy Entity-Labels zu PIITypes
        label_mapping = {
            "PER": PIIType.NAME,
            "PERSON": PIIType.NAME,
            "LOC": PIIType.ADDRESS,
            "GPE": PIIType.ADDRESS,
            "ORG": PIIType.NAME,  # Organisationen können auch sensibel sein
        }

        for ent in doc.ents:
            if ent.label_ in label_mapping:
                pii_match = PIIMatch(
                    text=ent.text,
                    pii_type=label_mapping[ent.label_],
                    start=ent.start_char,
                    end=ent.end_char,
                    confidence=0.85,  # NER hat typischerweise ~85% Genauigkeit
                    method="ner"
                )
                matches.append(pii_match)

        return matches

    def detect(self, text: str, method: str = "hybrid") -> List[PIIMatch]:
        """
        Erkennt PII mit der gewählten Methode.

        Args:
            text: Zu analysierender Text
            method: "regex", "ner", oder "hybrid"

        Returns:
            Liste von PIIMatch-Objekten (dedupliziert)
        """
        matches = []

        if method in ["regex", "hybrid"]:
            matches.extend(self.detect_regex(text))

        if method in ["ner", "hybrid"] and self.use_ner:
            matches.extend(self.detect_ner(text))

        # Deduplizierung: Überlappende Matches zusammenführen
        matches = self._deduplicate_matches(matches)

        # Nach Position sortieren
        matches.sort(key=lambda x: x.start)

        return matches

    def _deduplicate_matches(self, matches: List[PIIMatch]) -> List[PIIMatch]:
        """Entfernt überlappende Matches, behält den mit höherer Confidence"""
        if not matches:
            return []

        # Nach Start-Position und Confidence sortieren
        sorted_matches = sorted(matches, key=lambda x: (x.start, -x.confidence))

        deduplicated = [sorted_matches[0]]

        for match in sorted_matches[1:]:
            last = deduplicated[-1]
            # Wenn keine Überlappung, hinzufügen
            if match.start >= last.end:
                deduplicated.append(match)
            # Bei Überlappung: nur hinzufügen wenn höhere Confidence
            elif match.confidence > last.confidence:
                deduplicated[-1] = match

        return deduplicated

    def redact(
        self,
        text: str,
        method: str = "hybrid",
        pii_types: Optional[List[PIIType]] = None
    ) -> RedactionResult:
        """
        Maskiert PII im Text.

        Args:
            text: Zu maskierender Text
            method: Erkennungsmethode ("regex", "ner", "hybrid")
            pii_types: Optional - nur bestimmte PII-Typen maskieren

        Returns:
            RedactionResult mit maskiertem Text und Mapping
        """
        matches = self.detect(text, method)

        # Optional: Nur bestimmte Typen filtern
        if pii_types:
            matches = [m for m in matches if m.pii_type in pii_types]

        # Platzhalter generieren und Text ersetzen
        mapping = {}
        redacted_text = text
        offset = 0

        # Zähler pro Typ für eindeutige IDs
        type_counters = {t: 0 for t in PIIType}

        for match in matches:
            type_counters[match.pii_type] += 1
            placeholder = self._generate_placeholder(
                match.pii_type,
                type_counters[match.pii_type]
            )

            match.placeholder = placeholder

            # Hash des Originals speichern
            if self.hash_originals:
                match.original_hash = self._hash_text(match.text)
                mapping[placeholder] = match.original_hash
            else:
                mapping[placeholder] = match.text

            # Text ersetzen (mit Offset-Korrektur)
            start = match.start + offset
            end = match.end + offset
            redacted_text = redacted_text[:start] + placeholder + redacted_text[end:]

            # Offset aktualisieren
            offset += len(placeholder) - (match.end - match.start)

        return RedactionResult(
            original_text=text,
            redacted_text=redacted_text,
            matches=matches,
            mapping=mapping
        )

    def batch_redact(
        self,
        texts: List[str],
        method: str = "hybrid",
        pii_types: Optional[List[PIIType]] = None
    ) -> List[RedactionResult]:
        """
        Maskiert PII in mehreren Texten.

        Args:
            texts: Liste von Texten
            method: Erkennungsmethode
            pii_types: Optional - nur bestimmte PII-Typen

        Returns:
            Liste von RedactionResults
        """
        return [self.redact(text, method, pii_types) for text in texts]

    def get_statistics(self, results: List[RedactionResult]) -> dict:
        """
        Berechnet Statistiken über gefundene PIIs.

        Args:
            results: Liste von RedactionResults

        Returns:
            Dictionary mit Statistiken
        """
        total_matches = sum(len(r.matches) for r in results)

        type_counts = {}
        method_counts = {"regex": 0, "ner": 0}
        confidence_sum = 0

        for result in results:
            for match in result.matches:
                type_name = match.pii_type.value
                type_counts[type_name] = type_counts.get(type_name, 0) + 1
                method_counts[match.method] += 1
                confidence_sum += match.confidence

        return {
            "total_documents": len(results),
            "total_pii_found": total_matches,
            "pii_per_document": total_matches / len(results) if results else 0,
            "pii_by_type": type_counts,
            "pii_by_method": method_counts,
            "average_confidence": confidence_sum / total_matches if total_matches else 0
        }


# Für direkten Import
def create_redactor(**kwargs) -> PIIRedactor:
    """Factory-Funktion für einfache Erstellung"""
    return PIIRedactor(**kwargs)
