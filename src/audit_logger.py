"""
Audit Logger Module
===================
Modul für Audit-Logging und Zugriffskontrolle bei PII-Demaskierung.

Autor: Student Project
Version: 1.0.0
"""

import json
import hashlib
from datetime import datetime
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
from enum import Enum
from pathlib import Path
import uuid


class AccessLevel(Enum):
    """Zugriffsebenen für PII-Daten"""
    PUBLIC = 0        # Keine PII-Zugriff
    INTERNAL = 1      # Basis-PII (Namen, E-Mails)
    CONFIDENTIAL = 2  # Erweiterte PII (Adressen, Telefon)
    RESTRICTED = 3    # Sensible PII (SSN, Kreditkarten)
    ADMIN = 4         # Vollzugriff auf alle PII


@dataclass
class User:
    """Repräsentiert einen Benutzer mit Zugriffsrechten"""
    user_id: str
    username: str
    access_level: AccessLevel
    department: str = ""
    roles: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "user_id": self.user_id,
            "username": self.username,
            "access_level": self.access_level.name,
            "department": self.department,
            "roles": self.roles
        }


@dataclass
class AuditEntry:
    """Ein einzelner Audit-Log-Eintrag"""
    entry_id: str
    timestamp: str
    user: User
    action: str
    pii_type: str
    placeholder: str
    original_hash: str
    success: bool
    reason: str = ""
    ip_address: str = ""
    session_id: str = ""
    additional_data: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "entry_id": self.entry_id,
            "timestamp": self.timestamp,
            "user": self.user.to_dict(),
            "action": self.action,
            "pii_type": self.pii_type,
            "placeholder": self.placeholder,
            "original_hash": self.original_hash,
            "success": self.success,
            "reason": self.reason,
            "ip_address": self.ip_address,
            "session_id": self.session_id,
            "additional_data": self.additional_data
        }


class AuditLogger:
    """
    Audit-Logger für PII-Zugriffe.

    Verwaltet:
    - Zugriffskontrolle basierend auf Benutzerrollen
    - Audit-Trail für alle PII-Zugriffe
    - Export-Funktionalität für Compliance
    """

    # Welche PII-Typen benötigen welches Access Level
    PII_ACCESS_REQUIREMENTS = {
        "email": AccessLevel.INTERNAL,
        "name": AccessLevel.INTERNAL,
        "phone": AccessLevel.CONFIDENTIAL,
        "address": AccessLevel.CONFIDENTIAL,
        "date_of_birth": AccessLevel.CONFIDENTIAL,
        "ip_address": AccessLevel.CONFIDENTIAL,
        "ssn": AccessLevel.RESTRICTED,
        "credit_card": AccessLevel.RESTRICTED,
        "iban": AccessLevel.RESTRICTED,
        "id_number": AccessLevel.RESTRICTED,
    }

    def __init__(
        self,
        log_file: Optional[str] = None,
        require_reason: bool = True,
        max_entries_memory: int = 10000
    ):
        """
        Initialisiert den Audit-Logger.

        Args:
            log_file: Pfad zur Log-Datei (optional)
            require_reason: Ob eine Begründung für Zugriffe erforderlich ist
            max_entries_memory: Maximale Anzahl Einträge im Speicher
        """
        self.log_file = log_file
        self.require_reason = require_reason
        self.max_entries_memory = max_entries_memory
        self.entries: List[AuditEntry] = []
        self._pii_store: Dict[str, str] = {}  # placeholder -> original (encrypted)

    def register_pii(self, placeholder: str, original: str, pii_type: str) -> str:
        """
        Registriert einen PII-Wert für spätere Demaskierung.

        Args:
            placeholder: Der Platzhalter-Text
            original: Der originale PII-Wert
            pii_type: Typ der PII

        Returns:
            Hash des registrierten Wertes
        """
        # In Produktion würde hier Verschlüsselung verwendet
        entry_hash = hashlib.sha256(original.encode()).hexdigest()[:16]
        self._pii_store[placeholder] = {
            "original": original,
            "type": pii_type,
            "hash": entry_hash,
            "registered_at": datetime.now().isoformat()
        }
        return entry_hash

    def check_access(self, user: User, pii_type: str) -> tuple[bool, str]:
        """
        Prüft ob ein Benutzer Zugriff auf einen PII-Typ hat.

        Args:
            user: Der anfragende Benutzer
            pii_type: Typ der angeforderten PII

        Returns:
            Tuple (erlaubt: bool, grund: str)
        """
        required_level = self.PII_ACCESS_REQUIREMENTS.get(
            pii_type.lower(),
            AccessLevel.RESTRICTED
        )

        if user.access_level.value >= required_level.value:
            return True, f"Zugriff erlaubt: {user.access_level.name} >= {required_level.name}"

        return False, f"Zugriff verweigert: {user.access_level.name} < {required_level.name}"

    def demask(
        self,
        placeholder: str,
        user: User,
        reason: str = "",
        ip_address: str = "",
        session_id: str = ""
    ) -> tuple[Optional[str], AuditEntry]:
        """
        Demaskiert einen PII-Wert mit Audit-Logging.

        Args:
            placeholder: Der Platzhalter
            user: Der anfragende Benutzer
            reason: Begründung für den Zugriff
            ip_address: IP-Adresse des Anfragenden
            session_id: Session-ID

        Returns:
            Tuple (demaskierter Wert oder None, AuditEntry)
        """
        # Prüfen ob Begründung erforderlich
        if self.require_reason and not reason:
            entry = self._create_entry(
                user=user,
                action="DEMASK_ATTEMPT",
                pii_type="unknown",
                placeholder=placeholder,
                original_hash="",
                success=False,
                reason="Begründung erforderlich aber nicht angegeben",
                ip_address=ip_address,
                session_id=session_id
            )
            return None, entry

        # Prüfen ob Placeholder existiert
        if placeholder not in self._pii_store:
            entry = self._create_entry(
                user=user,
                action="DEMASK_ATTEMPT",
                pii_type="unknown",
                placeholder=placeholder,
                original_hash="",
                success=False,
                reason="Placeholder nicht gefunden",
                ip_address=ip_address,
                session_id=session_id
            )
            return None, entry

        pii_data = self._pii_store[placeholder]
        pii_type = pii_data["type"]

        # Zugriffsrecht prüfen
        allowed, access_reason = self.check_access(user, pii_type)

        if not allowed:
            entry = self._create_entry(
                user=user,
                action="DEMASK_DENIED",
                pii_type=pii_type,
                placeholder=placeholder,
                original_hash=pii_data["hash"],
                success=False,
                reason=f"{access_reason}. Angefragte Begründung: {reason}",
                ip_address=ip_address,
                session_id=session_id
            )
            return None, entry

        # Zugriff erlaubt - demaskieren
        entry = self._create_entry(
            user=user,
            action="DEMASK_SUCCESS",
            pii_type=pii_type,
            placeholder=placeholder,
            original_hash=pii_data["hash"],
            success=True,
            reason=reason,
            ip_address=ip_address,
            session_id=session_id
        )

        return pii_data["original"], entry

    def batch_demask(
        self,
        text: str,
        user: User,
        reason: str = "",
        ip_address: str = "",
        session_id: str = ""
    ) -> tuple[str, List[AuditEntry]]:
        """
        Demaskiert alle PIIs in einem Text.

        Args:
            text: Text mit Platzhaltern
            user: Der anfragende Benutzer
            reason: Begründung
            ip_address: IP-Adresse
            session_id: Session-ID

        Returns:
            Tuple (demaskierter Text, Liste von AuditEntries)
        """
        entries = []
        result_text = text

        for placeholder in self._pii_store.keys():
            if placeholder in result_text:
                original, entry = self.demask(
                    placeholder, user, reason, ip_address, session_id
                )
                entries.append(entry)

                if original:
                    result_text = result_text.replace(placeholder, original)

        return result_text, entries

    def _create_entry(
        self,
        user: User,
        action: str,
        pii_type: str,
        placeholder: str,
        original_hash: str,
        success: bool,
        reason: str,
        ip_address: str,
        session_id: str
    ) -> AuditEntry:
        """Erstellt einen neuen Audit-Eintrag"""
        entry = AuditEntry(
            entry_id=str(uuid.uuid4()),
            timestamp=datetime.now().isoformat(),
            user=user,
            action=action,
            pii_type=pii_type,
            placeholder=placeholder,
            original_hash=original_hash,
            success=success,
            reason=reason,
            ip_address=ip_address,
            session_id=session_id
        )

        self.entries.append(entry)

        # Optional: In Datei schreiben
        if self.log_file:
            self._write_to_file(entry)

        # Speicher begrenzen
        if len(self.entries) > self.max_entries_memory:
            self.entries = self.entries[-self.max_entries_memory:]

        return entry

    def _write_to_file(self, entry: AuditEntry):
        """Schreibt einen Eintrag in die Log-Datei"""
        with open(self.log_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry.to_dict(), ensure_ascii=False) + "\n")

    def export_json(self, filepath: Optional[str] = None) -> str:
        """
        Exportiert das Audit-Log als JSON.

        Args:
            filepath: Optional - Pfad zum Speichern

        Returns:
            JSON-String des Logs
        """
        export_data = {
            "export_timestamp": datetime.now().isoformat(),
            "total_entries": len(self.entries),
            "entries": [e.to_dict() for e in self.entries],
            "summary": self.get_summary()
        }

        json_str = json.dumps(export_data, indent=2, ensure_ascii=False)

        if filepath:
            Path(filepath).write_text(json_str, encoding="utf-8")

        return json_str

    def get_summary(self) -> dict:
        """Erstellt eine Zusammenfassung des Audit-Logs"""
        if not self.entries:
            return {"message": "Keine Einträge vorhanden"}

        success_count = sum(1 for e in self.entries if e.success)
        denied_count = sum(1 for e in self.entries if not e.success)

        users = {}
        pii_types = {}
        actions = {}

        for entry in self.entries:
            # User-Statistik
            uid = entry.user.user_id
            users[uid] = users.get(uid, 0) + 1

            # PII-Typ-Statistik
            pii_types[entry.pii_type] = pii_types.get(entry.pii_type, 0) + 1

            # Aktions-Statistik
            actions[entry.action] = actions.get(entry.action, 0) + 1

        return {
            "total_entries": len(self.entries),
            "successful_accesses": success_count,
            "denied_accesses": denied_count,
            "unique_users": len(users),
            "accesses_by_user": users,
            "accesses_by_pii_type": pii_types,
            "accesses_by_action": actions,
            "first_entry": self.entries[0].timestamp if self.entries else None,
            "last_entry": self.entries[-1].timestamp if self.entries else None
        }

    def get_user_history(self, user_id: str) -> List[AuditEntry]:
        """Gibt alle Einträge für einen Benutzer zurück"""
        return [e for e in self.entries if e.user.user_id == user_id]

    def get_entries_by_pii_type(self, pii_type: str) -> List[AuditEntry]:
        """Gibt alle Einträge für einen PII-Typ zurück"""
        return [e for e in self.entries if e.pii_type == pii_type]

    def clear_log(self):
        """Löscht alle Einträge (mit Warnung)"""
        print(f"WARNUNG: {len(self.entries)} Audit-Einträge werden gelöscht!")
        self.entries = []


def create_test_users() -> Dict[str, User]:
    """Erstellt Test-Benutzer für Demos"""
    return {
        "public": User(
            user_id="u001",
            username="guest_user",
            access_level=AccessLevel.PUBLIC,
            department="External",
            roles=["viewer"]
        ),
        "internal": User(
            user_id="u002",
            username="employee_standard",
            access_level=AccessLevel.INTERNAL,
            department="Marketing",
            roles=["employee", "data_viewer"]
        ),
        "confidential": User(
            user_id="u003",
            username="hr_manager",
            access_level=AccessLevel.CONFIDENTIAL,
            department="Human Resources",
            roles=["manager", "hr_staff"]
        ),
        "restricted": User(
            user_id="u004",
            username="data_protection_officer",
            access_level=AccessLevel.RESTRICTED,
            department="Compliance",
            roles=["dpo", "auditor"]
        ),
        "admin": User(
            user_id="u005",
            username="system_admin",
            access_level=AccessLevel.ADMIN,
            department="IT",
            roles=["admin", "superuser"]
        )
    }
