# vulnscan/utils/db.py - Database For Storing Scanned Vulnerabilities

from sqlalchemy import Column, Integer, String, Text, create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

Base = declarative_base()

class Vulnerability(Base):
    __tablename__ = "vulnerabilities"
    id = Column(Integer, primary_key=True)
    target = Column(String(255), index=True)
    vulnerability_type = Column(String(100))
    endpoint = Column(Text)
    severity = Column(String(50))
    description = Column(Text)
    evidence = Column(Text)
    remediation = Column(Text)

class VulnscanDatabase:
    """Simple SQLite-backed vulnerability store."""

    def __init__(self, db_path: str = "vulnscan.db"):
        self.engine = create_engine(f"sqlite:///{db_path}", echo=False)
        Base.metadata.create_all(self.engine)
        self.Session = sessionmaker(bind=self.engine)

    def add_vulnerability(
        self,
        *,
        target: str,
        vulnerability_type: str,
        endpoint: str,
        severity: str,
        description: str,
        evidence: str,
        remediation: str
    ):
        session = self.Session()
        vuln = Vulnerability(
            target=target,
            vulnerability_type=vulnerability_type,
            endpoint=endpoint,
            severity=severity,
            description=description,
            evidence=evidence,
            remediation=remediation
        )
        session.add(vuln)
        session.commit()
        session.close()
