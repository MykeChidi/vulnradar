# vulnradar/utils/db.py - Database For Storing Scanned Vulnerabilities

from sqlalchemy import Column, Integer, String, Text, create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import QueuePool
from typing import Any
from .logger import setup_logger
from .error_handler import get_global_error_handler, handle_errors, DatabaseError


logger = setup_logger("Database", log_to_file=False)
error_handler = get_global_error_handler()
Base: Any = declarative_base()

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

class VulnradarDatabase:
    """Simple SQLite-backed vulnerability store."""

    def __init__(self, db_path: str = "vulnradar.db", pool_size: int = 5):
        self.engine = create_engine(
            f"sqlite:///{db_path}", 
            echo=False,
            poolclass=QueuePool,
            pool_size=pool_size,
            max_overflow=10,
            pool_pre_ping=True,  # Verify connections
            pool_recycle=3600 )
        Base.metadata.create_all(self.engine)
        self.Session = sessionmaker(bind=self.engine)

    def __del__(self):
        """Cleanup on deletion"""
        if hasattr(self, 'engine'):
            self.engine.dispose()

    @handle_errors(
        error_handler=error_handler,
        user_message="Failed to store vulnerability in database",
        return_on_error=None
    )
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
        if not all(isinstance(v, str) for v in [target, vulnerability_type, endpoint, 
                                             severity, description, evidence, remediation]):
            raise ValueError("All parameters must be strings")
    
        if len(target) > 255 or len(vulnerability_type) > 100:
            raise ValueError("Input exceeds maximum length")
        
        if severity not in ['Critical', 'High', 'Medium', 'Low', 'Info']:
            raise ValueError(f"Invalid severity: {severity}")
        
        session = self.Session()
        try:
            vuln = Vulnerability(
                target=target[:255], 
                vulnerability_type=vulnerability_type[:100],
                endpoint=endpoint[:2048], 
                severity=severity,
                description=description[:4096],
                evidence=evidence[:8192],
                remediation=remediation[:8192]
            )
            session.add(vuln)
            session.commit()
        except Exception as e:
            session.rollback()
            error_handler.handle_error(
                DatabaseError(f"Failed to store vulnerability: {str(e)}", original_error=e),
                context={"target": target, "vulnerability_type": vulnerability_type, "endpoint": endpoint}
            )
            raise
        finally:
            session.close()

