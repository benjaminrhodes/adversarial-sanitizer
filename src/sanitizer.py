"""Adversarial input sanitizer for ML models."""

from dataclasses import dataclass, field
from typing import List


DEFAULT_PATTERNS = {
    "prompt_injection": [
        r"(?i)ignore\s+(all\s+)?(previous\s+)?instructions",
        r"(?i)ignore\s+(all\s+)?(system\s+)?prompt",
        r"(?i)disregard\s+(all\s+)?instructions",
        r"(?i)forget\s+(all\s+)?(your\s+)?instructions",
        r"(?i)new\s+instructions",
        r"(?i)override\s+(your\s+)?instructions",
        r"(?i)instead\s+of\s+(your\s+)?instructions",
        r"(?i)forget\s+everything",
        r"(?i)you\s+are\s+(now\s+)?(a\s+)?different",
    ],
    "sql_injection": [
        r"('\s*(?:or|and)\s*['\"]?\d|--)",
        r"(?i)\bunion\s+(all\s+)?select\b",
        r"(?i)\bdrop\s+(table|database)\b",
        r"(?i)\binsert\s+into\b",
        r"(?i)\bdelete\s+from\b",
        r"(?i)\bupdate\s+\w+\s+set\b",
        r"'\s*or\s*['\"]?1['\"]?\s*=\s*['\"]?1['\"]?",
        r"'\s*or\s*1\s*=\s*1",
        r"'\s*or\s*'1'\s*=\s*'1",
        r"(?i)'\s*or\s*",
        r"'\s*--",
        r";\s*drop\b",
    ],
    "xss": [
        r"<script[^>]*>.*?</script>",
        r"javascript\s*:",
        r"on\w+\s*=",
        r"<iframe[^>]*>.*?</iframe>",
        r"<object[^>]*>.*?</object>",
        r"<embed[^>]*>",
        r"<\?xml[^>]*>",
        r"data\s*:\s*text/html",
    ],
}


@dataclass
class DetectionResult:
    """Result of adversarial detection."""

    is_adversarial: bool
    detected_patterns: List[str] = field(default_factory=list)
    sanitized: str = ""
    was_sanitized: bool = False


class Sanitizer:
    """Sanitizer for detecting and removing adversarial inputs."""

    def __init__(self, patterns: List[str] = None):
        """Initialize sanitizer.

        Args:
            patterns: Additional custom patterns to detect.
        """
        self.patterns = DEFAULT_PATTERNS.copy()
        if patterns:
            self.patterns["custom"] = patterns

    def detect(self, text: str) -> DetectionResult:
        """Detect adversarial patterns in text.

        Args:
            text: Input text to analyze.

        Returns:
            DetectionResult with detection info.
        """
        if not text:
            return DetectionResult(is_adversarial=False, detected_patterns=[])

        detected = []
        for category, pattern_list in self.patterns.items():
            for pattern in pattern_list:
                import re

                if re.search(pattern, text):
                    detected.append(f"{category}:{pattern}")

        return DetectionResult(
            is_adversarial=len(detected) > 0,
            detected_patterns=detected,
        )

    def sanitize(self, text: str) -> DetectionResult:
        """Sanitize input by removing adversarial patterns.

        Args:
            text: Input text to sanitize.

        Returns:
            DetectionResult with sanitized text.
        """
        if not text:
            return DetectionResult(
                is_adversarial=False,
                detected_patterns=[],
                sanitized=text,
            )

        detection = self.detect(text)
        sanitized_text = text

        if detection.is_adversarial:
            for category, pattern_list in self.patterns.items():
                for pattern in pattern_list:
                    import re

                    sanitized_text = re.sub(pattern, "", sanitized_text, flags=re.IGNORECASE)
            sanitized_text = " ".join(sanitized_text.split())

        return DetectionResult(
            is_adversarial=detection.is_adversarial,
            detected_patterns=detection.detected_patterns,
            sanitized=sanitized_text,
            was_sanitized=detection.is_adversarial,
        )
