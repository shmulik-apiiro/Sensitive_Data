"""
Alert Context Gatherer Module - Comprehensive Timeline-Based Correlation

This module implements a comprehensive timeline-based correlation system that:
1. Reviews ALL monitored Slack channels for context
2. Resolves namespace IDs to customer names (using alert label patterns)
3. Maps ALL events (alerts, deployments, feature flags, builds) into a unified timeline
4. Categorizes events by type and relevance
5. Presents structured data for Claude to analyze and decide on correlations

Correlation Pipeline:
1. Gather all messages from all monitored channels (lookback window)
2. Parse each message: extract customer, namespace, event type
3. Resolve namespace → customer mapping from label patterns
4. Build unified timeline with all events sorted chronologically
5. Group events by customer (same customer vs. other customers)
6. Identify potential correlations (same time window, same alert type, cluster patterns)
7. Present to Claude with relevance scoring guidance

Channels monitored:
- #critical-alerts-devops (C05GN4V2P9Q): Critical infrastructure alerts, build failures
- #urgent-severity-alerts (C06745ME1PG): Urgent production alerts  
- #audit-account-service (C025NT4L5UK): Account service audit events
- #high-severity-alerts (C067CV07KQ8): High severity production alerts
- #Production (C066M2C91QV): Production environment alerts
- #environment-expiration (C02MADV4406): Environment expiration notifications
"""

import os
import re
import logging
from datetime import datetime, timedelta, timezone
from typing import Dict, Any, List, Optional, Tuple, Set
from dataclasses import dataclass, field
from collections import defaultdict
from enum import Enum

logger = logging.getLogger(__name__)


class EventType(Enum):
    """Types of events that can be correlated."""
    ALERT = "alert"
    DEPLOYMENT = "deployment"
    BUILD_FAILURE = "build_failure"
    BUILD_SUCCESS = "build_success"
    BUILD_TIMEOUT = "build_timeout"
    FEATURE_FLAG = "feature_flag"
    ENVIRONMENT_EXPIRATION = "environment_expiration"
    HUMAN_RESPONSE = "human_response"
    OTHER = "other"


@dataclass
class TimelineEvent:
    """A single event in the unified timeline."""
    timestamp: datetime
    event_type: EventType
    customer: str  # Resolved customer name
    namespace: str  # Raw namespace ID if available
    title: str
    message: str
    channel_id: str
    channel_name: str
    link: str
    labels: Dict[str, Any] = field(default_factory=dict)
    relevance_score: float = 0.0  # Calculated later based on correlation rules
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'event_type': self.event_type.value,
            'customer': self.customer,
            'namespace': self.namespace,
            'title': self.title,
            'message': self.message[:300] if self.message else '',
            'channel': self.channel_name,
            'link': self.link,
            'labels': self.labels,
            'relevance_score': self.relevance_score
        }


@dataclass
class ChannelAlerts:
    """Raw alerts from a single channel."""
    channel_id: str
    channel_name: str
    alerts: List[Dict[str, Any]] = field(default_factory=list)
    other_messages: List[Dict[str, Any]] = field(default_factory=list)  # Non-alert messages (deployments, etc.)


@dataclass
class TimelineWindow:
    """A time window containing correlated events."""
    window_name: str  # e.g., "immediate" (±30 min), "recent" (±2 hours), "historical" (7 days)
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    same_customer_alerts: List[Dict[str, Any]] = field(default_factory=list)
    other_customer_alerts: List[Dict[str, Any]] = field(default_factory=list)
    deployments: List[Dict[str, Any]] = field(default_factory=list)
    feature_flags: List[Dict[str, Any]] = field(default_factory=list)
    build_events: List[Dict[str, Any]] = field(default_factory=list)


class NamespaceCustomerResolver:
    """
    Resolves namespace IDs to customer names.
    
    Uses multiple strategies:
    1. Direct label extraction (Customer, deployment_cluster)
    2. GKE Index lookup (from lim-gitops gke-index.json)
    3. Cached mappings from previously seen alerts
    4. Pattern matching from known namespace formats
    """
    
    # Default paths to gke-index.json (checked in order)
    GKE_INDEX_PATHS = [
        # GitHub Actions - cloned lim-gitops repo
        'lim-gitops/registry/gke-index.json',
        # Local development - sibling repo
        '../lim-gitops/registry/gke-index.json',
        # Absolute path from environment variable
        None,  # Will be populated from GKE_INDEX_PATH env var
    ]
    
    def __init__(self, verbose: bool = False, gke_index_path: Optional[str] = None):
        # Cache of namespace -> customer mappings learned from alerts
        self._namespace_cache: Dict[str, str] = {}
        self._verbose = verbose
        
        # GKE Index: namespace_id -> customer_name mappings from gke-index.json
        self._gke_index: Dict[str, str] = {}
        
        # Known namespace patterns (can be extended)
        self._known_patterns = {
            # Add known patterns here if available
        }
        
        # Load GKE index
        self._load_gke_index(gke_index_path)
        
        if self._verbose:
            logger.info(f"🔧 [NamespaceResolver] Initialized with {len(self._gke_index)} GKE index entries")
    
    def _load_gke_index(self, explicit_path: Optional[str] = None) -> None:
        """Load namespace -> customer mappings from gke-index.json."""
        import json
        
        # Build list of paths to try
        paths_to_try = []
        
        # 1. Explicit path if provided
        if explicit_path:
            paths_to_try.append(explicit_path)
        
        # 2. Environment variable
        env_path = os.getenv('GKE_INDEX_PATH')
        if env_path:
            paths_to_try.append(env_path)
        
        # 3. Default paths
        for default_path in self.GKE_INDEX_PATHS:
            if default_path:
                paths_to_try.append(default_path)
        
        # Try each path
        for path in paths_to_try:
            try:
                if os.path.exists(path):
                    with open(path, 'r') as f:
                        index_data = json.load(f)
                    
                    # Parse the index: namespace_id -> fullname
                    for namespace_id, entry in index_data.items():
                        if isinstance(entry, dict) and 'fullname' in entry:
                            fullname = entry['fullname']
                            # Normalize customer name (replace underscores, clean up)
                            customer_name = fullname.replace('_', ' ')
                            self._gke_index[namespace_id] = customer_name
                    
                    if self._verbose:
                        logger.info(f"🔧 [NamespaceResolver] Loaded {len(self._gke_index)} entries from {path}")
                        # Log some examples
                        examples = list(self._gke_index.items())[:5]
                        for ns, cust in examples:
                            logger.info(f"   Example: {ns[:20]}... → {cust}")
                    return
                elif self._verbose:
                    logger.debug(f"🔧 [NamespaceResolver] Path not found: {path}")
            except Exception as e:
                if self._verbose:
                    logger.warning(f"🔧 [NamespaceResolver] Failed to load {path}: {e}")
        
        # No gke-index found
        if self._verbose:
            logger.warning("🔧 [NamespaceResolver] No gke-index.json found. Namespace resolution will be limited.")
            logger.info(f"   Tried paths: {paths_to_try}")
    
    def learn_from_alert(self, labels: Dict[str, Any], namespace: str) -> None:
        """Learn namespace -> customer mapping from an alert's labels."""
        if not namespace:
            if self._verbose:
                logger.debug("🔧 [NamespaceResolver] learn_from_alert: No namespace provided, skipping")
            return
        
        customer = self._extract_customer_from_labels(labels)
        if self._verbose:
            logger.info(f"🔧 [NamespaceResolver] learn_from_alert: namespace={namespace[:20]}..., extracted_customer='{customer}'")
        
        if customer and not self._is_ci_or_test(customer):
            self._namespace_cache[namespace] = customer
            if self._verbose:
                logger.info(f"   ✅ Cached mapping: {namespace[:20]}... → {customer}")
        elif self._verbose:
            if not customer:
                logger.debug(f"   ⚠️ No customer found in labels: {list(labels.keys())}")
            else:
                logger.debug(f"   ⚠️ Skipped CI/test customer: {customer}")
    
    def resolve(self, namespace: str, labels: Optional[Dict[str, Any]] = None) -> str:
        """
        Resolve a namespace ID to a customer name.
        
        Args:
            namespace: The namespace ID (e.g., "85a462d609654ce88e6fa767ec")
            labels: Optional labels dict that may contain customer info
            
        Returns:
            Customer name if found, otherwise the namespace ID itself
        """
        if self._verbose:
            logger.info(f"🔧 [NamespaceResolver] resolve: namespace={namespace[:20] if namespace else 'None'}...")
        
        # Strategy 1: Check labels directly
        if labels:
            customer = self._extract_customer_from_labels(labels)
            if customer:
                # Learn this mapping for future use
                if namespace:
                    self._namespace_cache[namespace] = customer
                if self._verbose:
                    logger.info(f"   ✅ Strategy 1 (labels): Found customer '{customer}' directly from labels")
                return customer
            elif self._verbose:
                logger.debug(f"   ❌ Strategy 1: No customer in labels {list(labels.keys())}")
        
        # Strategy 2: Check GKE Index (authoritative source)
        if namespace and namespace in self._gke_index:
            gke_customer = self._gke_index[namespace]
            # Cache it for faster future lookups
            self._namespace_cache[namespace] = gke_customer
            if self._verbose:
                logger.info(f"   ✅ Strategy 2 (gke-index): Found → '{gke_customer}'")
            return gke_customer
        elif self._verbose and namespace:
            logger.debug(f"   ❌ Strategy 2: Namespace not in GKE index (index size: {len(self._gke_index)})")
        
        # Strategy 3: Check cache (from previously learned alerts)
        if namespace in self._namespace_cache:
            cached = self._namespace_cache[namespace]
            if self._verbose:
                logger.info(f"   ✅ Strategy 3 (cache): Found cached mapping → '{cached}'")
            return cached
        elif self._verbose and namespace:
            logger.debug(f"   ❌ Strategy 3: Namespace not in cache (cache size: {len(self._namespace_cache)})")
        
        # Strategy 4: Check known patterns
        if namespace in self._known_patterns:
            known = self._known_patterns[namespace]
            if self._verbose:
                logger.info(f"   ✅ Strategy 4 (known patterns): Found → '{known}'")
            return known
        
        # Fallback: return namespace with marker
        fallback = f"[ns:{namespace[:12]}...]" if namespace and len(namespace) > 12 else namespace or "Unknown"
        if self._verbose:
            logger.warning(f"   ⚠️ Fallback: Could not resolve namespace, using '{fallback}'")
        return fallback
    
    def get_cache_stats(self) -> Dict[str, Any]:
        """Get statistics about the namespace cache and GKE index for debugging."""
        return {
            'gke_index_size': len(self._gke_index),
            'gke_index_customers': sorted(list(set(self._gke_index.values())))[:20],  # First 20
            'cache_size': len(self._namespace_cache),
            'cached_customers': list(set(self._namespace_cache.values())),
            'cached_namespaces': list(self._namespace_cache.keys())[:10]  # First 10 for brevity
        }
    
    def _extract_customer_from_labels(self, labels: Dict[str, Any]) -> str:
        """Extract customer name from labels."""
        customer = (
            labels.get('Customer') or 
            labels.get('customer') or 
            labels.get('deployment_cluster', '')
        ).strip()
        return customer
    
    def _is_ci_or_test(self, customer: str) -> bool:
        """Check if this is a CI/test environment."""
        if not customer:
            return False
        lower = customer.lower()
        is_ci = any(p in lower for p in ['ci', 'test', 'staging', 'dev', 'sandbox', 'demo', '*do not delete*'])
        return is_ci


@dataclass
class CrossChannelContext:
    """
    Comprehensive timeline context gathered from ALL monitored channels.
    
    This class implements the full correlation pipeline:
    1. Gather ALL events from ALL channels
    2. Resolve namespace → customer for each event
    3. Categorize events by type (alert, deployment, build, feature flag)
    4. Build unified chronological timeline
    5. Group by time windows (immediate, recent, historical)
    6. Separate same-customer vs other-customer events
    7. Calculate relevance scores for Claude to use
    
    Key features:
    - Unified timeline: ALL events sorted chronologically
    - Customer resolution: Namespace IDs mapped to customer names
    - Event categorization: Alerts, deployments, builds, feature flags
    - Noise filtering: CI/test environments filtered for production context
    - Relevance scoring: Pre-calculated scores guide Claude's correlation decisions
    """
    primary_alert: Dict[str, Any]
    channels: List[ChannelAlerts] = field(default_factory=list)
    lookback_minutes: int = 60
    verbose: bool = False  # Enable detailed logging for debugging
    
    # Namespace -> Customer resolver
    namespace_resolver: NamespaceCustomerResolver = field(default_factory=NamespaceCustomerResolver)
    
    # Unified timeline of ALL events
    unified_timeline: List[TimelineEvent] = field(default_factory=list)
    
    # Time windows for structured correlation
    immediate_window: Optional[TimelineWindow] = None  # ±30 min - likely same incident
    recent_window: Optional[TimelineWindow] = None     # ±2 hours - possibly related
    historical_window: Optional[TimelineWindow] = None # 7 days - pattern detection only
    
    # Correlation analysis results
    correlation_summary: Dict[str, Any] = field(default_factory=dict)
    
    # Causal Index pattern matches (symptom → root cause mappings)
    causal_patterns: Optional[Dict[str, Any]] = None
    
    def _log_verbose(self, message: str, level: str = 'info') -> None:
        """Log a message if verbose mode is enabled."""
        if not self.verbose:
            return
        if level == 'debug':
            logger.debug(message)
        elif level == 'warning':
            logger.warning(message)
        elif level == 'error':
            logger.error(message)
        else:
            logger.info(message)
    
    def _extract_customer(self, labels: Dict[str, Any]) -> str:
        """Extract customer name from alert labels."""
        return (
            labels.get('Customer') or 
            labels.get('customer') or 
            labels.get('deployment_cluster', '')
        ).strip()
    
    def _extract_namespace(self, labels: Dict[str, Any], message: str = '') -> str:
        """Extract namespace ID from labels or message."""
        # Try direct label
        namespace = labels.get('Namespace') or labels.get('namespace') or labels.get('resource.label.namespace_name', '')
        
        if namespace:
            return namespace.strip()
        
        # Try to extract from message (pattern: namespace_name="xxx" or Namespace: xxx)
        patterns = [
            r'namespace_name[=:]"?([a-f0-9]{20,})"?',
            r'Namespace:\s*([a-f0-9]{20,})',
            r'namespace[=:]"?([a-f0-9]{20,})"?'
        ]
        for pattern in patterns:
            match = re.search(pattern, message, re.IGNORECASE)
            if match:
                return match.group(1)
        
        return ''
    
    def _is_ci_or_test_environment(self, customer: str) -> bool:
        """Check if alert is from CI/test environment (should be filtered for production context)."""
        if not customer:
            return False
        lower_customer = customer.lower()
        return any(pattern in lower_customer for pattern in [
            'ci', 'test', 'staging', 'dev', 'sandbox', 'demo', '*do not delete*'
        ])
    
    def _parse_timestamp(self, ts_str: Optional[str]) -> Optional[datetime]:
        """Parse ISO timestamp string to datetime."""
        if not ts_str:
            return None
        try:
            # Handle ISO format with or without timezone
            if ts_str.endswith('Z'):
                ts_str = ts_str[:-1] + '+00:00'
            return datetime.fromisoformat(ts_str)
        except (ValueError, TypeError):
            return None
    
    def _get_primary_alert_time(self) -> Optional[datetime]:
        """Get the timestamp of the primary alert."""
        ts = self.primary_alert.get('slack_ts', '')
        if ts:
            try:
                return datetime.fromtimestamp(float(ts), tz=timezone.utc)
            except (ValueError, TypeError):
                pass
        return datetime.now(timezone.utc)
    
    def _detect_event_type(self, text: str, title: str = '') -> EventType:
        """Detect the type of event from message content."""
        lower_text = (text + ' ' + title).lower()
        
        # Build events
        if 'timed-out' in lower_text or 'timeout' in lower_text:
            return EventType.BUILD_TIMEOUT
        if 'failed' in lower_text and ('build' in lower_text or 'lim' in lower_text):
            return EventType.BUILD_FAILURE
        if 'success' in lower_text and 'build' in lower_text:
            return EventType.BUILD_SUCCESS
        
        # Deployment events
        if any(kw in lower_text for kw in ['deploy', 'helm', 'argocd', 'sync', 'upgrade', 'rollback', 'release']):
            return EventType.DEPLOYMENT
        
        # Feature flags
        if any(kw in lower_text for kw in ['feature flag', 'ff', 'toggle', 'launchdarkly']):
            return EventType.FEATURE_FLAG
        
        # Environment expiration
        if 'expir' in lower_text and ('environment' in lower_text or 'expire' in lower_text):
            return EventType.ENVIRONMENT_EXPIRATION
        
        return EventType.OTHER
    
    def _detect_deployment(self, text: str) -> bool:
        """Detect if a message is about a deployment."""
        return self._detect_event_type(text) == EventType.DEPLOYMENT
    
    def _detect_feature_flag(self, text: str) -> bool:
        """Detect if a message is about a feature flag change."""
        return self._detect_event_type(text) == EventType.FEATURE_FLAG
    
    def build_timeline(self) -> None:
        """
        Build comprehensive timeline-based correlation from ALL channel data.
        
        This method implements the full correlation pipeline:
        1. Extract primary alert info (customer, namespace, time)
        2. First pass: Learn namespace -> customer mappings from all alerts
        3. Second pass: Build unified timeline with resolved customers
        4. Group events into time windows
        5. Calculate correlation summary for Claude
        """
        self._log_verbose("=" * 80)
        self._log_verbose("🚀 [CORRELATION] Starting build_timeline()")
        self._log_verbose("=" * 80)
        
        primary_labels = self.primary_alert.get('labels', {})
        primary_customer = self._extract_customer(primary_labels)
        primary_namespace = self._extract_namespace(primary_labels, self.primary_alert.get('message', ''))
        primary_time = self._get_primary_alert_time()
        primary_alertname = primary_labels.get('alertname', self.primary_alert.get('title', ''))
        
        self._log_verbose(f"📋 [PRIMARY ALERT] Extracted info:")
        self._log_verbose(f"   Customer: '{primary_customer}'")
        self._log_verbose(f"   Namespace: '{primary_namespace}'")
        self._log_verbose(f"   Time: {primary_time}")
        self._log_verbose(f"   Alert Name: '{primary_alertname}'")
        self._log_verbose(f"   All Labels: {primary_labels}")
        
        # Learn primary alert's namespace mapping
        if primary_namespace and primary_customer:
            self.namespace_resolver.learn_from_alert(primary_labels, primary_namespace)
            self._log_verbose(f"   ✅ Learned namespace mapping: {primary_namespace[:20]}... → {primary_customer}")
        else:
            self._log_verbose(f"   ⚠️ Could not learn namespace mapping (namespace={bool(primary_namespace)}, customer={bool(primary_customer)})")
        
        # Filter out CI/test for production customers
        is_primary_production = not self._is_ci_or_test_environment(primary_customer)
        self._log_verbose(f"   Is Production: {is_primary_production}")
        
        # Initialize windows
        self.immediate_window = TimelineWindow(
            window_name="immediate",
            start_time=primary_time - timedelta(minutes=30) if primary_time else None,
            end_time=primary_time + timedelta(minutes=30) if primary_time else None
        )
        self.recent_window = TimelineWindow(
            window_name="recent",
            start_time=primary_time - timedelta(hours=2) if primary_time else None,
            end_time=primary_time + timedelta(hours=2) if primary_time else None
        )
        self.historical_window = TimelineWindow(
            window_name="historical",
            start_time=primary_time - timedelta(days=7) if primary_time else None,
            end_time=primary_time if primary_time else None
        )
        
        # First pass: Learn all namespace -> customer mappings
        self._log_verbose("")
        self._log_verbose("🔍 [PASS 1] Learning namespace → customer mappings from all alerts...")
        total_alerts_pass1 = 0
        for ch in self.channels:
            self._log_verbose(f"   Channel: #{ch.channel_name} ({ch.channel_id}) - {len(ch.alerts)} alerts")
            for alert in ch.alerts:
                total_alerts_pass1 += 1
                labels = alert.get('labels', {})
                namespace = self._extract_namespace(labels, alert.get('message', ''))
                if namespace:
                    self.namespace_resolver.learn_from_alert(labels, namespace)
        self._log_verbose(f"   Total alerts processed in pass 1: {total_alerts_pass1}")
        if self.namespace_resolver._verbose or self.verbose:
            cache_stats = self.namespace_resolver.get_cache_stats()
            self._log_verbose(f"   Namespace cache now has {cache_stats['cache_size']} entries: {cache_stats['cached_customers']}")
        
        # Track unique customers seen in immediate window for cluster detection
        immediate_customers: Set[str] = set()
        immediate_alert_types: Dict[str, int] = defaultdict(int)
        
        # Verbose tracking counters
        alerts_processed = 0
        alerts_skipped_ci = 0
        alerts_same_customer = 0
        alerts_other_customer = 0
        
        # Second pass: Build timeline and categorize events
        self._log_verbose("")
        self._log_verbose("🔍 [PASS 2] Building timeline and categorizing events...")
        for ch in self.channels:
            self._log_verbose(f"   📂 Processing channel: #{ch.channel_name}")
            # Process alerts
            for alert in ch.alerts:
                alerts_processed += 1
                labels = alert.get('labels', {})
                namespace = self._extract_namespace(labels, alert.get('message', ''))
                alert_customer = self._extract_customer(labels)
                
                # Resolve customer from namespace if not directly available
                customer_source = "unknown"
                if not alert_customer and namespace:
                    alert_customer = self.namespace_resolver.resolve(namespace, labels)
                    customer_source = "namespace_resolver"
                elif alert_customer:
                    customer_source = "direct_label"
                else:
                    alert_customer = "Unknown"
                    customer_source = "fallback"
                
                alert_time = self._parse_timestamp(alert.get('timestamp'))
                alert_title = alert.get('title', '')
                alertname = labels.get('alertname', alert_title)
                
                # Skip CI/test alerts when analyzing production incidents
                if is_primary_production and self._is_ci_or_test_environment(alert_customer):
                    alerts_skipped_ci += 1
                    self._log_verbose(f"      ⏭️ SKIPPED (CI/test): '{alert_title[:40]}...' customer='{alert_customer}'", 'debug')
                    continue
                
                self._log_verbose(f"      📌 Alert #{alerts_processed}: '{alert_title[:50]}...'")
                self._log_verbose(f"         Customer: '{alert_customer}' (source: {customer_source})")
                self._log_verbose(f"         Namespace: '{namespace[:20]}...' " if namespace else "         Namespace: None")
                self._log_verbose(f"         Time: {alert_time}")
                
                # Create timeline event
                event = TimelineEvent(
                    timestamp=alert_time or datetime.now(timezone.utc),
                    event_type=EventType.ALERT,
                    customer=alert_customer,
                    namespace=namespace,
                    title=alert_title,
                    message=alert.get('message', ''),
                    channel_id=ch.channel_id,
                    channel_name=ch.channel_name,
                    link=alert.get('link', ''),
                    labels=labels
                )
                self.unified_timeline.append(event)
                
                # Add to appropriate window
                alert_with_channel = {
                    **alert,
                    'channel_name': ch.channel_name,
                    'channel_id': ch.channel_id,
                    'customer': alert_customer,
                    'namespace': namespace,
                    'alertname': alertname
                }
                
                # Determine time window and calculate relevance
                window_name = "unknown"
                if primary_time and alert_time:
                    time_diff = abs((alert_time - primary_time).total_seconds())
                    time_diff_mins = time_diff / 60
                    
                    if time_diff <= 30 * 60:  # 30 minutes - immediate window
                        target_window = self.immediate_window
                        window_name = "IMMEDIATE"
                        immediate_customers.add(alert_customer)
                        immediate_alert_types[alertname] += 1
                        
                        # Calculate relevance score
                        event.relevance_score = self._calculate_relevance(
                            alert_customer, primary_customer,
                            alertname, primary_alertname,
                            time_diff
                        )
                    elif time_diff <= 2 * 60 * 60:  # 2 hours
                        target_window = self.recent_window
                        window_name = "RECENT"
                        event.relevance_score = 0.5 if alert_customer.lower() == primary_customer.lower() else 0.2
                    else:
                        target_window = self.historical_window
                        window_name = "HISTORICAL"
                        event.relevance_score = 0.3 if alert_customer.lower() == primary_customer.lower() else 0.0
                    
                    self._log_verbose(f"         Time diff: {time_diff_mins:.1f} min → {window_name} window")
                else:
                    target_window = self.historical_window
                    window_name = "HISTORICAL (no timestamp)"
                    event.relevance_score = 0.1
                    self._log_verbose(f"         ⚠️ Missing timestamp, defaulting to HISTORICAL window")
                
                # Categorize by customer match
                is_same_customer = alert_customer and primary_customer and alert_customer.lower() == primary_customer.lower()
                if is_same_customer:
                    target_window.same_customer_alerts.append(alert_with_channel)
                    alerts_same_customer += 1
                    self._log_verbose(f"         ✅ SAME CUSTOMER match! Relevance: {event.relevance_score:.2f}")
                else:
                    target_window.other_customer_alerts.append(alert_with_channel)
                    alerts_other_customer += 1
                    self._log_verbose(f"         ❌ Different customer ('{alert_customer}' vs '{primary_customer}'). Relevance: {event.relevance_score:.2f}")
            
            # Process other messages (deployments, feature flags, builds)
            for msg in ch.other_messages:
                text = msg.get('text', '')
                msg_time = self._parse_timestamp(msg.get('timestamp'))
                event_type = self._detect_event_type(text)
                
                msg_with_channel = {
                    **msg,
                    'channel_name': ch.channel_name,
                    'event_type': event_type.value
                }
                
                # Only look at recent window for non-alert events
                if primary_time and msg_time:
                    time_diff = abs((msg_time - primary_time).total_seconds())
                    if time_diff > 2 * 60 * 60:  # More than 2 hours, skip
                        continue
                
                # Add to timeline
                event = TimelineEvent(
                    timestamp=msg_time or datetime.now(timezone.utc),
                    event_type=event_type,
                    customer="",  # Non-alert messages often don't have customer
                    namespace="",
                    title=text[:100] if text else "",
                    message=text,
                    channel_id=ch.channel_id,
                    channel_name=ch.channel_name,
                    link=msg.get('link', ''),
                    labels={}
                )
                self.unified_timeline.append(event)
                
                # Categorize by type
                if event_type == EventType.DEPLOYMENT:
                    self.immediate_window.deployments.append(msg_with_channel)
                elif event_type == EventType.FEATURE_FLAG:
                    self.immediate_window.feature_flags.append(msg_with_channel)
                elif event_type in [EventType.BUILD_FAILURE, EventType.BUILD_TIMEOUT, EventType.BUILD_SUCCESS]:
                    self.immediate_window.build_events.append(msg_with_channel)
        
        # Sort unified timeline by timestamp
        self.unified_timeline.sort(key=lambda e: e.timestamp if e.timestamp else datetime.min.replace(tzinfo=timezone.utc))
        
        # Log pass 2 summary
        self._log_verbose("")
        self._log_verbose("📊 [PASS 2 SUMMARY]")
        self._log_verbose(f"   Total alerts processed: {alerts_processed}")
        self._log_verbose(f"   Skipped (CI/test): {alerts_skipped_ci}")
        self._log_verbose(f"   Same customer matches: {alerts_same_customer}")
        self._log_verbose(f"   Other customer matches: {alerts_other_customer}")
        self._log_verbose(f"   Unique customers in immediate window: {list(immediate_customers)}")
        self._log_verbose(f"   Alert types in immediate window: {dict(immediate_alert_types)}")
        
        # Build correlation summary
        self._build_correlation_summary(
            primary_customer, primary_alertname, immediate_customers, immediate_alert_types
        )
        
        self._log_verbose("")
        self._log_verbose("=" * 80)
        self._log_verbose("✅ [CORRELATION] build_timeline() complete")
        self._log_verbose("=" * 80)
    
    def _calculate_relevance(
        self, 
        alert_customer: str, 
        primary_customer: str,
        alert_type: str,
        primary_type: str,
        time_diff_seconds: float
    ) -> float:
        """
        Calculate relevance score for an alert based on correlation rules.
        
        Returns a score from 0.0 to 1.0:
        - 1.0: Same customer + same alert type + immediate
        - 0.9: Same customer + immediate
        - 0.8: Same alert type + immediate (different customer)
        - 0.6: Same customer + recent
        - 0.4: Same alert type + recent (different customer)
        - 0.2: Historical same customer
        - 0.0: Historical different customer
        """
        is_same_customer = alert_customer and primary_customer and alert_customer.lower() == primary_customer.lower()
        is_same_type = alert_type and primary_type and alert_type.lower() == primary_type.lower()
        
        # Time-based base score
        if time_diff_seconds <= 30 * 60:  # Immediate (±30 min)
            if is_same_customer and is_same_type:
                return 1.0
            elif is_same_customer:
                return 0.9
            elif is_same_type:
                return 0.8  # Same alert type, different customer = potential systemic issue
            else:
                return 0.5
        elif time_diff_seconds <= 2 * 60 * 60:  # Recent (±2 hours)
            if is_same_customer:
                return 0.6
            elif is_same_type:
                return 0.4
            else:
                return 0.2
        else:  # Historical
            if is_same_customer:
                return 0.3
            else:
                return 0.0  # Different customer + historical = NOT correlated
    
    def _build_correlation_summary(
        self,
        primary_customer: str,
        primary_alertname: str,
        immediate_customers: Set[str],
        immediate_alert_types: Dict[str, int]
    ) -> None:
        """Build summary of correlation findings for Claude."""
        self._log_verbose("")
        self._log_verbose("📋 [CORRELATION SUMMARY] Building summary for Claude...")
        
        self.correlation_summary = {
            'primary_customer': primary_customer,
            'primary_alertname': primary_alertname,
            'same_customer_total': 0,
            'immediate_same_customer': 0,
            'immediate_other_customers': 0,
            'potential_cluster': False,
            'cluster_type': None,
            'recent_deployments': 0,
            'recent_build_events': 0,
            'recent_feature_flags': 0,
            'unique_customers_immediate': list(immediate_customers),
            'alert_types_immediate': dict(immediate_alert_types),
            'correlation_decision_hints': []
        }
        
        if self.immediate_window:
            self.correlation_summary['immediate_same_customer'] = len(self.immediate_window.same_customer_alerts)
            self.correlation_summary['immediate_other_customers'] = len(self.immediate_window.other_customer_alerts)
            self.correlation_summary['recent_deployments'] = len(self.immediate_window.deployments)
            self.correlation_summary['recent_build_events'] = len(self.immediate_window.build_events)
            self.correlation_summary['recent_feature_flags'] = len(self.immediate_window.feature_flags)
            # BUG FIX: Include immediate window alerts in same_customer_total
            self.correlation_summary['same_customer_total'] += len(self.immediate_window.same_customer_alerts)
            
            self._log_verbose(f"   IMMEDIATE Window:")
            self._log_verbose(f"      Same customer alerts: {self.correlation_summary['immediate_same_customer']}")
            self._log_verbose(f"      Other customer alerts: {self.correlation_summary['immediate_other_customers']}")
            self._log_verbose(f"      Deployments: {self.correlation_summary['recent_deployments']}")
            self._log_verbose(f"      Build events: {self.correlation_summary['recent_build_events']}")
            self._log_verbose(f"      Feature flags: {self.correlation_summary['recent_feature_flags']}")
            
            # Log same customer alerts details and add hint for Claude
            if self.immediate_window.same_customer_alerts:
                self._log_verbose(f"      📌 Same customer alert details:")
                for i, alert in enumerate(self.immediate_window.same_customer_alerts[:5], 1):
                    self._log_verbose(f"         {i}. {alert.get('title', '')[:50]}... (customer: {alert.get('customer', '')})")
                # Add hint for same-customer immediate alerts
                count = len(self.immediate_window.same_customer_alerts)
                hint = f"🔴 {count} same-customer alert(s) in immediate window (±30 min) - likely same incident, analyze together"
                self.correlation_summary['correlation_decision_hints'].append(hint)
                self._log_verbose(f"   {hint}")
                
                # Check for environment expiration alerts - these are ROOT CAUSES
                env_expiration_alerts = [
                    a for a in self.immediate_window.same_customer_alerts
                    if 'expir' in a.get('title', '').lower() and 'environment' in a.get('title', '').lower()
                ]
                if env_expiration_alerts:
                    env_hint = f"🔥 ROOT CAUSE DETECTED: Environment Expiration alert found for same customer ({primary_customer}). When an environment expires, ALL services fail - this is the root cause of other alerts."
                    self.correlation_summary['correlation_decision_hints'].insert(0, env_hint)  # Insert at top - highest priority
                    self.correlation_summary['environment_expiration_detected'] = True
                    self.correlation_summary['environment_expiration_alert'] = {
                        'title': env_expiration_alerts[0].get('title', ''),
                        'timestamp': env_expiration_alerts[0].get('timestamp', ''),
                        'link': env_expiration_alerts[0].get('link', '')
                    }
                    self._log_verbose(f"   🔥 ENVIRONMENT EXPIRATION DETECTED: {env_expiration_alerts[0].get('title', '')}")
            
            # Log other customer alerts details 
            if self.immediate_window.other_customer_alerts:
                self._log_verbose(f"      📌 Other customer alert details:")
                for i, alert in enumerate(self.immediate_window.other_customer_alerts[:5], 1):
                    self._log_verbose(f"         {i}. {alert.get('title', '')[:50]}... (customer: {alert.get('customer', '')})")
            
            # Detect cluster patterns
            if len(immediate_customers) >= 3:
                self.correlation_summary['potential_cluster'] = True
                self.correlation_summary['cluster_type'] = 'multi_customer'
                hint = f"⚠️ CLUSTER: {len(immediate_customers)} different customers affected in immediate window - likely systemic issue"
                self.correlation_summary['correlation_decision_hints'].append(hint)
                self._log_verbose(f"   🔴 CLUSTER DETECTED: {hint}")
            
            # Check for same alert type cluster
            for alert_type, count in immediate_alert_types.items():
                if count >= 3:
                    self.correlation_summary['potential_cluster'] = True
                    self.correlation_summary['cluster_type'] = 'same_alert_type'
                    hint = f"⚠️ CLUSTER: Alert type '{alert_type}' fired {count} times in immediate window"
                    self.correlation_summary['correlation_decision_hints'].append(hint)
                    self._log_verbose(f"   🔴 CLUSTER DETECTED: {hint}")
            
            # Add deployment hint
            if self.immediate_window.deployments:
                hint = f"🚀 {len(self.immediate_window.deployments)} deployment(s) detected in immediate window - potential regression"
                self.correlation_summary['correlation_decision_hints'].append(hint)
                self._log_verbose(f"   {hint}")
            
            # Add build failure hint
            build_failures = [b for b in self.immediate_window.build_events if 'fail' in b.get('event_type', '').lower()]
            if build_failures:
                hint = f"🔴 {len(build_failures)} build failure(s) detected - check for related code changes"
                self.correlation_summary['correlation_decision_hints'].append(hint)
                self._log_verbose(f"   {hint}")
        
        if self.recent_window:
            self.correlation_summary['same_customer_total'] += len(self.recent_window.same_customer_alerts)
            self._log_verbose(f"   RECENT Window: {len(self.recent_window.same_customer_alerts)} same customer alerts")
            if self.recent_window.same_customer_alerts:
                count = len(self.recent_window.same_customer_alerts)
                hint = f"📍 {count} same-customer alert(s) in recent window (±2 hours) - possibly related, check for patterns"
                self.correlation_summary['correlation_decision_hints'].append(hint)
                self._log_verbose(f"   {hint}")
                
                # Also check recent window for environment expiration if not already found
                if not self.correlation_summary.get('environment_expiration_detected'):
                    env_expiration_alerts = [
                        a for a in self.recent_window.same_customer_alerts
                        if 'expir' in a.get('title', '').lower() and 'environment' in a.get('title', '').lower()
                    ]
                    if env_expiration_alerts:
                        env_hint = f"🔥 ROOT CAUSE DETECTED: Environment Expiration alert found for same customer ({primary_customer}) in recent window. Environment expiration causes ALL services to fail."
                        self.correlation_summary['correlation_decision_hints'].insert(0, env_hint)
                        self.correlation_summary['environment_expiration_detected'] = True
                        self.correlation_summary['environment_expiration_alert'] = {
                            'title': env_expiration_alerts[0].get('title', ''),
                            'timestamp': env_expiration_alerts[0].get('timestamp', ''),
                            'link': env_expiration_alerts[0].get('link', '')
                        }
                        self._log_verbose(f"   🔥 ENVIRONMENT EXPIRATION DETECTED (recent): {env_expiration_alerts[0].get('title', '')}")
        
        if self.historical_window:
            self.correlation_summary['same_customer_total'] += len(self.historical_window.same_customer_alerts)
            self._log_verbose(f"   HISTORICAL Window: {len(self.historical_window.same_customer_alerts)} same customer alerts")
            if self.historical_window.same_customer_alerts:
                hint = f"📅 {len(self.historical_window.same_customer_alerts)} previous occurrences for same customer - check if recurring issue"
                self.correlation_summary['correlation_decision_hints'].append(hint)
                self._log_verbose(f"   {hint}")
        
        self._log_verbose(f"   Total same customer alerts (all windows): {self.correlation_summary['same_customer_total']}")
        self._log_verbose(f"   Decision hints for Claude: {len(self.correlation_summary['correlation_decision_hints'])}")
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert to comprehensive dictionary for Claude context.
        
        Returns:
        - Primary alert info with resolved customer
        - Unified timeline of all events
        - Time-window grouped events
        - Correlation summary with decision hints
        """
        # Build timeline if not already done
        if self.immediate_window is None:
            self.build_timeline()
        
        # Extract primary alert info
        primary_labels = self.primary_alert.get('labels', {})
        primary_customer = self._extract_customer(primary_labels)
        primary_namespace = self._extract_namespace(primary_labels, self.primary_alert.get('message', ''))
        primary_time = self._get_primary_alert_time()
        
        def format_window(window: Optional[TimelineWindow]) -> Dict[str, Any]:
            if not window:
                return {}
            return {
                'window_name': window.window_name,
                'time_range': f"{window.start_time.isoformat() if window.start_time else 'unknown'} to {window.end_time.isoformat() if window.end_time else 'unknown'}",
                'same_customer_alerts': [
                    {
                        'title': a.get('title', ''),
                        'alertname': a.get('alertname', a.get('title', '')),
                        'customer': a.get('customer', ''),
                        'namespace': a.get('namespace', ''),
                        'timestamp': a.get('timestamp', ''),
                        'link': a.get('link', ''),
                        'channel': a.get('channel_name', ''),
                        'labels': {k: v for k, v in a.get('labels', {}).items() if k not in ['Customer', 'customer', 'deployment_cluster']}
                    }
                    for a in window.same_customer_alerts[:10]
                ],
                'other_customer_alerts': [
                    {
                        'title': a.get('title', ''),
                        'alertname': a.get('alertname', a.get('title', '')),
                        'customer': a.get('customer', ''),
                        'namespace': a.get('namespace', ''),
                        'timestamp': a.get('timestamp', ''),
                        'link': a.get('link', ''),
                        'channel': a.get('channel_name', '')
                    }
                    for a in window.other_customer_alerts[:10]
                ],
                'deployments': [
                    {
                        'text': d.get('text', '')[:200],
                        'timestamp': d.get('timestamp', ''),
                        'link': d.get('link', ''),
                        'channel': d.get('channel_name', '')
                    }
                    for d in window.deployments[:5]
                ],
                'build_events': [
                    {
                        'text': b.get('text', '')[:200],
                        'event_type': b.get('event_type', 'build'),
                        'timestamp': b.get('timestamp', ''),
                        'link': b.get('link', ''),
                        'channel': b.get('channel_name', '')
                    }
                    for b in getattr(window, 'build_events', [])[:5]
                ],
                'feature_flags': [
                    {
                        'text': f.get('text', '')[:200],
                        'timestamp': f.get('timestamp', ''),
                        'link': f.get('link', ''),
                        'channel': f.get('channel_name', '')
                    }
                    for f in window.feature_flags[:5]
                ]
            }
        
        # Get high-relevance events from unified timeline for quick reference
        high_relevance_events = [
            e.to_dict() for e in self.unified_timeline 
            if e.relevance_score >= 0.7
        ][:15]
        
        result = {
            'primary_alert': {
                'customer': primary_customer,
                'namespace': primary_namespace,
                'timestamp': primary_time.isoformat() if primary_time else None,
                'title': self.primary_alert.get('title', ''),
                'alertname': primary_labels.get('alertname', '')
            },
            'correlation_windows': {
                'immediate': format_window(self.immediate_window),
                'recent': format_window(self.recent_window),
                'historical': format_window(self.historical_window)
            },
            'high_relevance_events': high_relevance_events,
            'summary': self.correlation_summary,
            'correlation_hints': self.correlation_summary.get('correlation_decision_hints', [])
        }
        
        return result


class AlertContextGatherer:
    """
    Gathers raw alert context from multiple channels.
    
    Claude performs all correlation analysis - this module just provides raw data.
    
    Monitored channels:
    - #critical-alerts-devops (C05GN4V2P9Q): Critical infrastructure alerts
    - #urgent-severity-alerts (C06745ME1PG): Urgent production alerts  
    - #audit-account-service (C025NT4L5UK): Account service audit events
    - #high-severity-alerts (C067CV07KQ8): High severity production alerts
    - #Production (C066M2C91QV): Production environment alerts
    - #environment-expiration (C02MADV4406): Environment expiration notifications
    """
    
    # Channel configuration
    CONTEXT_CHANNELS = {
        'C05GN4V2P9Q': {
            'name': 'critical-alerts-devops',
            'description': 'Critical infrastructure alerts'
        },
        'C06745ME1PG': {
            'name': 'urgent-severity-alerts',
            'description': 'Urgent production alerts'
        },
        'C025NT4L5UK': {
            'name': 'audit-account-service',
            'description': 'Account service audit events'
        },
        'C067CV07KQ8': {
            'name': 'high-severity-alerts',
            'description': 'High severity production alerts'
        },
        'C066M2C91QV': {
            'name': 'Production',
            'description': 'Production environment alerts'
        },
        'C02MADV4406': {
            'name': 'environment-expiration',
            'description': 'Environment expiration notifications'
        }
    }
    
    def __init__(self, slack_client, verbose: bool = False, gke_index_path: Optional[str] = None):
        """
        Initialize the context gatherer.
        
        Args:
            slack_client: SlackClient instance for fetching messages
            verbose: Enable detailed logging for debugging correlation logic
            gke_index_path: Path to gke-index.json for namespace resolution
        """
        self.slack = slack_client
        self.verbose = verbose
        self.gke_index_path = gke_index_path
        logger.info(f"AlertContextGatherer initialized with {len(self.CONTEXT_CHANNELS)} channels (verbose={verbose})")
        if gke_index_path:
            logger.info(f"   GKE index path: {gke_index_path}")
    
    def gather_context(
        self,
        primary_alert: Dict[str, Any],
        lookback_minutes: int = 60,
        include_channels: Optional[List[str]] = None,
        verbose: Optional[bool] = None
    ) -> CrossChannelContext:
        """
        Gather raw alert context from multiple channels.
        
        Args:
            primary_alert: The primary alert being enriched
            lookback_minutes: How far back to look for context
            include_channels: Optional list of channel IDs (defaults to all)
            verbose: Override instance verbose setting for this call
            
        Returns:
            CrossChannelContext with raw data for Claude to analyze
        """
        # Use passed verbose or instance default
        use_verbose = verbose if verbose is not None else self.verbose
        
        result = CrossChannelContext(
            primary_alert=primary_alert,
            lookback_minutes=lookback_minutes,
            verbose=use_verbose,
            namespace_resolver=NamespaceCustomerResolver(
                verbose=use_verbose,
                gke_index_path=self.gke_index_path
            )
        )
        
        # Get timestamp of primary alert for reference
        primary_ts = primary_alert.get('slack_ts', '')
        
        # Determine which channels to search
        channels = include_channels or list(self.CONTEXT_CHANNELS.keys())
        
        if use_verbose:
            logger.info("=" * 80)
            logger.info("🔍 [VERBOSE] AlertContextGatherer.gather_context() START")
            logger.info("=" * 80)
            logger.info(f"   Primary alert: {primary_alert.get('title', primary_alert.get('alertname', 'Unknown'))[:60]}...")
            logger.info(f"   Primary alert labels: {primary_alert.get('labels', {})}")
            logger.info(f"   Primary alert slack_ts: {primary_ts}")
            logger.info(f"   Lookback: {lookback_minutes} min")
            logger.info(f"   Channels to search: {channels}")
        
        logger.info(f"🔍 Gathering context from {len(channels)} channels (lookback: {lookback_minutes} min)")
        
        for channel_id in channels:
            if channel_id not in self.CONTEXT_CHANNELS:
                if use_verbose:
                    logger.warning(f"   ⚠️ Channel {channel_id} not in CONTEXT_CHANNELS, skipping")
                continue
            
            channel_config = self.CONTEXT_CHANNELS[channel_id]
            channel_name = channel_config['name']
            
            if use_verbose:
                logger.info(f"")
                logger.info(f"   📂 Fetching from #{channel_name} ({channel_id})...")
            
            try:
                messages = self.slack.fetch_messages_since(
                    channel_id=channel_id,
                    minutes=lookback_minutes,
                    limit=100
                )
                
                if use_verbose:
                    logger.info(f"      Retrieved {len(messages)} raw messages")
                
                # Parse messages into alerts and other messages
                channel_alerts = ChannelAlerts(
                    channel_id=channel_id,
                    channel_name=channel_name
                )
                
                skipped_primary = 0
                parsed_alerts = 0
                parsed_other = 0
                parse_failed = 0
                
                for msg in messages:
                    # Skip the primary alert itself
                    if msg.get('ts') == primary_ts:
                        skipped_primary += 1
                        continue
                    
                    parsed = self._parse_message(msg, channel_id)
                    if parsed:
                        if parsed.get('is_alert'):
                            channel_alerts.alerts.append(parsed)
                            parsed_alerts += 1
                            if use_verbose:
                                labels = parsed.get('labels', {})
                                customer = labels.get('Customer') or labels.get('customer') or labels.get('deployment_cluster', '')
                                logger.info(f"      🔔 Alert: '{parsed.get('title', '')[:40]}...' Customer='{customer}'")
                        else:
                            channel_alerts.other_messages.append(parsed)
                            parsed_other += 1
                    else:
                        parse_failed += 1
                
                result.channels.append(channel_alerts)
                logger.info(f"   📥 #{channel_name}: {len(channel_alerts.alerts)} alerts, {len(channel_alerts.other_messages)} other messages")
                
                if use_verbose:
                    logger.info(f"      Parse stats: {parsed_alerts} alerts, {parsed_other} other, {parse_failed} unparseable, {skipped_primary} skipped (primary)")
                
            except Exception as e:
                logger.warning(f"Failed to fetch from #{channel_name}: {e}")
                if use_verbose:
                    import traceback
                    logger.error(f"   Full traceback: {traceback.format_exc()}")
        
        total_alerts = sum(len(ch.alerts) for ch in result.channels)
        total_other = sum(len(ch.other_messages) for ch in result.channels)
        logger.info(f"✅ Context gathered: {total_alerts} alerts, {total_other} other messages")
        
        if use_verbose:
            logger.info("")
            logger.info("📊 [VERBOSE] gather_context() SUMMARY:")
            logger.info(f"   Total channels processed: {len(result.channels)}")
            logger.info(f"   Total alerts found: {total_alerts}")
            logger.info(f"   Total other messages: {total_other}")
            
            # List all unique customers found
            all_customers = set()
            for ch in result.channels:
                for alert in ch.alerts:
                    labels = alert.get('labels', {})
                    customer = labels.get('Customer') or labels.get('customer') or labels.get('deployment_cluster', '')
                    if customer:
                        all_customers.add(customer)
            
            logger.info(f"   Unique customers found: {list(all_customers)}")
            logger.info("=" * 80)
            logger.info("🔍 [VERBOSE] AlertContextGatherer.gather_context() END")
            logger.info("=" * 80)
        
        return result
    
    def _parse_message(self, msg: Dict[str, Any], channel_id: str) -> Optional[Dict[str, Any]]:
        """Parse a Slack message into a structured format."""
        ts = msg.get('ts', '')
        timestamp = None
        if ts:
            try:
                timestamp = datetime.fromtimestamp(float(ts), tz=timezone.utc).isoformat()
            except (ValueError, TypeError):
                pass
        
        # Build Slack link
        ts_clean = ts.replace('.', '') if ts else ''
        link = f"https://apiiro.slack.com/archives/{channel_id}/p{ts_clean}" if ts_clean else ''
        
        # Check if it's a bot/alert message
        is_bot = msg.get('subtype') == 'bot_message'
        attachments = msg.get('attachments', [])
        blocks = msg.get('blocks', [])
        text = msg.get('text', '')
        
        if is_bot and attachments:
            # Parse Grafana-style alert (has attachments with labels)
            att = attachments[0]
            title = att.get('title', '')
            att_text = att.get('text', '')
            
            # Parse labels from text
            labels = {}
            for line in att_text.split('\n'):
                if ':' in line and not line.strip().startswith('<'):
                    parts = line.split(':', 1)
                    if len(parts) == 2:
                        key = parts[0].strip()
                        value = parts[1].strip()
                        if not value.startswith('http') and not value.startswith('<'):
                            labels[key] = value
            
            return {
                'is_alert': True,
                'title': title,
                'message': att_text,
                'labels': labels,
                'timestamp': timestamp,
                'link': link
            }
        elif is_bot and blocks and text:
            # Parse Block Kit style notifications (environment expiration, etc.)
            # Format: "[*CustomerName*] Environment namespace_id expired/expiring"
            labels = {}
            title = text[:100] if text else ''
            
            # Extract customer name from [*CustomerName*] pattern
            customer_match = re.search(r'\[\*([^*]+)\*\]', text)
            if customer_match:
                labels['Customer'] = customer_match.group(1)
            
            # Extract namespace from URL or text
            # Format: environment/62649d0876954b5e9a06564ab5
            ns_match = re.search(r'environment/([a-f0-9]{20,})', text)
            if ns_match:
                labels['namespace'] = ns_match.group(1)
            
            # Detect event type from text
            is_expiration = 'expire' in text.lower() or 'expired' in text.lower() or 'deletion' in text.lower()
            
            return {
                'is_alert': is_expiration,  # Treat expiration events as alerts for correlation
                'title': title,
                'message': text,
                'labels': labels,
                'timestamp': timestamp,
                'link': link,
                'event_subtype': 'environment_expiration' if is_expiration else 'notification'
            }
        elif text and len(text) > 10:
            # Non-alert message (could be deployment, feature flag, etc.)
            return {
                'is_alert': False,
                'text': text,
                'timestamp': timestamp,
                'user': msg.get('user'),
                'link': link
            }
        
        return None


def get_context_channels() -> Dict[str, Dict[str, Any]]:
    """Get the configured context channels."""
    return AlertContextGatherer.CONTEXT_CHANNELS.copy()


def add_context_channel(channel_id: str, name: str, description: str = ''):
    """Add a new channel to the context configuration."""
    AlertContextGatherer.CONTEXT_CHANNELS[channel_id] = {
        'name': name,
        'description': description
    }


# Backward compatibility aliases
AlertCorrelator = AlertContextGatherer
CorrelationResult = CrossChannelContext

