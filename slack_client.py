"""
Slack Client Module

Handles Slack API interactions:
- Scraping messages from channels
- Posting enriched messages to threads
- Searching message history
"""

import os
import logging
import time
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta

from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError

logger = logging.getLogger(__name__)


class SlackClient:
    """
    Slack client for alert enrichment operations.
    
    Handles:
    - Fetching messages from alert channels
    - Filtering for Grafana bot messages
    - Posting enriched responses to threads
    - Searching historical discussions
    """
    
    # Known Grafana bot identifiers
    GRAFANA_BOT_NAMES = ['grafana', 'Grafana']
    GRAFANA_BOT_ID_PREFIX = 'B'  # Bot IDs start with B
    
    # Rate limiting configuration
    MAX_RETRIES = 5
    BASE_RETRY_DELAY = 1  # seconds
    
    def __init__(self, token: Optional[str] = None):
        """
        Initialize Slack client.
        
        Args:
            token: Slack bot token. If not provided, reads from ALERTS_ENRICHER_SLACK_BOT_TOKEN 
                   or SLACK_BOT_TOKEN env var (in that order).
        """
        self.token = token or os.getenv('ALERTS_ENRICHER_SLACK_BOT_TOKEN') or os.getenv('SLACK_BOT_TOKEN')
        if not self.token:
            raise ValueError("ALERTS_ENRICHER_SLACK_BOT_TOKEN environment variable not set")
        
        self.client = WebClient(token=self.token)
        self._bot_user_id = None
    
    @property
    def bot_user_id(self) -> str:
        """Get the bot's user ID (cached)."""
        if self._bot_user_id is None:
            try:
                response = self.client.auth_test()
                self._bot_user_id = response['user_id']
            except SlackApiError as e:
                logger.error(f"Failed to get bot user ID: {e}")
                self._bot_user_id = ''
        return self._bot_user_id
    
    def _call_with_rate_limit_handling(self, api_call, *args, **kwargs):
        """
        Call a Slack API method with automatic rate limit handling.
        
        Implements exponential backoff when rate limited.
        
        Args:
            api_call: The Slack API method to call
            *args, **kwargs: Arguments to pass to the API method
            
        Returns:
            The API response
            
        Raises:
            SlackApiError: If the call fails after all retries
        """
        for attempt in range(self.MAX_RETRIES):
            try:
                return api_call(*args, **kwargs)
            except SlackApiError as e:
                if e.response.get('error') == 'ratelimited':
                    retry_after = int(e.response.headers.get('Retry-After', self.BASE_RETRY_DELAY))
                    wait_time = retry_after if attempt == 0 else retry_after * (2 ** attempt)
                    
                    logger.warning(
                        f"Rate limited by Slack API (attempt {attempt + 1}/{self.MAX_RETRIES}). "
                        f"Waiting {wait_time}s before retry..."
                    )
                    time.sleep(wait_time)
                    
                    if attempt == self.MAX_RETRIES - 1:
                        logger.error(f"Max retries reached for rate-limited call")
                        raise
                else:
                    # Not a rate limit error, raise immediately
                    raise
    
    def fetch_messages_since(
        self,
        channel_id: str,
        oldest_ts: Optional[str] = None,
        minutes: int = 15,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """
        Fetch messages from a channel since a given timestamp.
        
        Args:
            channel_id: Slack channel ID
            oldest_ts: Oldest message timestamp to fetch from (exclusive)
            minutes: If oldest_ts not provided, fetch messages from last N minutes
            limit: Maximum number of messages to fetch
            
        Returns:
            List of message dictionaries, oldest first.
        """
        if not oldest_ts:
            # Calculate timestamp from minutes ago
            oldest_time = datetime.utcnow() - timedelta(minutes=minutes)
            oldest_ts = str(oldest_time.timestamp())
        
        messages = []
        cursor = None
        
        try:
            while True:
                response = self._call_with_rate_limit_handling(
                    self.client.conversations_history,
                    channel=channel_id,
                    oldest=oldest_ts,
                    limit=min(limit - len(messages), 100),
                    cursor=cursor
                )
                
                messages.extend(response.get('messages', []))
                
                # Check for pagination
                if not response.get('has_more') or len(messages) >= limit:
                    break
                
                cursor = response.get('response_metadata', {}).get('next_cursor')
                if not cursor:
                    break
            
            # Slack returns newest first, reverse to get oldest first
            messages.reverse()
            
            # Add channel ID to each message (Slack API doesn't include it by default)
            for msg in messages:
                msg['channel'] = channel_id
            
            logger.info(f"Fetched {len(messages)} messages from channel {channel_id}")
            return messages
            
        except SlackApiError as e:
            logger.error(f"Error fetching messages: {e}")
            raise
    
    def filter_grafana_alerts(self, messages: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Filter messages to only include Grafana alert bot messages.
        
        Args:
            messages: List of Slack messages
            
        Returns:
            List of messages that are Grafana alerts.
        """
        grafana_messages = []
        
        for msg in messages:
            # Check if it's a bot message
            if msg.get('subtype') != 'bot_message':
                continue
            
            # Check username
            username = msg.get('username', '')
            if any(name.lower() in username.lower() for name in self.GRAFANA_BOT_NAMES):
                grafana_messages.append(msg)
                continue
            
            # Check for Grafana-specific attachment structure
            attachments = msg.get('attachments', [])
            if attachments:
                # Grafana alerts have specific footer
                footer = attachments[0].get('footer', '')
                if 'grafana' in footer.lower():
                    grafana_messages.append(msg)
                    continue
                
                # Check for Grafana-style title (X FIRING)
                title = attachments[0].get('title', '')
                if 'FIRING' in title or 'RESOLVED' in title:
                    grafana_messages.append(msg)
        
        logger.info(f"Filtered {len(grafana_messages)} Grafana alerts from {len(messages)} messages")
        return grafana_messages
    
    def post_message(
        self,
        channel_id: str,
        text: str,
        thread_ts: Optional[str] = None,
        blocks: Optional[List[Dict]] = None,
        attachments: Optional[List[Dict]] = None,
        unfurl_links: bool = False
    ) -> Dict[str, Any]:
        """
        Post a message to a Slack channel or thread.
        
        Args:
            channel_id: Slack channel ID
            text: Message text (fallback for notifications)
            thread_ts: Thread timestamp to reply to
            blocks: Slack Block Kit blocks
            attachments: Slack message attachments (legacy formatting)
            unfurl_links: Whether to unfurl links
            
        Returns:
            Slack API response with 'ts' (message timestamp) field.
        """
        try:
            kwargs = {
                'channel': channel_id,
                'text': text,
                'unfurl_links': unfurl_links
            }
            
            if thread_ts:
                kwargs['thread_ts'] = thread_ts
            
            if blocks:
                kwargs['blocks'] = blocks
            
            if attachments:
                kwargs['attachments'] = attachments
            
            response = self.client.chat_postMessage(**kwargs)
            logger.info(f"Posted message to {channel_id}" + (f" thread {thread_ts}" if thread_ts else ""))
            return response
            
        except SlackApiError as e:
            logger.error(f"Error posting message: {e}")
            raise
    
    def update_message(
        self,
        channel_id: str,
        message_ts: str,
        text: str,
        blocks: Optional[List[Dict]] = None
    ) -> Dict[str, Any]:
        """
        Update an existing message in Slack.
        
        Args:
            channel_id: Slack channel ID
            message_ts: Timestamp of the message to update
            text: New message text
            blocks: Optional new Slack Block Kit blocks
            
        Returns:
            Slack API response.
        """
        try:
            kwargs = {
                'channel': channel_id,
                'ts': message_ts,
                'text': text
            }
            
            if blocks:
                kwargs['blocks'] = blocks
            
            response = self.client.chat_update(**kwargs)
            logger.info(f"Updated message {message_ts} in {channel_id}")
            return response
            
        except SlackApiError as e:
            logger.error(f"Error updating message: {e}")
            raise
    
    def search_messages(
        self,
        query: str,
        channel_id: Optional[str] = None,
        days: int = 7,
        count: int = 20
    ) -> List[Dict[str, Any]]:
        """
        Search for messages in Slack.
        
        Args:
            query: Search query
            channel_id: Optional channel to limit search to
            days: Search messages from last N days
            count: Maximum results to return
            
        Returns:
            List of matching messages.
        """
        # Build search query
        search_query = query
        
        if channel_id:
            search_query = f"in:<#{channel_id}> {search_query}"
        
        # Add date filter
        after_date = (datetime.utcnow() - timedelta(days=days)).strftime('%Y-%m-%d')
        search_query = f"after:{after_date} {search_query}"
        
        try:
            response = self.client.search_messages(
                query=search_query,
                count=count,
                sort='timestamp',
                sort_dir='desc'
            )
            
            messages = response.get('messages', {}).get('matches', [])
            logger.info(f"Found {len(messages)} messages for query: {query}")
            return messages
            
        except SlackApiError as e:
            logger.error(f"Error searching messages: {e}")
            # Search API requires specific scopes, may not be available
            return []
    
    def get_thread_replies(
        self,
        channel_id: str,
        thread_ts: str,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """
        Get all replies in a thread.
        
        Args:
            channel_id: Slack channel ID
            thread_ts: Thread timestamp
            limit: Maximum replies to fetch
            
        Returns:
            List of messages in the thread.
        """
        try:
            response = self._call_with_rate_limit_handling(
                self.client.conversations_replies,
                channel=channel_id,
                ts=thread_ts,
                limit=limit
            )
            
            messages = response.get('messages', [])
            logger.info(f"Fetched {len(messages)} messages from thread {thread_ts}")
            return messages
            
        except SlackApiError as e:
            logger.error(f"Error fetching thread replies: {e}")
            return []
    
    def add_reaction(
        self,
        channel_id: str,
        timestamp: str,
        reaction: str
    ) -> bool:
        """
        Add a reaction emoji to a message.
        
        Args:
            channel_id: Slack channel ID
            timestamp: Message timestamp
            reaction: Emoji name (without colons)
            
        Returns:
            True if successful.
        """
        try:
            self.client.reactions_add(
                channel=channel_id,
                timestamp=timestamp,
                name=reaction
            )
            return True
        except SlackApiError as e:
            if e.response.get('error') == 'already_reacted':
                return True  # Already has the reaction
            logger.error(f"Error adding reaction: {e}")
            return False


def build_enrichment_blocks(
    title: str,
    severity: str,
    evidence: Dict[str, Any],
    recommendations: List[str],
    links: Dict[str, str],
    duplicate_count: int = 0,
    strategy: str = "New Alert"
) -> List[Dict[str, Any]]:
    """
    Build Slack Block Kit blocks for an enriched alert message.
    
    Args:
        title: Alert title
        severity: Alert severity (critical, high, medium, low)
        evidence: Evidence gathered from various sources
        recommendations: List of recommended actions
        links: Dictionary of link label -> URL
        duplicate_count: Number of duplicate alerts consolidated
        strategy: Enrichment strategy used
        
    Returns:
        List of Slack Block Kit blocks.
    """
    # Severity emoji mapping
    severity_emoji = {
        'critical': '🔴',
        'high': '🟠',
        'medium': '🟡',
        'low': '🟢'
    }.get(severity.lower(), '⚪')
    
    # Strategy emoji mapping
    strategy_emoji = {
        'Recurring Alert': '🔄',
        'Likely Regression': '🐛',
        'Known Issue': '📋',
        'Duplicate Alert': '🔁',
        'New Alert': '🚨',
        'Consolidated Alert': '🔄'
    }.get(strategy, '🔍')
    
    blocks = []
    
    # Header
    header_text = f"{strategy_emoji} {strategy}: {title}"
    if duplicate_count > 0:
        header_text += f" ({duplicate_count + 1} occurrences)"
    
    blocks.append({
        "type": "header",
        "text": {
            "type": "plain_text",
            "text": header_text[:150],  # Slack limit
            "emoji": True
        }
    })
    
    # Context line
    context_parts = [f"*Severity:* {severity_emoji} {severity.capitalize()}"]
    if evidence.get('service'):
        context_parts.append(f"*Service:* {evidence['service']}")
    if evidence.get('customer'):
        context_parts.append(f"*Customer:* {evidence['customer']}")
    
    blocks.append({
        "type": "context",
        "elements": [{
            "type": "mrkdwn",
            "text": " | ".join(context_parts)
        }]
    })
    
    blocks.append({"type": "divider"})
    
    # Evidence section
    evidence_text = "*🔍 Evidence*\n\n"
    
    if evidence.get('metrics'):
        evidence_text += "*Metrics:*\n"
        metrics = evidence['metrics']
        # Handle both list and dict formats
        if isinstance(metrics, dict):
            for key, value in list(metrics.items())[:5]:
                evidence_text += f"• {key}: {value}\n"
        elif isinstance(metrics, list):
            for metric in metrics[:5]:
                evidence_text += f"• {metric}\n"
        else:
            evidence_text += f"• {metrics}\n"
        evidence_text += "\n"
    
    if evidence.get('logs'):
        evidence_text += "*Logs:*\n"
        logs = evidence['logs']
        # Handle both list and dict formats
        if isinstance(logs, dict):
            for key, value in list(logs.items())[:3]:
                evidence_text += f"• `{str(value)[:100]}`\n"
        elif isinstance(logs, list):
            for log in logs[:3]:
                evidence_text += f"• `{str(log)[:100]}`\n"
        else:
            evidence_text += f"• `{str(logs)[:100]}`\n"
        evidence_text += "\n"
    
    # Regression Candidate (highlighted for "Likely Regression" strategy)
    if evidence.get('regression_candidate'):
        rc = evidence['regression_candidate']
        if isinstance(rc, dict):
            # Map confidence to emoji
            confidence = rc.get('confidence', 'unknown')
            confidence_emoji = {"high": "🔴", "medium": "🟠", "low": "🟡"}.get(confidence, "⚪")
            evidence_text += f"*{confidence_emoji} REGRESSION SUSPECT ({confidence} confidence):*\n"
            
            pr_num = rc.get('pr_number', 'N/A')
            pr_title = rc.get('pr_title', 'Unknown PR')
            author = rc.get('author', 'Unknown')
            pr_url = rc.get('url', f"https://github.com/apiiro/lim/pull/{pr_num}")
            
            # Include hyperlink inline
            evidence_text += f"• *<{pr_url}|PR #{pr_num}>*: {pr_title[:80]}\n"
            evidence_text += f"• Author: {author}\n"
            
            # Show signals (new format) or fallback to why (old format)
            signals = rc.get('signals', [])
            if signals:
                # Handle signals as list of strings or list of dicts
                if isinstance(signals, list):
                    signal_strs = []
                    for s in signals[:3]:
                        if isinstance(s, dict):
                            signal_strs.append(str(s.get('description', s.get('name', str(s)))))
                        else:
                            signal_strs.append(str(s))
                    evidence_text += f"• Signals: {'; '.join(signal_strs)}\n"
                else:
                    evidence_text += f"• Signals: {str(signals)}\n"
            elif rc.get('why'):
                evidence_text += f"• Why: {rc['why']}\n"
            
            evidence_text += "\n"
        else:
            # Legacy string format
            evidence_text += f"*🔴 REGRESSION SUSPECT:* {rc}\n\n"
    
    if evidence.get('related_tickets'):
        evidence_text += "*Related Tickets:*\n"
        for ticket in evidence['related_tickets'][:3]:
            # Check if ticket is a string (might be "KEY: Summary" format) or dict
            if isinstance(ticket, dict):
                ticket_key = ticket.get('key', 'Unknown')
                ticket_url = ticket.get('url', f"https://apiiro.atlassian.net/browse/{ticket_key}")
                ticket_summary = ticket.get('summary', '')[:50]
                evidence_text += f"• <{ticket_url}|{ticket_key}>: {ticket_summary}...\n"
            elif isinstance(ticket, str):
                # Try to parse "KEY: Summary" or "KEY - Summary" format and add hyperlink
                import re
                match = re.match(r'^([A-Z]+-\d+)[:\s-]+(.*)$', ticket)
                if match:
                    key, summary = match.groups()
                    url = f"https://apiiro.atlassian.net/browse/{key}"
                    evidence_text += f"• <{url}|{key}>: {summary}\n"
                else:
                    evidence_text += f"• {ticket}\n"
            else:
                evidence_text += f"• {ticket}\n"
        evidence_text += "\n"
    
    if evidence.get('previous_discussions'):
        import re
        evidence_text += "*Previous Discussions:*\n"
        for disc in evidence['previous_discussions'][:2]:
            # Claude may include links in various formats - preserve Slack markdown links
            # Format 1: Already Slack formatted: (<url|text>)
            # Format 2: Plain URL: https://apiiro.slack.com/archives/...
            # Format 3: Markdown: [text](url)
            
            formatted_disc = disc
            
            # Convert markdown links [text](url) to Slack format <url|text>
            markdown_links = re.findall(r'\[([^\]]+)\]\((https?://[^\)]+)\)', formatted_disc)
            for text, url in markdown_links:
                formatted_disc = formatted_disc.replace(f'[{text}]({url})', f'<{url}|{text}>')
            
            # Convert plain Slack URLs to clickable links (if not already formatted)
            # Match Slack archive URLs that aren't already in <url|text> format
            plain_urls = re.findall(r'(?<![<|])(https://[a-z]+\.slack\.com/archives/[A-Z0-9]+/p\d+)(?![>|])', formatted_disc)
            for url in plain_urls:
                formatted_disc = formatted_disc.replace(url, f'<{url}|view thread>')
            
            evidence_text += f"• {formatted_disc}\n"
        evidence_text += "\n"
    
    # Correlated Alerts (detected by Claude from cross-channel context)
    if evidence.get('correlated_alerts'):
        import re
        corr_alerts = evidence['correlated_alerts']
        
        # Handle various formats
        if isinstance(corr_alerts, str):
            # Try to parse if it's JSON
            try:
                import json
                corr_alerts = json.loads(corr_alerts)
            except (json.JSONDecodeError, TypeError):
                corr_alerts = [corr_alerts]
        
        # If it's a dict (single alert), wrap in list
        if isinstance(corr_alerts, dict):
            corr_alerts = [corr_alerts]
        
        # If it's not a list at this point, skip
        if not isinstance(corr_alerts, list):
            logger.warning(f"Unexpected correlated_alerts type: {type(corr_alerts)}")
        else:
            evidence_text += "*🔗 Correlated Alerts:*\n"
            for corr in corr_alerts[:3]:
                # Handle dict format from DSPy
                if isinstance(corr, dict):
                    alert_name = corr.get('name', corr.get('alertname', 'Unknown Alert'))
                    labels = corr.get('labels', {})
                    state = corr.get('state', '')
                    formatted_corr = f"{alert_name}"
                    if isinstance(labels, dict) and labels.get('resource.label.namespace_name'):
                        formatted_corr += f" (namespace: {labels['resource.label.namespace_name']})"
                    if state:
                        formatted_corr += f" [{state}]"
                elif isinstance(corr, str):
                    # Try to parse string as JSON dict
                    try:
                        import json
                        corr_obj = json.loads(corr)
                        if isinstance(corr_obj, dict):
                            alert_name = corr_obj.get('name', corr_obj.get('alertname', 'Unknown Alert'))
                            labels = corr_obj.get('labels', {})
                            state = corr_obj.get('state', '')
                            formatted_corr = f"{alert_name}"
                            if isinstance(labels, dict) and labels.get('resource.label.namespace_name'):
                                formatted_corr += f" (namespace: {labels['resource.label.namespace_name']})"
                            if state:
                                formatted_corr += f" [{state}]"
                        else:
                            formatted_corr = corr
                    except (json.JSONDecodeError, TypeError):
                        formatted_corr = corr
                else:
                    formatted_corr = str(corr)
                
                # Convert markdown links [text](url) to Slack format <url|text>
                markdown_links = re.findall(r'\[([^\]]+)\]\((https?://[^\)]+)\)', formatted_corr)
                for text, url in markdown_links:
                    formatted_corr = formatted_corr.replace(f'[{text}]({url})', f'<{url}|{text}>')
                
                # Convert plain Slack URLs to clickable links (if not already formatted)
                plain_urls = re.findall(r'(?<![<|])(https://[a-z]+\.slack\.com/archives/[A-Z0-9]+/p\d+)(?![>|])', formatted_corr)
                for url in plain_urls:
                    formatted_corr = formatted_corr.replace(url, f'<{url}|view thread>')
                
                evidence_text += f"• {formatted_corr}\n"
            evidence_text += "\n"
    
    # Recent Changes (detected by Claude: feature flags, deployments)
    if evidence.get('recent_changes'):
        changes = evidence['recent_changes']
        # Handle both list and string formats
        if isinstance(changes, str):
            changes = [changes]
        evidence_text += "*⚡ Recent Changes:*\n"
        for change in changes[:3]:
            evidence_text += f"• {change}\n"
        evidence_text += "\n"
    
    blocks.append({
        "type": "section",
        "text": {
            "type": "mrkdwn",
            "text": evidence_text[:3000]  # Slack limit
        }
    })
    
    blocks.append({"type": "divider"})
    
    # Recommendations section
    if recommendations:
        import re
        rec_text = "*✅ Recommended Actions*\n\n"
        for i, rec in enumerate(recommendations[:5], 1):
            # Convert PR references to hyperlinks: "PR #1234" -> "<url|PR #1234>"
            rec_with_links = rec
            pr_matches = re.findall(r'\bPR #(\d+)\b', rec)
            for pr_num in pr_matches:
                pr_url = f"https://github.com/apiiro/lim/pull/{pr_num}"
                rec_with_links = rec_with_links.replace(f"PR #{pr_num}", f"<{pr_url}|PR #{pr_num}>")
            
            # Convert Jira references to hyperlinks: "SUP-1234" or "LIM-1234" -> "<url|KEY>"
            jira_matches = re.findall(r'\b([A-Z]+-\d+)\b', rec_with_links)
            for jira_key in jira_matches:
                if not jira_key.startswith('PR-'):  # Avoid matching PR-# patterns
                    jira_url = f"https://apiiro.atlassian.net/browse/{jira_key}"
                    rec_with_links = rec_with_links.replace(jira_key, f"<{jira_url}|{jira_key}>")
            
            rec_text += f"{i}. {rec_with_links}\n"
        
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": rec_text
            }
        })
    
    # Links section
    if links:
        links_text = "*🔗 Resources*\n"
        for label, url in list(links.items())[:6]:
            links_text += f"• <{url}|{label}>\n"
        
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": links_text
            }
        })
    
    return blocks


if __name__ == '__main__':
    # Test the client (requires ALERTS_ENRICHER_SLACK_BOT_TOKEN)
    import sys
    
    if not os.getenv('ALERTS_ENRICHER_SLACK_BOT_TOKEN') and not os.getenv('SLACK_BOT_TOKEN'):
        print("Set ALERTS_ENRICHER_SLACK_BOT_TOKEN to test")
        sys.exit(1)
    
    client = SlackClient()
    channel = os.getenv('SLACK_CHANNEL_ID', 'C067CV07KQ8')
    
    print(f"Bot user ID: {client.bot_user_id}")
    
    messages = client.fetch_messages_since(channel, minutes=60)
    print(f"Fetched {len(messages)} messages")
    
    grafana_alerts = client.filter_grafana_alerts(messages)
    print(f"Found {len(grafana_alerts)} Grafana alerts")

