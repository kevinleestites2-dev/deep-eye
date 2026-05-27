"""
Test Notification System
Tests Discord, Slack, and Email notifications
"""

import sys
import os
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from utils.config_loader import ConfigLoader
from utils.notification_manager import NotificationManager
from utils.logger import get_logger
from datetime import datetime

logger = get_logger(__name__)


def test_scan_complete_notification(config_path: str = "config/config.yaml"):
    """Test scan completion notification."""
    print("=" * 60)
    print("Testing Scan Completion Notification")
    print("=" * 60)

    try:
        # Load config
        config = ConfigLoader.load(config_path)
        notification_manager = NotificationManager(config)

        # Check if notifications are enabled
        if not notification_manager.enabled:
            print("\n❌ Notifications are DISABLED in config")
            print("   Set notifications.enabled = true in config.yaml\n")
            return False

        print(f"\n✓ Notifications enabled: {notification_manager.enabled}")

        # Check Discord configuration
        discord_config = config.get('notifications', {}).get('discord', {})
        print(f"✓ Discord enabled: {discord_config.get('enabled', False)}")
        webhook_url = discord_config.get('webhook_url', '')
        if webhook_url:
            print(f"✓ Discord webhook URL: {webhook_url[:50]}...")
        else:
            print("❌ Discord webhook URL not configured")

        # Prepare test data
        test_results = {
            'target': 'https://example.com',
            'start_time': '2024-01-01T12:00:00',
            'end_time': '2024-01-01T12:30:00',
            'duration': '0:30:00',
            'urls_crawled': 42,
            'vulnerabilities': [
                {'severity': 'critical'},
                {'severity': 'critical'},
                {'severity': 'high'},
                {'severity': 'high'},
                {'severity': 'high'},
                {'severity': 'medium'},
                {'severity': 'low'},
            ],
            'severity_summary': {
                'critical': 2,
                'high': 3,
                'medium': 1,
                'low': 1,
                'info': 0
            }
        }

        print("\nSending test notification...")
        print(f"  Target: {test_results['target']}")
        print(f"  Vulnerabilities: {len(test_results['vulnerabilities'])}")
        print(f"  Critical: {test_results['severity_summary']['critical']}")
        print(f"  High: {test_results['severity_summary']['high']}")

        # Send notification
        success = notification_manager.send_scan_complete(test_results)

        if success:
            print("\n✅ Test notification sent successfully!")
            print("   Check your Discord channel for the message.")
            return True
        else:
            print("\n❌ Failed to send test notification")
            print("   Check logs for error details")
            return False

    except FileNotFoundError:
        print(f"\n❌ Config file not found: {config_path}")
        print("   Copy config.example.yaml to config.yaml and configure it")
        return False
    except Exception as e:
        print(f"\n❌ Error: {e}")
        logger.exception("Test failed:")
        return False


def test_critical_vulnerability_notification(config_path: str = "config/config.yaml"):
    """Test critical vulnerability alert."""
    print("\n" + "=" * 60)
    print("Testing Critical Vulnerability Alert")
    print("=" * 60)

    try:
        # Load config
        config = ConfigLoader.load(config_path)
        notification_manager = NotificationManager(config)

        if not notification_manager.enabled:
            print("\n❌ Notifications are DISABLED in config")
            return False

        # Prepare test vulnerability
        test_vulnerability = {
            'type': 'SQL Injection',
            'severity': 'critical',
            'url': 'https://example.com/login?user=admin',
            'parameter': 'user',
            'payload': "admin' OR '1'='1--",
            'evidence': 'MySQL error: You have an error in your SQL syntax...',
        }

        print("\nSending test critical alert...")
        print(f"  Type: {test_vulnerability['type']}")
        print(f"  Severity: {test_vulnerability['severity']}")
        print(f"  URL: {test_vulnerability['url']}")

        # Send notification
        success = notification_manager.send_critical_vulnerability(
            test_vulnerability,
            'https://example.com'
        )

        if success:
            print("\n✅ Test critical alert sent successfully!")
            print("   Check your Discord channel for the @here mention.")
            return True
        else:
            print("\n❌ Failed to send test critical alert")
            return False

    except Exception as e:
        print(f"\n❌ Error: {e}")
        logger.exception("Test failed:")
        return False


def print_configuration_guide():
    """Print configuration guide."""
    print("\n" + "=" * 60)
    print("Discord Notification Configuration Guide")
    print("=" * 60)
    print("""
1. Create a Discord Webhook:
   - Open Discord Server Settings
   - Go to Integrations → Webhooks
   - Click "New Webhook"
   - Choose the channel for notifications
   - Copy the Webhook URL

2. Configure config.yaml:

   notifications:
     enabled: true  # Enable notifications
     notify_on_critical: true  # Enable critical alerts

     discord:
       enabled: true  # Enable Discord
       webhook_url: "https://discord.com/api/webhooks/YOUR/WEBHOOK/URL"
       username: "Deep Eye Scanner"  # Optional
       avatar_url: ""  # Optional

3. Test the configuration:
   python scripts/test_notifications.py

Common Issues:
- Webhook URL is invalid or expired
- notifications.enabled = false (not enabled)
- discord.enabled = false (not enabled)
- Firewall blocking outgoing HTTPS connections
- Invalid Discord webhook permissions
""")


def main():
    """Main test function."""
    print("""
╔═══════════════════════════════════════════════════════════╗
║       Discord Notification Test Script                    ║
║       Deep Eye Security Scanner                           ║
╚═══════════════════════════════════════════════════════════╝
""")

    # Check if config exists
    config_path = "config/config.yaml"
    if not Path(config_path).exists():
        print(f"❌ Config file not found: {config_path}")
        print("   Copy config.example.yaml to config.yaml")
        print_configuration_guide()
        return

    # Test scan completion notification
    success1 = test_scan_complete_notification(config_path)

    # Test critical vulnerability notification
    success2 = test_critical_vulnerability_notification(config_path)

    # Summary
    print("\n" + "=" * 60)
    print("Test Summary")
    print("=" * 60)
    print(f"Scan completion notification: {'✅ PASSED' if success1 else '❌ FAILED'}")
    print(f"Critical alert notification: {'✅ PASSED' if success2 else '❌ FAILED'}")

    if success1 or success2:
        print("\n✅ At least one test passed! Check your Discord channel.")
    else:
        print("\n❌ All tests failed. See errors above.")
        print_configuration_guide()


if __name__ == "__main__":
    main()
