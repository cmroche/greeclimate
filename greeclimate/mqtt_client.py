"""Gree Cloud MQTT Client

Controls devices via Gree Cloud MQTT broker.

Based on PCAP analysis of Gree+ app:
- Server: mqtt.gree.com:8883 (TLS)
- Protocol: MQTT 3.1.1
- Authentication: username=userId, password=token
- Topics:
  - request/{device_mac} - send commands to device
  - response/{device_mac}/# - receive responses from device
  - status/{device_mac}/# - receive status updates
  - connect/{device_mac} - device connection status

Message format (JSON):
{
  "cid": "[random_client_id]",
  "i": [sequence_number],
  "pack": "[base64_aes_encrypted_payload]",
  "t": "pack",
  "tcid": "[target_device_mac]",
  "uid": [user_id]
}
"""

import asyncio
import json
import logging
import random
import ssl
from typing import Optional, Callable, Any, Dict
from dataclasses import dataclass

try:
    import aiomqtt
except ImportError:
    import asyncio_mqtt as aiomqtt

_LOGGER = logging.getLogger(__name__)


@dataclass
class MqttDeviceMessage:
    """MQTT device message structure"""
    cid: str
    i: int
    pack: str
    t: str
    tcid: str
    uid: int
    tag: Optional[str] = None
    ts: Optional[int] = None
    extras: Optional[Dict] = None


class GreeMqttClient:
    """Gree Cloud MQTT Client

    Handles MQTT communication with Gree Cloud broker for device control.
    """

    # MQTT broker settings per region
    MQTT_SERVERS = {
        'Australia': 'mqtt-au.gree.com',
        'China Mainland': 'mqtt.gree.com',
        'East South Asia': 'mqtt-as.gree.com',
        'Europe': 'mqtt-eu.gree.com',
        'India': 'mqtt-in.gree.com',
        'Latin American': 'mqtt-la.gree.com',
        'Middle East': 'mqtt-me.gree.com',
        'North American': 'mqtt-na.gree.com',
        'Russia': 'mqtt-ru.gree.com',
        'South American': 'mqtt-sa.gree.com',
    }

    def __init__(
        self,
        user_id: int,
        token: str,
        server: str = 'mqtt-eu.gree.com',
        port: int = 1984,
        keepalive: int = 60
    ):
        """Initialize MQTT client

        Args:
            user_id: Gree Cloud user ID from login
            token: Gree Cloud token from login
            server: MQTT broker hostname (default: mqtt-eu.gree.com)
            port: MQTT broker port (1984 for TLS, not 8883!)
            keepalive: MQTT keepalive interval in seconds
        """
        self.user_id = user_id
        self.token = token
        self.server = server
        self.port = port
        self.keepalive = keepalive

        # Generate random client ID (similar to Gree+ app)
        self.client_id = self._generate_client_id()

        self._client: Optional[aiomqtt.Client] = None
        self._connected = False
        self._message_handlers: Dict[str, Callable] = {}
        self._receive_task: Optional[asyncio.Task] = None

    def _generate_client_id(self) -> str:
        """Generate random client ID"""
        return f"app_{random.getrandbits(64):016x}"

    async def connect(self) -> None:
        """Connect to MQTT broker"""
        if self._connected:
            return

        try:
            # The Gree broker presents a custom cert, so verification is disabled
            # anyway. Building the context directly avoids create_default_context(),
            # whose load_default_certs() does blocking file I/O -- Home Assistant
            # flags that when connect() runs inside the event loop.
            tls_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            tls_context.check_hostname = False
            tls_context.verify_mode = ssl.CERT_NONE

            # Use MQTT v3.1.1 protocol (Gree Cloud requirement)
            import paho.mqtt.client as mqtt

            _LOGGER.debug(f"Connecting to MQTT broker {self.server}:{self.port}")

            self._client = aiomqtt.Client(
                hostname=self.server,
                port=self.port,
                username=str(self.user_id),
                password=self.token,
                identifier=self.client_id,
                keepalive=self.keepalive,
                protocol=mqtt.MQTTv311,  # Gree uses MQTT v3.1.1
                clean_session=True,  # For MQTT v3.1.1
                tls_context=tls_context,
                timeout=30.0,  # 30 second connect timeout
            )

            await self._client.__aenter__()
            self._connected = True

            # Start message receiving task
            self._receive_task = asyncio.create_task(self._receive_messages())

            _LOGGER.info(f"Connected to MQTT broker {self.server}:{self.port}")

        except Exception as e:
            _LOGGER.error(f"Failed to connect to MQTT broker: {e}")
            raise

    async def disconnect(self) -> None:
        """Disconnect from MQTT broker"""
        if not self._connected:
            return

        # Cancel receive task
        if self._receive_task:
            self._receive_task.cancel()
            try:
                await self._receive_task
            except asyncio.CancelledError:
                pass

        # Close MQTT client
        if self._client:
            try:
                await self._client.__aexit__(None, None, None)
            except Exception as e:
                _LOGGER.warning(f"Error closing MQTT client: {e}")
            finally:
                self._client = None

        self._connected = False
        _LOGGER.info("Disconnected from MQTT broker")

    async def subscribe_to_device(self, device_mac: str) -> None:
        """Subscribe to device topics

        Args:
            device_mac: Device MAC address (without colons)
        """
        if not self._connected:
            raise Exception("Not connected to MQTT broker")

        # Detect parent MAC for parent/child devices
        parent_mac = self._detect_parent_mac(device_mac)

        topics = [
            f"response/{parent_mac}/#",
            f"status/{parent_mac}/#",
            f"connect/{parent_mac}",
        ]

        for topic in topics:
            await self._client.subscribe(topic, qos=1)
            _LOGGER.debug(f"Subscribed to topic: {topic}")

    async def unsubscribe_from_device(self, device_mac: str) -> None:
        """Unsubscribe from device topics

        Args:
            device_mac: Device MAC address (without colons)
        """
        if not self._connected:
            raise Exception("Not connected to MQTT broker")

        parent_mac = self._detect_parent_mac(device_mac)

        topics = [
            f"response/{parent_mac}/#",
            f"status/{parent_mac}/#",
            f"connect/{parent_mac}",
        ]

        for topic in topics:
            await self._client.unsubscribe(topic)
            _LOGGER.debug(f"Unsubscribed from topic: {topic}")

    async def publish_command(
        self,
        device_mac: str,
        command: Dict[str, Any],
        cipher: Any,
        target_device_mac: Optional[str] = None
    ) -> None:
        """Publish command to device

        Args:
            device_mac: Device MAC address (used for topic)
            command: Command payload (will be encrypted)
            cipher: Cipher instance (CipherV1 or CipherV2)
            target_device_mac: Optional target device MAC for child devices (used in tcid)
        """
        if not self._connected:
            raise Exception("Not connected to MQTT broker")

        # Encrypt command
        encrypted_result = cipher.encrypt(command)
        if isinstance(encrypted_result, tuple):
            encrypted, tag = encrypted_result
        else:
            encrypted = encrypted_result
            tag = None

        # Detect parent MAC for topic
        parent_mac = self._detect_parent_mac(device_mac)

        # Create message
        message = {
            'cid': str(random.randint(1000000000, 9999999999)),
            'i': 0,
            'pack': encrypted,
            't': 'pack',
            'tcid': target_device_mac or device_mac,
            'uid': self.user_id,
        }

        # Add tag if present (GCM encryption)
        if tag:
            message['tag'] = tag

        topic = f"request/{parent_mac}"
        payload = json.dumps(message)

        _LOGGER.debug(f"Publishing to {topic}: {message.get('cid')}")
        await self._client.publish(topic, payload, qos=1)

    def add_message_handler(self, handler: Callable[[str, MqttDeviceMessage], None]) -> None:
        """Add message handler

        Args:
            handler: Callback function that receives (topic, message)
        """
        handler_id = id(handler)
        self._message_handlers[handler_id] = handler

    def remove_message_handler(self, handler: Callable) -> None:
        """Remove message handler

        Args:
            handler: Previously added handler function
        """
        handler_id = id(handler)
        if handler_id in self._message_handlers:
            del self._message_handlers[handler_id]

    async def _receive_messages(self) -> None:
        """Receive and process MQTT messages"""
        try:
            async for message in self._client.messages:
                try:
                    topic = message.topic.value if hasattr(message.topic, 'value') else str(message.topic)
                    payload = json.loads(message.payload.decode())

                    # Convert to MqttDeviceMessage
                    msg = MqttDeviceMessage(
                        cid=payload.get('cid', ''),
                        i=payload.get('i', 0),
                        pack=payload.get('pack', ''),
                        t=payload.get('t', ''),
                        tcid=payload.get('tcid', ''),
                        uid=payload.get('uid', 0),
                        tag=payload.get('tag'),
                        ts=payload.get('ts'),
                        extras=payload.get('extras')
                    )

                    _LOGGER.debug(f"Received message on {topic}")

                    # Call all registered handlers
                    for handler in self._message_handlers.values():
                        try:
                            handler(topic, msg)
                        except Exception as e:
                            _LOGGER.exception(f"Error in message handler: {e}")

                except json.JSONDecodeError as e:
                    _LOGGER.error(f"Failed to parse MQTT message: {e}")
                except Exception as e:
                    _LOGGER.exception(f"Error processing MQTT message: {e}")

        except asyncio.CancelledError:
            _LOGGER.debug("Message receive task cancelled")
            raise
        except Exception as e:
            _LOGGER.exception(f"Error in message receive loop: {e}")

    def _detect_parent_mac(self, mac: str) -> str:
        """Detect parent MAC from child MAC

        For devices ending with '00' and longer than 12 chars, strip last 2 chars.
        This handles parent/child device hierarchy for commercial units.

        Args:
            mac: Device MAC address

        Returns:
            Parent MAC address
        """
        if mac.endswith('00') and len(mac) > 12:
            return mac[:-2]
        return mac

    @property
    def is_connected(self) -> bool:
        """Check if connected to MQTT broker"""
        return self._connected and self._client is not None

    def get_client_id(self) -> str:
        """Get current client ID"""
        return self.client_id
