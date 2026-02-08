"""
Infrastructure Layer - Outbox Processor

The Outbox Processor is a background worker that:
1. Polls the outbox table for unpublished events
2. Publishes events to RabbitMQ
3. Marks events as published

This implements the "Transactional Outbox" pattern for reliable
message delivery with at-least-once semantics.
"""

import asyncio
import logging
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any
import json

from ..application.ports import OutboxRepository, EventPublisher


logger = logging.getLogger(__name__)


class OutboxProcessor:
    """
    Background processor for publishing events from the outbox.
    
    Implements:
    - Polling-based consumption
    - Batched publishing for efficiency
    - Retry with exponential backoff
    - Dead letter handling after max retries
    - Cleanup of old published messages
    
    Usage:
        processor = OutboxProcessor(outbox_repo, event_publisher)
        await processor.start()  # Runs until stopped
    """
    
    def __init__(
        self,
        outbox_repository: OutboxRepository,
        event_publisher: EventPublisher,
        poll_interval_seconds: float = 1.0,
        batch_size: int = 100,
        max_retries: int = 5,
        cleanup_interval_hours: int = 24,
        retention_hours: int = 72,
    ):
        self.outbox = outbox_repository
        self.publisher = event_publisher
        self.poll_interval = poll_interval_seconds
        self.batch_size = batch_size
        self.max_retries = max_retries
        self.cleanup_interval = timedelta(hours=cleanup_interval_hours)
        self.retention_period = timedelta(hours=retention_hours)
        
        self._running = False
        self._last_cleanup = datetime.min
    
    async def start(self) -> None:
        """Start the processor loop."""
        logger.info("Starting outbox processor")
        self._running = True
        
        while self._running:
            try:
                # Process pending messages
                processed = await self._process_batch()
                
                # Cleanup old messages periodically
                if datetime.utcnow() - self._last_cleanup > self.cleanup_interval:
                    await self._cleanup_old_messages()
                    self._last_cleanup = datetime.utcnow()
                
                # If no messages processed, wait before next poll
                if processed == 0:
                    await asyncio.sleep(self.poll_interval)
                    
            except Exception as e:
                logger.error(f"Error in outbox processor: {e}")
                await asyncio.sleep(self.poll_interval * 2)  # Back off on error
    
    async def stop(self) -> None:
        """Stop the processor gracefully."""
        logger.info("Stopping outbox processor")
        self._running = False
    
    async def _process_batch(self) -> int:
        """Process a batch of unpublished messages. Returns count processed."""
        # Check if publisher is connected
        if not await self.publisher.is_connected():
            logger.warning("Event publisher not connected, skipping batch")
            return 0
        
        # Get unpublished messages
        messages = await self.outbox.get_unpublished(self.batch_size)
        if not messages:
            return 0
        
        logger.debug(f"Processing {len(messages)} outbox messages")
        
        published_ids = []
        
        for message in messages:
            try:
                # Skip if max retries exceeded
                if message.get('retry_count', 0) >= self.max_retries:
                    logger.error(
                        f"Message {message['id']} exceeded max retries, "
                        f"moving to dead letter"
                    )
                    await self._handle_dead_letter(message)
                    published_ids.append(message['id'])  # Remove from outbox
                    continue
                
                # Publish event
                await self._publish_message(message)
                published_ids.append(message['id'])
                
            except Exception as e:
                logger.error(f"Failed to publish message {message['id']}: {e}")
                await self._handle_publish_error(message, str(e))
        
        # Mark successfully published
        if published_ids:
            await self.outbox.mark_as_published(published_ids)
            logger.info(f"Published {len(published_ids)} events")
        
        return len(published_ids)
    
    async def _publish_message(self, message: Dict[str, Any]) -> None:
        """Publish a single message to the event publisher."""
        event_type = message['event_type']
        payload = message['payload']
        
        # Reconstruct event for publishing
        # The payload already contains the full event data
        await self.publisher.publish_raw(
            event_type=event_type,
            payload=payload,
        )
    
    async def _handle_publish_error(self, message: Dict[str, Any], error: str) -> None:
        """Handle a publish error by incrementing retry count."""
        await self.outbox.increment_retry(message['id'], error)
    
    async def _handle_dead_letter(self, message: Dict[str, Any]) -> None:
        """Handle a message that has exceeded max retries."""
        # In a production system, you might:
        # - Move to a dead letter queue/table
        # - Send an alert
        # - Log for manual review
        logger.error(
            f"Dead letter: event_type={message['event_type']}, "
            f"aggregate={message['aggregate_type']}/{message['aggregate_id']}, "
            f"error={message.get('last_error', 'unknown')}"
        )
    
    async def _cleanup_old_messages(self) -> None:
        """Clean up old published messages."""
        cutoff = datetime.utcnow() - self.retention_period
        deleted = await self.outbox.delete_published(cutoff)
        if deleted > 0:
            logger.info(f"Cleaned up {deleted} old outbox messages")


class RabbitMQEventPublisher(EventPublisher):
    """
    RabbitMQ implementation of EventPublisher.
    
    Publishes events to a RabbitMQ exchange for consumption
    by interested services.
    """
    
    def __init__(
        self,
        connection_url: str,
        exchange_name: str = "deployguard.events",
    ):
        self.connection_url = connection_url
        self.exchange_name = exchange_name
        self._connection = None
        self._channel = None
    
    async def connect(self) -> None:
        """Establish connection to RabbitMQ."""
        import aio_pika
        
        self._connection = await aio_pika.connect_robust(self.connection_url)
        self._channel = await self._connection.channel()
        
        # Declare exchange
        await self._channel.declare_exchange(
            self.exchange_name,
            aio_pika.ExchangeType.TOPIC,
            durable=True,
        )
        
        logger.info(f"Connected to RabbitMQ exchange: {self.exchange_name}")
    
    async def disconnect(self) -> None:
        """Close connection to RabbitMQ."""
        if self._channel:
            await self._channel.close()
        if self._connection:
            await self._connection.close()
        logger.info("Disconnected from RabbitMQ")
    
    async def is_connected(self) -> bool:
        """Check if connected to RabbitMQ."""
        return (
            self._connection is not None
            and not self._connection.is_closed
        )
    
    async def publish(self, event: 'DomainEvent') -> None:
        """Publish a domain event."""
        await self.publish_raw(
            event_type=event.event_type,
            payload=event.to_dict(),
        )
    
    async def publish_batch(self, events: List['DomainEvent']) -> None:
        """Publish multiple events."""
        for event in events:
            await self.publish(event)
    
    async def publish_raw(self, event_type: str, payload: Dict[str, Any]) -> None:
        """Publish raw event data."""
        import aio_pika
        
        if not await self.is_connected():
            await self.connect()
        
        # Routing key based on event type
        # e.g., "job.created", "job.scan.completed"
        routing_key = self._event_type_to_routing_key(event_type)
        
        message = aio_pika.Message(
            body=json.dumps(payload).encode(),
            content_type="application/json",
            delivery_mode=aio_pika.DeliveryMode.PERSISTENT,
        )
        
        exchange = await self._channel.get_exchange(self.exchange_name)
        await exchange.publish(message, routing_key=routing_key)
        
        logger.debug(f"Published event: {event_type} -> {routing_key}")
    
    def _event_type_to_routing_key(self, event_type: str) -> str:
        """Convert event type to routing key."""
        # JobCreatedEvent -> job.created
        # ScanCompletedEvent -> scan.completed
        import re
        
        # Remove 'Event' suffix
        name = event_type.replace("Event", "")
        
        # Convert CamelCase to dot.separated.lowercase
        s1 = re.sub('(.)([A-Z][a-z]+)', r'\1.\2', name)
        return re.sub('([a-z0-9])([A-Z])', r'\1.\2', s1).lower()
