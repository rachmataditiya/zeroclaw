//! AMQP/RabbitMQ event source implementation.
//!
//! Connects to a RabbitMQ broker, consumes messages from a queue,
//! and converts them into `AgentEvent::WebhookReceived` for agent processing.

use crate::agent::event_bus::AgentEvent;
use crate::events::EventSource;
use anyhow::{Context, Result};
use async_trait::async_trait;
use futures_util::StreamExt;
use lapin::{
    options::{BasicAckOptions, BasicConsumeOptions, BasicQosOptions, QueueDeclareOptions},
    types::FieldTable,
    Channel, Connection, ConnectionProperties, Consumer,
};

/// AMQP event source that listens to a RabbitMQ queue.
pub struct AmqpEventSource {
    name: String,
    url: String,
    queue: String,
    routing_key: Option<String>,
    prefetch_count: u16,
    connection: Option<Connection>,
    channel: Option<Channel>,
    consumer: Option<Consumer>,
    /// Delivery tag of the last received message (for acknowledgment).
    pending_delivery_tag: Option<u64>,
}

impl AmqpEventSource {
    pub fn new(
        name: String,
        url: String,
        queue: String,
        routing_key: Option<String>,
        prefetch_count: u16,
    ) -> Self {
        Self {
            name,
            url,
            queue,
            routing_key,
            prefetch_count: prefetch_count.max(1),
            connection: None,
            channel: None,
            consumer: None,
            pending_delivery_tag: None,
        }
    }

    /// Build from config.
    pub fn from_config(config: &crate::config::EventSourceConfig) -> Self {
        Self::new(
            config.name.clone(),
            config.url.clone(),
            config.queue.clone(),
            config.routing_key.clone(),
            config.prefetch_count,
        )
    }
}

#[async_trait]
impl EventSource for AmqpEventSource {
    fn name(&self) -> &str {
        &self.name
    }

    async fn connect(&mut self) -> Result<()> {
        let conn = Connection::connect(&self.url, ConnectionProperties::default())
            .await
            .context("AMQP connection failed")?;

        let channel = conn
            .create_channel()
            .await
            .context("AMQP channel creation failed")?;

        // Set QoS (prefetch count)
        channel
            .basic_qos(self.prefetch_count, BasicQosOptions::default())
            .await
            .context("AMQP QoS setup failed")?;

        // Declare queue (durable, will survive broker restarts)
        channel
            .queue_declare(
                &self.queue,
                QueueDeclareOptions {
                    durable: true,
                    ..QueueDeclareOptions::default()
                },
                FieldTable::default(),
            )
            .await
            .context("AMQP queue declaration failed")?;

        // Start consuming
        let consumer_tag = format!("zeroclaw-{}", &self.name);
        let consumer = channel
            .basic_consume(
                &self.queue,
                &consumer_tag,
                BasicConsumeOptions {
                    no_ack: false,
                    ..BasicConsumeOptions::default()
                },
                FieldTable::default(),
            )
            .await
            .context("AMQP consumer setup failed")?;

        tracing::info!(
            name = %self.name,
            queue = %self.queue,
            prefetch = self.prefetch_count,
            "AMQP event source connected"
        );

        self.connection = Some(conn);
        self.channel = Some(channel);
        self.consumer = Some(consumer);

        Ok(())
    }

    async fn next_event(&mut self) -> Result<AgentEvent> {
        let consumer = self
            .consumer
            .as_mut()
            .context("AMQP consumer not initialized — call connect() first")?;

        let delivery = consumer
            .next()
            .await
            .context("AMQP consumer stream ended")?
            .context("AMQP delivery error")?;

        // Store delivery tag for later acknowledgment
        self.pending_delivery_tag = Some(delivery.delivery_tag);

        // Parse payload as JSON, fall back to string
        let body_bytes = delivery.data.as_slice();
        let payload: serde_json::Value = serde_json::from_slice(body_bytes).unwrap_or_else(|_| {
            serde_json::Value::String(String::from_utf8_lossy(body_bytes).to_string())
        });

        // Use routing key from delivery if available, otherwise use configured routing_key
        let source = delivery.routing_key.as_str().to_string();
        let source = if source.is_empty() {
            self.routing_key
                .clone()
                .unwrap_or_else(|| self.name.clone())
        } else {
            source
        };

        Ok(AgentEvent::WebhookReceived { source, payload })
    }

    async fn acknowledge(&self, _event_id: &str) -> Result<()> {
        let channel = self
            .channel
            .as_ref()
            .context("AMQP channel not initialized")?;

        if let Some(tag) = self.pending_delivery_tag {
            channel
                .basic_ack(tag, BasicAckOptions::default())
                .await
                .context("AMQP acknowledgment failed")?;
        }

        Ok(())
    }

    async fn disconnect(&mut self) -> Result<()> {
        // Drop consumer first
        self.consumer = None;

        // Close channel
        if let Some(channel) = self.channel.take() {
            let _ = channel.close(200, "Normal shutdown").await;
        }

        // Close connection
        if let Some(conn) = self.connection.take() {
            let _ = conn.close(200, "Normal shutdown").await;
        }

        tracing::info!(name = %self.name, "AMQP event source disconnected");
        Ok(())
    }

    fn is_connected(&self) -> bool {
        self.connection
            .as_ref()
            .map_or(false, |conn| conn.status().connected())
    }
}
