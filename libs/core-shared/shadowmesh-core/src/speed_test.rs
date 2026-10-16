use crate::api_client::ApiClient;
use crate::ShadowMeshError;
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, OnceLock};
use std::time::Instant;

/// The maximum size of the pre-allocated zero buffer (10MB).
const MAX_ZERO_BUFFER_SIZE: usize = 10 * 1024 * 1024;

/// A shared, pre-allocated buffer of zeros used for upload tests to avoid repeated allocations.
static ZERO_BUFFER: OnceLock<Bytes> = OnceLock::new();

fn get_zero_buffer() -> Bytes {
    ZERO_BUFFER.get_or_init(|| Bytes::from(vec![0u8; MAX_ZERO_BUFFER_SIZE])).clone()
}

/// The result of a network speed test.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpeedTestResult {
    /// Average round-trip latency in milliseconds.
    pub latency_ms: f64,
    /// Measured download speed in Megabits per second (Mbps).
    pub download_speed_mbps: f64,
    /// Measured upload speed in Megabits per second (Mbps).
    pub upload_speed_mbps: f64,
}

/// A tool for measuring network latency and throughput.
pub struct SpeedTest {
    api_client: std::sync::Arc<ApiClient>,
}

impl SpeedTest {
    /// Creates a new `SpeedTest` instance using the provided API client.
    pub fn new(api_client: Arc<ApiClient>) -> Self {
        Self { api_client }
    }

    /// Performs a full speed test including latency, download, and upload measurements (Async).
    pub async fn run_full_test_async(&self) -> Result<SpeedTestResult, ShadowMeshError> {
        let latency = self.measure_latency_async().await?;
        let download = self.measure_download_async(5000).await?; // 5MB test
        let upload = self.measure_upload_async(2000).await?; // 2MB test

        Ok(SpeedTestResult {
            latency_ms: latency,
            download_speed_mbps: download,
            upload_speed_mbps: upload,
        })
    }

    /// Performs a full speed test including latency, download, and upload measurements (Sync).
    pub fn run_full_test(&self) -> Result<SpeedTestResult, ShadowMeshError> {
        let latency = self.measure_latency()?;
        let download = self.measure_download(5000)?;
        let upload = self.measure_upload(2000)?;

        Ok(SpeedTestResult {
            latency_ms: latency,
            download_speed_mbps: download,
            upload_speed_mbps: upload,
        })
    }

    /// Measures the average network latency by performing multiple pings (Async).
    pub async fn measure_latency_async(&self) -> Result<f64, ShadowMeshError> {
        let mut total_latency = 0.0;
        let iterations = 5;

        for _ in 0..iterations {
            let start = Instant::now();
            self.api_client.speedtest_ping_async().await?;
            total_latency += start.elapsed().as_secs_f64() * 1000.0;
        }

        Ok(total_latency / iterations as f64)
    }

    /// Measures the average network latency by performing multiple pings (Sync).
    pub fn measure_latency(&self) -> Result<f64, ShadowMeshError> {
        let mut total_latency = 0.0;
        let iterations = 5;

        for _ in 0..iterations {
            let start = Instant::now();
            self.api_client.speedtest_ping()?;
            total_latency += start.elapsed().as_secs_f64() * 1000.0;
        }

        Ok(total_latency / iterations as f64)
    }

    /// Measures the download speed using a test file of the specified size (Async).
    pub async fn measure_download_async(&self, size_kb: u32) -> Result<f64, ShadowMeshError> {
        let start = Instant::now();
        let data = self.api_client.speedtest_download_async(size_kb).await?;
        let elapsed = start.elapsed().as_secs_f64();

        if elapsed < 0.000001 {
            return Ok(0.0);
        }

        let size_bits = (data.len() as f64) * 8.0;
        let speed_bps = size_bits / elapsed;
        let speed_mbps = speed_bps / 1_000_000.0;

        Ok(speed_mbps)
    }

    /// Measures the download speed using a test file of the specified size (Sync).
    pub fn measure_download(&self, size_kb: u32) -> Result<f64, ShadowMeshError> {
        let start = Instant::now();
        let data = self.api_client.speedtest_download(size_kb)?;
        let elapsed = start.elapsed().as_secs_f64();

        if elapsed < 0.000001 {
            return Ok(0.0);
        }

        let size_bits = (data.len() as f64) * 8.0;
        let speed_bps = size_bits / elapsed;
        let speed_mbps = speed_bps / 1_000_000.0;

        Ok(speed_mbps)
    }

    /// Measures the upload speed by sending the specified amount of data (Async).
    /// Utilizes a pre-allocated zero-buffer to avoid heap allocations.
    pub async fn measure_upload_async(&self, size_kb: u32) -> Result<f64, ShadowMeshError> {
        let size_bytes = (size_kb as usize).saturating_mul(1024);
        let buffer = get_zero_buffer();

        let data = if size_bytes <= buffer.len() {
            buffer.slice(0..size_bytes)
        } else {
            // Fallback for extremely large tests exceeding static buffer
            Bytes::from(vec![0u8; size_bytes])
        };

        let start = Instant::now();
        self.api_client.speedtest_upload_async(data).await?;
        let elapsed = start.elapsed().as_secs_f64();

        if elapsed < 0.000001 {
            return Ok(0.0);
        }

        let size_bits = (size_bytes as f64) * 8.0;
        let speed_bps = size_bits / elapsed;
        let speed_mbps = speed_bps / 1_000_000.0;

        Ok(speed_mbps)
    }

    /// Measures the upload speed by sending the specified amount of data (Sync).
    pub fn measure_upload(&self, size_kb: u32) -> Result<f64, ShadowMeshError> {
        let size_bytes = (size_kb as usize).saturating_mul(1024);
        let buffer = get_zero_buffer();

        let data = if size_bytes <= buffer.len() {
            buffer.slice(0..size_bytes)
        } else {
            Bytes::from(vec![0u8; size_bytes])
        };

        let start = Instant::now();
        // Use synchronous upload from ApiClient. Note: this still converts Bytes to Vec internally
        // for reqwest's current sync wrapper if not optimized.
        self.api_client.speedtest_upload(data.to_vec())?;
        let elapsed = start.elapsed().as_secs_f64();

        if elapsed < 0.000001 {
            return Ok(0.0);
        }

        let size_bits = (size_bytes as f64) * 8.0;
        let speed_bps = size_bits / elapsed;
        let speed_mbps = speed_bps / 1_000_000.0;

        Ok(speed_mbps)
    }
}
