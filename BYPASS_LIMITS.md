# Bypass Tool Limits - ZeroClaw

Dokumen ini menjelaskan cara bypass semua limit tools di ZeroClaw.

## Lokasi Limit

Limit tools dikontrol oleh `max_actions_per_hour` yang diterapkan di:
- **Config file**: `~/.zeroclaw/config.toml` (section `[autonomy]`)
- **Code**: `src/security/policy.rs` - `SecurityPolicy::record_action()` dan `is_rate_limited()`
- **Default**: 20 actions per hour

## Cara 1: Ubah melalui Config File (Recommended)

Edit file config di `~/.zeroclaw/config.toml`:

```toml
[autonomy]
# Set ke nilai sangat besar untuk bypass (u32::MAX = 4294967295)
max_actions_per_hour = 4294967295

# Atau set ke nilai praktis yang sangat besar
# max_actions_per_hour = 1000000
```

Setelah mengubah config, restart ZeroClaw untuk menerapkan perubahan.

## Cara 2: Hardcode di Source Code (Tidak Recommended)

Jika ingin bypass permanen di source code, edit `src/security/policy.rs`:

```rust
// Line ~571: Ubah logic record_action()
pub fn record_action(&self) -> bool {
    let count = self.tracker.record();
    // Bypass: selalu return true
    true
    // Atau: count <= u32::MAX as usize (selalu true)
}

// Line ~576: Ubah logic is_rate_limited()
pub fn is_rate_limited(&self) -> bool {
    // Bypass: selalu return false
    false
    // Atau: self.tracker.count() >= u32::MAX as usize (selalu false)
}
```

**Catatan**: Hardcode bypass tidak recommended karena:
- Perlu rebuild binary
- Hilang saat update
- Tidak fleksibel untuk production

## Cara 3: Set Default di Config Schema

Edit `src/config/schema.rs` untuk mengubah default:

```rust
// Line ~1584: Ubah default max_actions_per_hour
impl Default for AutonomyConfig {
    fn default() -> Self {
        Self {
            // ... other fields ...
            max_actions_per_hour: u32::MAX, // Bypass default
            // ...
        }
    }
}
```

## Verifikasi

Setelah mengubah config, verifikasi dengan:

```bash
# Check config
zeroclaw status

# Test dengan banyak tool calls
zeroclaw chat "run 100 commands"
```

## Limit Lainnya

Selain `max_actions_per_hour`, ada limit lain yang mungkin perlu diubah:

### 1. Tool Iterations Limit
**Config**: `[agent] max_tool_iterations` (default: 10)
**Code**: `src/agent/loop_.rs` - `DEFAULT_MAX_TOOL_ITERATIONS` (fallback: 10)

```toml
[agent]
max_tool_iterations = 1000  # atau nilai besar lainnya
```

### 2. Cost Limit
**Config**: `[autonomy] max_cost_per_day_cents` (default: 500)

```toml
[autonomy]
max_cost_per_day_cents = 4294967295  # u32::MAX
```

### 3. Shell Tool Limits (Hardcoded)
**File**: `src/tools/shell.rs`
- `SHELL_TIMEOUT_SECS`: 60 detik (line ~10)
- `MAX_OUTPUT_BYTES`: 1MB (line ~12)

Untuk bypass, edit langsung di source code:
```rust
const SHELL_TIMEOUT_SECS: u64 = u64::MAX;  // No timeout
const MAX_OUTPUT_BYTES: usize = usize::MAX;  // No size limit
```

### Config Lengkap untuk Bypass Semua Limit

```toml
[autonomy]
max_actions_per_hour = 4294967295  # u32::MAX - unlimited actions
max_cost_per_day_cents = 4294967295  # u32::MAX - unlimited cost
level = "full"  # Full autonomy (no approval needed)

[agent]
max_tool_iterations = 10000  # Very high iteration limit
```

## Catatan Keamanan

⚠️ **Peringatan**: Bypass limit dapat menyebabkan:
- Resource exhaustion (CPU, memory, disk)
- Biaya API yang tidak terkontrol
- Security risk jika agent berjalan tanpa pengawasan

Gunakan dengan hati-hati dan hanya di environment yang terkontrol.
