use anyhow::{Result, Context};
use wasmi::*;

pub struct WasmRuntime {
    engine: Engine,
}

impl WasmRuntime {
    pub fn new() -> Self {
        Self {
            engine: Engine::default(),
        }
    }
}

impl Default for WasmRuntime {
    fn default() -> Self {
        Self::new()
    }
}

impl WasmRuntime {

    /// Executes a WASM plugin in a strictly isolated environment.
    /// ABI: The guest must export a function `scan` that takes and returns pointers to shared memory.
    /// For simplicity in this implementation, we assume a simple string-in/string-out JSON interface.
    pub fn execute_plugin(&self, wasm_bytes: &[u8], input_json: &str) -> Result<String> {
        let module = Module::new(&self.engine, wasm_bytes).context("Failed to create WASM module")?;
        
        let mut store = Store::new(&self.engine, ());
        let linker = Linker::new(&self.engine);
        
        // Potential Host Functions (e.g. logging)
        // linker.define("env", "log", func_to_log)?;

        let instance = linker
            .instantiate(&mut store, &module)?
            .start(&mut store)?;

        let memory = instance
            .get_export(&store, "memory")
            .and_then(Extern::into_memory)
            .context("Plugin must export 'memory'")?;

        // 1. Allocate space for input in WASM memory
        // (Assuming plugin exports an 'alloc' function)
        let alloc = instance
            .get_export(&store, "alloc")
            .and_then(Extern::into_func)
            .context("Plugin must export 'alloc' for input handling")?;

        let input_bytes = input_json.as_bytes();
        let input_len = input_bytes.len() as u64;
        
        let mut results = [Value::I32(0)];
        alloc.call(&mut store, &[Value::I32(input_len as i32)], &mut results)?;
        let ptr = results[0].i32().context("alloc failed")? as usize;

        // 2. Write input to WASM memory
        memory.write(&mut store, ptr, input_bytes).map_err(|e| anyhow::anyhow!("WASM Memory Write Error: {:?}", e))?;

        // 3. Call scan(ptr, len)
        let scan = instance
            .get_export(&store, "scan")
            .and_then(Extern::into_func)
            .context("Plugin must export 'scan'")?;

        let mut output_results = [Value::I32(0)];
        scan.call(&mut store, &[Value::I32(ptr as i32), Value::I32(input_len as i32)], &mut output_results)?;
        
        // 4. Read result from memory
        // (Assuming scan returns a pointer to a null-terminated string or we use a separate length function)
        // For this PoC, let's assume it returns a pointer to a buffer starting with 4-byte length.
        let out_ptr = output_results[0].i32().context("scan failed")? as usize;
        
        let mut len_buf = [0u8; 4];
        memory.read(&store, out_ptr, &mut len_buf).map_err(|e| anyhow::anyhow!("WASM Memory Read Error (len): {:?}", e))?;
        let out_len = u32::from_le_bytes(len_buf) as usize;
        
        let mut out_buf = vec![0u8; out_len];
        memory.read(&store, out_ptr + 4, &mut out_buf).map_err(|e| anyhow::anyhow!("WASM Memory Read Error (data): {:?}", e))?;

        Ok(String::from_utf8(out_buf)?)
    }
}
